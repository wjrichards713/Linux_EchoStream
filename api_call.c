#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libwebsockets.h>
#include <signal.h>
#include <time.h>
#include <portaudio.h>
#include <opus/opus.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>

void auto_assign_usb_devices();
PaDeviceIndex get_device_for_channel(const char* channel);

struct response_data {
    char *data;
    size_t size;
};

struct server_config {
    int udp_port;
    char udp_host[128];
    int websocket_id;
    char aes_key[256];
};

struct websocket_ctx {
    struct lws_context *context;
    struct lws *client_wsi;
    int interrupted;
    char channel_id[16];
};

struct audio_stream {
    PaStream *stream;
    OpusEncoder *encoder;
    unsigned char key[32];
    int transmitting;
    float *buffer;
    int buffer_size;
    int buffer_pos;
    PaDeviceIndex device_index;
    char channel_id[16];
};

struct channel_context {
    struct audio_stream audio;
    int active;
};

struct shared_connection {
    struct websocket_ctx ws_ctx;
    struct server_config config;
    pthread_t thread;
    int udp_socket;
    struct sockaddr_in server_addr;
    int active;
};

static struct channel_context channels[2] = {0};
static struct shared_connection shared_conn = {0};
static PaDeviceIndex usb_devices[2] = {paNoDevice, paNoDevice};
static int device_assigned = 0;
static int global_interrupted = 0;
static int gpio_pin_555 = 589;  // GPIO 20 (physical pin 38) on RPi5
static int gpio_pin_666 = 590;  // GPIO 21 (physical pin 40) on RPi5
static int gpio_initialized_555 = 0;
static int gpio_initialized_666 = 0;

int init_gpio_pin(int pin) {
    char path[64], value[8];
    int fd;
    
    // First try to unexport the pin in case it's already exported
    snprintf(path, sizeof(path), "/sys/class/gpio/unexport");
    if ((fd = open(path, O_WRONLY)) != -1) {
        snprintf(value, sizeof(value), "%d", pin);
        write(fd, value, strlen(value));  // Ignore errors - pin might not be exported
        close(fd);
    }
    
    // Small delay
    usleep(100000);
    
    snprintf(path, sizeof(path), "/sys/class/gpio/export");
    if ((fd = open(path, O_WRONLY)) == -1) {
        printf("ERROR: Cannot open GPIO export file %s: %s\n", path, strerror(errno));
        return 0;
    }
    snprintf(value, sizeof(value), "%d", pin);
    if (write(fd, value, strlen(value)) == -1) {
        printf("ERROR: Cannot export GPIO pin %d: %s\n", pin, strerror(errno));
        close(fd);
        return 0;
    }
    close(fd);
    
    // Small delay to allow GPIO to be exported
    usleep(100000);
    
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", pin);
    if ((fd = open(path, O_WRONLY)) == -1) {
        printf("ERROR: Cannot open GPIO direction file %s: %s\n", path, strerror(errno));
        return 0;
    }
    if (write(fd, "in", 2) == -1) {
        printf("ERROR: Cannot set GPIO pin %d direction: %s\n", pin, strerror(errno));
        close(fd);
        return 0;
    }
    close(fd);
    
    // Enable pull-up resistor using pinctrl command for Pi 5
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "pinctrl set %d ip pu", pin - 569);
    system(cmd);
    
    printf("GPIO pin %d initialized successfully\n", pin);
    return 1;
}

int read_gpio_pin(int pin) {
    char path[64], value[4];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", pin);
    if ((fd = open(path, O_RDONLY)) == -1) {
        printf("ERROR: Cannot open GPIO value file %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    if (read(fd, value, 3) == -1) {
        printf("ERROR: Cannot read GPIO pin %d value: %s\n", pin, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    
    return (value[0] == '0') ? 0 : 1;
}

int is_ptt_active_for_channel(const char* channel_id) {
    int pin = (strcmp(channel_id, "555") == 0) ? gpio_pin_555 : gpio_pin_666;
    int *initialized = (strcmp(channel_id, "555") == 0) ? &gpio_initialized_555 : &gpio_initialized_666;
    static int last_ptt_state_555 = -1;
    static int last_ptt_state_666 = -1;
    int *last_state = (strcmp(channel_id, "555") == 0) ? &last_ptt_state_555 : &last_ptt_state_666;
    
    if (!*initialized) {
        *initialized = init_gpio_pin(pin) ? 1 : -1;
        if (*initialized == -1) {
            printf("ERROR: GPIO initialization failed for pin %d\n", pin);
            return 1;
        }
    }
    
    if (*initialized == -1) {
        return 1;
    }
    
    int pin_value = read_gpio_pin(pin);
    int ptt_active = (pin_value == 0);
    
    // Only log when PTT state changes
    if (ptt_active != *last_state) {
        printf("PTT Channel %s: %s\n", channel_id, ptt_active ? "ACTIVE" : "INACTIVE");
        *last_state = ptt_active;
    }
    
    return ptt_active;
}

static void handle_interrupt(int sig) {
    (void)sig; // Mark parameter as used
    global_interrupted = 1;
    shared_conn.ws_ctx.interrupted = 1;
    for (int i = 0; i < 2; i++) {
        if (channels[i].active) {
            channels[i].audio.transmitting = 0;
        }
    }
}

char* encode_base64(const unsigned char* data, size_t len) {
    char* encoded = malloc(len * 2 + 16); // Simple overallocation
    if (!encoded) return NULL;
    
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, j = 0;
    
    for (; i + 2 < len; i += 3) {
        uint32_t v = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
        encoded[j++] = t[v >> 18]; encoded[j++] = t[(v >> 12) & 63];
        encoded[j++] = t[(v >> 6) & 63]; encoded[j++] = t[v & 63];
    }
    
    if (i < len) {
        uint32_t v = data[i] << 16;
        if (i + 1 < len) v |= data[i+1] << 8;
        encoded[j++] = t[v >> 18]; encoded[j++] = t[(v >> 12) & 63];
        encoded[j++] = (i + 1 < len) ? t[(v >> 6) & 63] : '=';
        encoded[j++] = '=';
    }
    
    encoded[j] = '\0';
    return encoded;
}

int decode_base64(const char* input, unsigned char* output) {
    const char* key = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(input);
    if (len % 4) return 0;
    
    for (size_t i = 0, j = 0; i < len; i += 4) {
        uint32_t v = 0;
        for (int k = 0; k < 4; k++) {
            char c = input[i + k];
            if (c == '=') break;
            char* p = strchr(key, c);
            if (!p) return 0;
            v = (v << 6) | (p - key);
        }
        
        if (j < len) output[j++] = v >> 16;
        if (j < len && input[i + 2] != '=') output[j++] = v >> 8;
        if (j < len && input[i + 3] != '=') output[j++] = v;
    }
    
    return 1;
}

unsigned char* encrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12], *encrypted = malloc(data_len + 28);
    int len, ciphertext_len;
    
    if (!ctx || !encrypted || RAND_bytes(iv, 12) != 1 || 
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        (memcpy(encrypted, iv, 12), EVP_EncryptUpdate(ctx, encrypted + 12, &len, data, data_len) != 1) ||
        (ciphertext_len = len, EVP_EncryptFinal_ex(ctx, encrypted + 12 + len, &len) != 1) ||
        (ciphertext_len += len, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted + 12 + ciphertext_len) != 1)) {
        free(encrypted);
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    *out_len = 12 + ciphertext_len + 16;
    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
}

static int audio_callback(const void *input, void *output, unsigned long frames,
                         const PaStreamCallbackTimeInfo* time_info,
                         PaStreamCallbackFlags flags, void *user_data) {
    
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    int ptt_active = is_ptt_active_for_channel(audio_stream->channel_id);
    
    if (!audio_stream->transmitting || !input || !ptt_active) {
        return paContinue;
    }
    
    const float *samples = (const float*)input;
    
    for (unsigned long i = 0; i < frames; i++) {
        audio_stream->buffer[audio_stream->buffer_pos++] = samples[i];
        
        if (audio_stream->buffer_pos >= 1920) {
            short pcm[1920];
            for (int j = 0; j < 1920; j++) {
                float sample = audio_stream->buffer[j];
                if (sample > 1.0f) sample = 1.0f;
                if (sample < -1.0f) sample = -1.0f;
                pcm[j] = (short)(sample * 32767.0f);
            }
            
            unsigned char opus_data[4000];
            int opus_len = opus_encode(audio_stream->encoder, pcm, 1920, opus_data, sizeof(opus_data));
            
            if (opus_len > 0) {
                size_t encrypted_len;
                unsigned char* encrypted = encrypt_data(opus_data, opus_len, audio_stream->key, &encrypted_len);
                
                if (encrypted) {
                    char* b64_data = encode_base64(encrypted, encrypted_len);
                    
                    if (b64_data) {
                        char msg[8192];
                        snprintf(msg, sizeof(msg),
                                "{\"channel_id\":\"%s\",\"type\":\"audio\",\"data\":\"%s\"}", audio_stream->channel_id, b64_data);
                        
                        sendto(shared_conn.udp_socket, msg, strlen(msg), 0,
                               (struct sockaddr*)&shared_conn.server_addr, sizeof(shared_conn.server_addr));
                        
                        free(b64_data);
                    }
                    free(encrypted);
                }
            }
            
            audio_stream->buffer_pos = 0;
        }
    }
    
    return paContinue;
}

int setup_audio_for_channel(struct audio_stream* audio_stream) {
    int error;
    audio_stream->encoder = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        fprintf(stderr, "Opus encoder error: %s\n", opus_strerror(error));
        return 0;
    }
    
    opus_encoder_ctl(audio_stream->encoder, OPUS_SET_BITRATE(64000));
    opus_encoder_ctl(audio_stream->encoder, OPUS_SET_VBR(1));
    
    audio_stream->buffer_size = 4800;
    audio_stream->buffer = malloc(audio_stream->buffer_size * sizeof(float));
    audio_stream->buffer_pos = 0;
    
    return 1;
}

int initialize_portaudio() {
    static int initialized = 0;
    if (initialized) return 1;
    
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    initialized = 1;
    return 1;
}

int setup_shared_udp(struct server_config* config) {
    if (shared_conn.udp_socket > 0) {
        return 1; // Already setup
    }
    
    shared_conn.udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (shared_conn.udp_socket < 0) {
        perror("socket failed");
        return 0;
    }
    
    memset(&shared_conn.server_addr, 0, sizeof(shared_conn.server_addr));
    shared_conn.server_addr.sin_family = AF_INET;
    shared_conn.server_addr.sin_port = htons(config->udp_port);
    
    if (inet_aton(config->udp_host, &shared_conn.server_addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid UDP host\n");
        close(shared_conn.udp_socket);
        return 0;
    }
    
    printf("Shared UDP configured for %s:%d\n", config->udp_host, config->udp_port);
    return 1;
}

int start_transmission_for_channel(struct audio_stream* audio_stream) {
    PaStreamParameters input_params;
    
    audio_stream->device_index = get_device_for_channel(audio_stream->channel_id);
    input_params.device = audio_stream->device_index;
    if (input_params.device == paNoDevice) {
        fprintf(stderr, "No input device for channel %s\n", audio_stream->channel_id);
        return 0;
    }
    
    input_params.channelCount = 1;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    PaError err = Pa_OpenStream(&audio_stream->stream, &input_params, NULL, 48000, 1024, 
                                paClipOff, audio_callback, audio_stream);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio stream error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    err = Pa_StartStream(audio_stream->stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->stream);
        return 0;
    }
    
    audio_stream->transmitting = 1;
    printf("Audio transmission started for channel %s\n", audio_stream->channel_id);
    return 1;
}

size_t response_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t real_size = size * nmemb;
    struct response_data *resp = (struct response_data *)userdata;
    
    char *new_data = realloc(resp->data, resp->size + real_size + 1);
    if (new_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    
    resp->data = new_data;
    memcpy(&(resp->data[resp->size]), ptr, real_size);
    resp->size += real_size;
    resp->data[resp->size] = '\0';
    
    return real_size;
}

int parse_server_response(const char *json_str, struct server_config *cfg) {
    struct json_object *json;
    struct json_object *udp_port, *udp_host, *websocket_id, *aes_key;
    
    json = json_tokener_parse(json_str);
    if (json == NULL) {
        fprintf(stderr, "JSON parse failed\n");
        return 0;
    }
    
    if (json_object_object_get_ex(json, "udp_port", &udp_port) &&
        json_object_object_get_ex(json, "udp_host", &udp_host) &&
        json_object_object_get_ex(json, "websocket_id", &websocket_id) &&
        json_object_object_get_ex(json, "aes_key", &aes_key)) {
        
        cfg->udp_port = json_object_get_int(udp_port);
        strncpy(cfg->udp_host, json_object_get_string(udp_host), sizeof(cfg->udp_host) - 1);
        cfg->websocket_id = json_object_get_int(websocket_id);
        strncpy(cfg->aes_key, json_object_get_string(aes_key), sizeof(cfg->aes_key) - 1);
        
        printf("UDP Port: %d\n", cfg->udp_port);
        printf("UDP Host: %s\n", cfg->udp_host);
        printf("WebSocket ID: %d\n", cfg->websocket_id);
        printf("AES Key: %s\n", cfg->aes_key);
        
        json_object_put(json);
        return 1;
    } else {
        fprintf(stderr, "Failed to extract JSON fields\n");
        json_object_put(json);
        return 0;
    }
}

static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
                             void *user, void *in, size_t len) {
    if (shared_conn.ws_ctx.client_wsi != wsi) {
        return 0;
    }
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            printf("Shared WebSocket connection established\n");
            
            // Setup both channels
            const char* key_b64 = "46dR4QR5KH7JhPyyjh/ZS4ki/3QBVwwOTkkQTdZQkC0=";
            for (int i = 0; i < 2; i++) {
                if (channels[i].active) {
                    if (!decode_base64(key_b64, channels[i].audio.key)) {
                        fprintf(stderr, "Key decode failed for channel %s\n", channels[i].audio.channel_id);
                        continue;
                    }
                    printf("AES key decoded for channel %s\n", channels[i].audio.channel_id);
                    
                    if (start_transmission_for_channel(&channels[i].audio)) {
                        printf("Audio stream ready for channel %s - waiting for PTT activation\n", channels[i].audio.channel_id);
                    }
                }
            }
            
            if (setup_shared_udp(&shared_conn.config)) {
                printf("Shared connection ready for both channels\n");
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            printf("Received shared message: %.*s\n", (int)len, (char *)in);
            
            char *data = malloc(len + 1);
            if (data) {
                memcpy(data, in, len);
                data[len] = '\0';
                
                if (strstr(data, "users_connected")) {
                    printf("Both channels ready for transmission when PTT is active\n");
                }
                
                free(data);
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("Shared WebSocket connection closed\n");
            shared_conn.ws_ctx.client_wsi = NULL;
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("Shared WebSocket error: %.*s\n", (int)len, (char *)in);
            shared_conn.ws_ctx.client_wsi = NULL;
            break;
            
        default:
            break;
    }
    
    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "audio-protocol",
        websocket_callback,
        0,
        4096,
    },
    { NULL, NULL, 0, 0 }
};

int connect_shared_websocket(struct server_config* config) {
    if (shared_conn.ws_ctx.context) {
        return 1; // Already connected
    }
    
    struct lws_context_creation_info info;
    char ws_url[256];
    
    snprintf(ws_url, sizeof(ws_url), "wss://audio-1.redenes.org/ws/?websocket_id=%d", config->websocket_id);
    printf("Connecting to shared WebSocket: %s\n", ws_url);
    
    char address[128] = "audio-1.redenes.org";
    char path[256];
    int port = 443;
    
    snprintf(path, sizeof(path), "/ws/?websocket_id=%d", config->websocket_id);
    
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.ssl_cert_filepath = NULL;
    info.ssl_private_key_filepath = NULL;
    info.ssl_ca_filepath = NULL;
    
    shared_conn.ws_ctx.context = lws_create_context(&info);
    if (!shared_conn.ws_ctx.context) {
        fprintf(stderr, "Shared WebSocket context failed\n");
        return 0;
    }
    
    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = shared_conn.ws_ctx.context;
    connect_info.address = address;
    connect_info.port = port;
    connect_info.path = path;
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    connect_info.protocol = protocols[0].name;
    connect_info.pwsi = &shared_conn.ws_ctx.client_wsi;
    
    shared_conn.ws_ctx.client_wsi = lws_client_connect_via_info(&connect_info);
    if (shared_conn.ws_ctx.client_wsi == NULL) {
        fprintf(stderr, "Shared WebSocket connect failed\n");
        return 0;
    }
    
    return 1;
}

void* shared_websocket_thread(void* arg) {
    (void)arg; // Unused parameter
    
    printf("Starting shared WebSocket thread\n");
    
    shared_conn.ws_ctx.interrupted = 0;
    while (!shared_conn.ws_ctx.interrupted && !global_interrupted && shared_conn.ws_ctx.client_wsi) {
        lws_service(shared_conn.ws_ctx.context, 100);
    }
    
    if (shared_conn.ws_ctx.context) {
        lws_context_destroy(shared_conn.ws_ctx.context);
        shared_conn.ws_ctx.context = NULL;
    }
    
    printf("Shared WebSocket thread terminated\n");
    return NULL;
}

void auto_assign_usb_devices() {
    if (device_assigned) return;
    
    int usb_count = 0;
    for (int i = 0; i < Pa_GetDeviceCount() && usb_count < 2; i++) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(i);
        if (info && info->maxInputChannels > 0 && 
            (strstr(info->name, "USB") || strstr(info->name, "Audio Device"))) {
            usb_devices[usb_count++] = i;
            printf("USB Device %d: %s\n", i, info->name);
        }
    }
    
    if (!usb_count) usb_devices[0] = usb_devices[1] = Pa_GetDefaultInputDevice();
    else if (usb_count == 1) usb_devices[1] = usb_devices[0];
    
    printf("Channels 555/666 -> Devices %d/%d\n", usb_devices[0], usb_devices[1]);
    device_assigned = 1;
}

PaDeviceIndex get_device_for_channel(const char* channel) {
    auto_assign_usb_devices();
    return usb_devices[strcmp(channel, "666") == 0 ? 1 : 0];
}

int setup_channel(struct channel_context *ctx, const char *channel_id) {
    strcpy(ctx->audio.channel_id, channel_id);
    if (!setup_audio_for_channel(&ctx->audio)) {
        fprintf(stderr, "Audio setup failed for channel %s\n", channel_id);
        return 0;
    }
    ctx->active = 1;
    return 1;
}

int setup_shared_connection() {
    if (shared_conn.active) return 1;
    
    CURL *curl = curl_easy_init();
    struct response_data resp = {malloc(1), 0};
    if (!resp.data) return 0;
    resp.data[0] = '\0';
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://audio-1.redenes.org/audio-server-port");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        if (curl_easy_perform(curl) == CURLE_OK && 
            parse_server_response(resp.data, &shared_conn.config) &&
            connect_shared_websocket(&shared_conn.config)) {
            shared_conn.active = 1;
            curl_easy_cleanup(curl);
            free(resp.data);
            return 1;
        }
        curl_easy_cleanup(curl);
    }
    
    free(resp.data);
    return 0;
}

int main(int argc, char *argv[]) {
    int run_both = 1;
    
    if (argc > 1) {
        if (argc > 2) gpio_pin_555 = atoi(argv[2]);
        if (argc > 3) gpio_pin_666 = atoi(argv[3]);
        
        int channel = atoi(argv[1]);
        if (channel == 555 || channel == 666) {
            run_both = 0;
            printf("Running channel %d only\n", channel);
        } else if (strcmp(argv[1], "both") != 0) {
            fprintf(stderr, "Usage: %s [555|666|both] [gpio_pin_555] [gpio_pin_666]\n", argv[0]);
            return 1;
        }
    }
    
    printf("GPIO pins: 555->%d, 666->%d | Mode: %s\n", gpio_pin_555, gpio_pin_666, 
           run_both ? "both channels" : "single channel");
    
    if (!initialize_portaudio()) {
        fprintf(stderr, "PortAudio initialization failed\n");
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    signal(SIGINT, handle_interrupt);
    
    if (run_both) {
        printf("Setting up both channels...\n");
        fflush(stdout);
        
        if (!setup_channel(&channels[0], "555")) {
            fprintf(stderr, "Failed to setup channel 555\n");
            curl_global_cleanup();
            return 1;
        }
        
        if (!setup_channel(&channels[1], "666")) {
            fprintf(stderr, "Failed to setup channel 666\n");
            curl_global_cleanup();
            return 1;
        }
        
        if (!setup_shared_connection()) {
            fprintf(stderr, "Failed to setup shared connection\n");
            curl_global_cleanup();
            return 1;
        }
        
        if (pthread_create(&shared_conn.thread, NULL, shared_websocket_thread, NULL)) {
            fprintf(stderr, "Failed to create shared WebSocket thread\n");
            curl_global_cleanup();
            return 1;
        }
        
        printf("Both channels running with shared connection. Press Ctrl+C to stop.\n");
        
        pthread_join(shared_conn.thread, NULL);
        
    } else {
        int channel_idx = (argc > 1 && atoi(argv[1]) == 666) ? 1 : 0;
        const char* channel_id = (channel_idx == 0) ? "555" : "666";
        
        if (!setup_channel(&channels[channel_idx], channel_id)) {
            fprintf(stderr, "Failed to setup channel %s\n", channel_id);
            curl_global_cleanup();
            return 1;
        }
        
        if (!setup_shared_connection()) {
            fprintf(stderr, "Failed to setup shared connection\n");
            curl_global_cleanup();
            return 1;
        }
        
        shared_websocket_thread(NULL);
    }
    
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}