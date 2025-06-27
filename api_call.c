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
    int udp_socket;
    struct sockaddr_in server_addr;
    unsigned char key[32];
    int transmitting;
    float *buffer;
    int buffer_size;
    int buffer_pos;
    PaDeviceIndex device_index;
    char channel_id[16];
};

struct channel_context {
    struct websocket_ctx ws_ctx;
    struct server_config config;
    struct audio_stream audio;
    pthread_t thread;
    int active;
};

static struct channel_context channels[2] = {0};
static PaDeviceIndex usb_devices[2] = {paNoDevice, paNoDevice};
static int device_assigned = 0;
static int global_interrupted = 0;
static int gpio_pin = 18;
static int gpio_initialized = 0;

int init_gpio_pin(int pin) {
    char path[64];
    char value[8];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/export");
    fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("GPIO export failed");
        return 0;
    }
    
    snprintf(value, sizeof(value), "%d", pin);
    if (write(fd, value, strlen(value)) == -1) {
        close(fd);
    }
    close(fd);
    
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", pin);
    fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("GPIO direction failed");
        return 0;
    }
    
    if (write(fd, "in", 2) == -1) {
        perror("GPIO direction write failed");
        close(fd);
        return 0;
    }
    close(fd);
    
    printf("GPIO pin %d initialized as input\n", pin);
    return 1;
}

int read_gpio_pin(int pin) {
    char path[64];
    char value[4];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", pin);
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    
    if (read(fd, value, 3) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    
    return (value[0] == '0') ? 0 : 1;
}

int is_ptt_active() {
    if (!gpio_initialized) {
        if (!init_gpio_pin(gpio_pin)) {
            return 1;
        }
        gpio_initialized = 1;
    }
    
    int pin_state = read_gpio_pin(gpio_pin);
    return (pin_state == 0);
}

static void handle_interrupt(int sig) {
    global_interrupted = 1;
    for (int i = 0; i < 2; i++) {
        if (channels[i].active) {
            channels[i].ws_ctx.interrupted = 1;
            channels[i].audio.transmitting = 0;
        }
    }
}

char* encode_base64(const unsigned char* data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const int padding[] = {0, 2, 1};
    
    size_t output_len = 4 * ((len + 2) / 3);
    char* encoded = malloc(output_len + 1);
    if (!encoded) return NULL;
    
    for (size_t i = 0, j = 0; i < len;) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 0x10) + (b << 0x08) + c;
        
        encoded[j++] = table[(triple >> 3 * 6) & 0x3F];
        encoded[j++] = table[(triple >> 2 * 6) & 0x3F];
        encoded[j++] = table[(triple >> 1 * 6) & 0x3F];
        encoded[j++] = table[(triple >> 0 * 6) & 0x3F];
    }
    
    for (int i = 0; i < padding[len % 3]; i++)
        encoded[output_len - 1 - i] = '=';
    
    encoded[output_len] = '\0';
    return encoded;
}

int decode_base64(const char* input, unsigned char* output) {
    static const int table[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
    };
    
    size_t input_len = strlen(input);
    if (input_len % 4 != 0) return 0;
    
    size_t output_len = input_len / 4 * 3;
    if (input[input_len - 1] == '=') output_len--;
    if (input[input_len - 2] == '=') output_len--;
    
    for (size_t i = 0, j = 0; i < input_len;) {
        uint32_t a = input[i] == '=' ? 0 & i++ : table[(int)input[i++]];
        uint32_t b = input[i] == '=' ? 0 & i++ : table[(int)input[i++]];
        uint32_t c = input[i] == '=' ? 0 & i++ : table[(int)input[i++]];
        uint32_t d = input[i] == '=' ? 0 & i++ : table[(int)input[i++]];
        
        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);
        
        if (j < output_len) output[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 0 * 8) & 0xFF;
    }
    
    return 1;
}

unsigned char* encrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    
    unsigned char iv[12];
    if (RAND_bytes(iv, 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char* encrypted = malloc(data_len + 12 + 16);
    if (!encrypted) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    memcpy(encrypted, iv, 12);
    
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted + 12, &len, data, data_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, encrypted + 12 + len, &len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, encrypted + 12 + ciphertext_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
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
    
    if (!audio_stream->transmitting || !input || !is_ptt_active()) {
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
                        
                        sendto(audio_stream->udp_socket, msg, strlen(msg), 0,
                               (struct sockaddr*)&audio_stream->server_addr, sizeof(audio_stream->server_addr));
                        
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

int setup_udp_for_channel(struct audio_stream* audio_stream, struct server_config* config) {
    audio_stream->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (audio_stream->udp_socket < 0) {
        perror("socket failed");
        return 0;
    }
    
    memset(&audio_stream->server_addr, 0, sizeof(audio_stream->server_addr));
    audio_stream->server_addr.sin_family = AF_INET;
    audio_stream->server_addr.sin_port = htons(config->udp_port);
    
    if (inet_aton(config->udp_host, &audio_stream->server_addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid UDP host\n");
        close(audio_stream->udp_socket);
        return 0;
    }
    
    printf("UDP configured for %s:%d on channel %s\n", config->udp_host, config->udp_port, audio_stream->channel_id);
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
    struct channel_context *ctx = NULL;
    
    for (int i = 0; i < 2; i++) {
        if (channels[i].ws_ctx.client_wsi == wsi) {
            ctx = &channels[i];
            break;
        }
    }
    
    if (!ctx) return 0;
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            printf("WebSocket connection established for channel %s\n", ctx->ws_ctx.channel_id);
            
            char connect_msg[512];
            time_t now = time(NULL);
            
            snprintf(connect_msg, sizeof(connect_msg),
                "{\"connect\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"%s\",\"time\":%ld}}",
                ctx->ws_ctx.channel_id, now);
            
            printf("Sending connect message: %s\n", connect_msg);
            
            size_t msg_len = strlen(connect_msg);
            unsigned char *buf = malloc(LWS_PRE + msg_len);
            if (buf) {
                memcpy(&buf[LWS_PRE], connect_msg, msg_len);
                lws_write(wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
                free(buf);
            }
            
            printf("Channel %s connected, ready for transmission when PTT is active\n", ctx->ws_ctx.channel_id);
            
            const char* key_b64 = "46dR4QR5KH7JhPyyjh/ZS4ki/3QBVwwOTkkQTdZQkC0=";
            if (!decode_base64(key_b64, ctx->audio.key)) {
                fprintf(stderr, "Key decode failed for channel %s\n", ctx->ws_ctx.channel_id);
                break;
            }
            printf("AES key decoded for channel %s\n", ctx->ws_ctx.channel_id);
            
            if (setup_udp_for_channel(&ctx->audio, &ctx->config)) {
                if (start_transmission_for_channel(&ctx->audio)) {
                    printf("Audio stream ready for channel %s - waiting for PTT activation\n", ctx->ws_ctx.channel_id);
                }
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            printf("Received on channel %s: %.*s\n", ctx->ws_ctx.channel_id, (int)len, (char *)in);
            
            char *data = malloc(len + 1);
            if (data) {
                memcpy(data, in, len);
                data[len] = '\0';
                
                if (strstr(data, "users_connected") && !ctx->audio.transmitting) {
                    printf("Channel %s users connected, ready for transmission when PTT is active\n", ctx->ws_ctx.channel_id);
                }
                
                free(data);
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("WebSocket closed for channel %s\n", ctx->ws_ctx.channel_id);
            ctx->ws_ctx.client_wsi = NULL;
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("WebSocket error for channel %s: %.*s\n", ctx->ws_ctx.channel_id, (int)len, (char *)in);
            ctx->ws_ctx.client_wsi = NULL;
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

int connect_websocket_for_channel(struct channel_context *ctx) {
    struct lws_context_creation_info info;
    char ws_url[256];
    
    snprintf(ws_url, sizeof(ws_url), "wss://audio-1.redenes.org/ws/?websocket_id=%d", ctx->config.websocket_id);
    printf("Connecting to: %s for channel %s\n", ws_url, ctx->ws_ctx.channel_id);
    
    char address[128] = "audio-1.redenes.org";
    char path[256];
    int port = 443;
    
    snprintf(path, sizeof(path), "/ws/?websocket_id=%d", ctx->config.websocket_id);
    
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    
    ctx->ws_ctx.context = lws_create_context(&info);
    if (!ctx->ws_ctx.context) {
        fprintf(stderr, "WebSocket context failed for channel %s\n", ctx->ws_ctx.channel_id);
        return 0;
    }
    
    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = ctx->ws_ctx.context;
    connect_info.address = address;
    connect_info.port = port;
    connect_info.path = path;
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.ssl_connection = LCCSCF_USE_SSL;
    connect_info.protocol = protocols[0].name;
    connect_info.pwsi = &ctx->ws_ctx.client_wsi;
    
    ctx->ws_ctx.client_wsi = lws_client_connect_via_info(&connect_info);
    if (ctx->ws_ctx.client_wsi == NULL) {
        fprintf(stderr, "WebSocket connect failed for channel %s\n", ctx->ws_ctx.channel_id);
        return 0;
    }
    
    return 1;
}

void* channel_thread(void* arg) {
    struct channel_context *ctx = (struct channel_context*)arg;
    
    printf("Starting channel thread for %s\n", ctx->ws_ctx.channel_id);
    
    ctx->ws_ctx.interrupted = 0;
    while (!ctx->ws_ctx.interrupted && !global_interrupted && ctx->ws_ctx.client_wsi) {
        lws_service(ctx->ws_ctx.context, 100);
    }
    
    if (ctx->ws_ctx.context) {
        lws_context_destroy(ctx->ws_ctx.context);
        ctx->ws_ctx.context = NULL;
    }
    
    printf("Channel thread for %s terminated\n", ctx->ws_ctx.channel_id);
    return NULL;
}

void auto_assign_usb_devices() {
    if (device_assigned) return;
    
    int num_devices = Pa_GetDeviceCount();
    int usb_count = 0;
    
    printf("Scanning for USB audio devices...\n");
    
    for (int i = 0; i < num_devices && usb_count < 2; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info && device_info->maxInputChannels > 0) {
            const PaHostApiInfo* host_info = Pa_GetHostApiInfo(device_info->hostApi);
            if (host_info && host_info->type == paALSA) {
                const char* name = device_info->name;
                if (strstr(name, "USB") || strstr(name, "usb") || 
                    strstr(name, "Audio Device") || strstr(name, "Headset")) {
                    usb_devices[usb_count] = i;
                    printf("USB Device %d assigned to slot %d: %s\n", i, usb_count, name);
                    usb_count++;
                }
            }
        }
    }
    
    if (usb_count == 0) {
        printf("No USB audio devices found, using default input device\n");
        usb_devices[0] = Pa_GetDefaultInputDevice();
        usb_devices[1] = Pa_GetDefaultInputDevice();
    } else if (usb_count == 1) {
        printf("Only one USB device found, both channels will use the same device\n");
        usb_devices[1] = usb_devices[0];
    }
    
    printf("Channel 555 -> Device %d\n", usb_devices[0]);
    printf("Channel 666 -> Device %d\n", usb_devices[1]);
    
    device_assigned = 1;
}

PaDeviceIndex get_device_for_channel(const char* channel) {
    auto_assign_usb_devices();
    
    if (strcmp(channel, "555") == 0) {
        return usb_devices[0];
    } else if (strcmp(channel, "666") == 0) {
        return usb_devices[1];
    }
    
    return usb_devices[0];
}

int setup_channel(struct channel_context *ctx, const char *channel_id) {
    strcpy(ctx->ws_ctx.channel_id, channel_id);
    strcpy(ctx->audio.channel_id, channel_id);
    
    if (!setup_audio_for_channel(&ctx->audio)) {
        fprintf(stderr, "Audio setup failed for channel %s\n", channel_id);
        return 0;
    }
    
    CURL *curl;
    CURLcode res;
    struct response_data resp = {0};
    
    resp.data = malloc(1);
    if (resp.data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    resp.data[0] = '\0';
    resp.size = 0;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://audio-1.redenes.org/audio-server-port");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl failed for channel %s: %s\n", channel_id, curl_easy_strerror(res));
            free(resp.data);
            curl_easy_cleanup(curl);
            return 0;
        }
        
        printf("Raw Response for channel %s: %s\n", channel_id, resp.data);
        
        if (parse_server_response(resp.data, &ctx->config)) {
            curl_easy_cleanup(curl);
            free(resp.data);
            
            if (!connect_websocket_for_channel(ctx)) {
                fprintf(stderr, "WebSocket connection failed for channel %s\n", channel_id);
                return 0;
            }
            
            ctx->active = 1;
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
        if (argc > 2) {
            gpio_pin = atoi(argv[2]);
            printf("Using GPIO pin %d for PTT\n", gpio_pin);
        }
        
        int channel = atoi(argv[1]);
        if (channel == 555) {
            run_both = 0;
            printf("Running channel 555 only\n");
        } else if (channel == 666) {
            run_both = 0;
            printf("Running channel 666 only\n");
        } else if (strcmp(argv[1], "both") == 0) {
            run_both = 1;
            printf("Running both channels simultaneously\n");
        } else {
            fprintf(stderr, "Usage: %s [555|666|both] [gpio_pin]\n", argv[0]);
            fprintf(stderr, "  555       - Run channel 555 only\n");
            fprintf(stderr, "  666       - Run channel 666 only\n");
            fprintf(stderr, "  both      - Run both channels simultaneously (default)\n");
            fprintf(stderr, "  gpio_pin  - GPIO pin number for PTT (default: 18)\n");
            return 1;
        }
    } else {
        printf("Running both channels simultaneously (default)\n");
    }
    
    printf("PTT GPIO pin: %d (transmission active when grounded)\n", gpio_pin);
    
    if (!initialize_portaudio()) {
        fprintf(stderr, "PortAudio initialization failed\n");
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    signal(SIGINT, handle_interrupt);
    
    if (run_both) {
        printf("Setting up both channels...\n");
        
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
        
        if (pthread_create(&channels[0].thread, NULL, channel_thread, &channels[0])) {
            fprintf(stderr, "Failed to create thread for channel 555\n");
            curl_global_cleanup();
            return 1;
        }
        
        if (pthread_create(&channels[1].thread, NULL, channel_thread, &channels[1])) {
            fprintf(stderr, "Failed to create thread for channel 666\n");
            curl_global_cleanup();
            return 1;
        }
        
        printf("Both channels running. Press Ctrl+C to stop.\n");
        
        pthread_join(channels[0].thread, NULL);
        pthread_join(channels[1].thread, NULL);
        
    } else {
        int channel_idx = (argc > 1 && atoi(argv[1]) == 666) ? 1 : 0;
        const char* channel_id = (channel_idx == 0) ? "555" : "666";
        
        if (!setup_channel(&channels[channel_idx], channel_id)) {
            fprintf(stderr, "Failed to setup channel %s\n", channel_id);
            curl_global_cleanup();
            return 1;
        }
        
        channel_thread(&channels[channel_idx]);
    }
    
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}