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
};

static struct websocket_ctx ws_ctx = {0};
static struct server_config config = {0};
static struct audio_stream audio = {0};

static void handle_interrupt(int sig) {
    ws_ctx.interrupted = 1;
    audio.transmitting = 0;
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
    
    if (!audio.transmitting || !input) {
        return paContinue;
    }
    
    const float *samples = (const float*)input;
    
    for (unsigned long i = 0; i < frames; i++) {
        audio.buffer[audio.buffer_pos++] = samples[i];
        
        if (audio.buffer_pos >= 1920) {
            short pcm[1920];
            for (int j = 0; j < 1920; j++) {
                float sample = audio.buffer[j];
                if (sample > 1.0f) sample = 1.0f;
                if (sample < -1.0f) sample = -1.0f;
                pcm[j] = (short)(sample * 32767.0f);
            }
            
            unsigned char opus_data[4000];
            int opus_len = opus_encode(audio.encoder, pcm, 1920, opus_data, sizeof(opus_data));
            
            if (opus_len > 0) {
                size_t encrypted_len;
                unsigned char* encrypted = encrypt_data(opus_data, opus_len, audio.key, &encrypted_len);
                
                if (encrypted) {
                    char* b64_data = encode_base64(encrypted, encrypted_len);
                    
                    if (b64_data) {
                        char msg[8192];
                        snprintf(msg, sizeof(msg),
                                "{\"channel_id\":\"555\",\"type\":\"audio\",\"data\":\"%s\"}", b64_data);
                        
                        sendto(audio.udp_socket, msg, strlen(msg), 0,
                               (struct sockaddr*)&audio.server_addr, sizeof(audio.server_addr));
                        
                        free(b64_data);
                    }
                    free(encrypted);
                }
            }
            
            audio.buffer_pos = 0;
        }
    }
    
    return paContinue;
}

int setup_audio() {
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    int error;
    audio.encoder = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        fprintf(stderr, "Opus encoder error: %s\n", opus_strerror(error));
        Pa_Terminate();
        return 0;
    }
    
    opus_encoder_ctl(audio.encoder, OPUS_SET_BITRATE(64000));
    opus_encoder_ctl(audio.encoder, OPUS_SET_VBR(1));
    
    audio.buffer_size = 4800;
    audio.buffer = malloc(audio.buffer_size * sizeof(float));
    audio.buffer_pos = 0;
    
    return 1;
}

int setup_udp() {
    audio.udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (audio.udp_socket < 0) {
        perror("socket failed");
        return 0;
    }
    
    memset(&audio.server_addr, 0, sizeof(audio.server_addr));
    audio.server_addr.sin_family = AF_INET;
    audio.server_addr.sin_port = htons(config.udp_port);
    
    if (inet_aton(config.udp_host, &audio.server_addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid UDP host\n");
        close(audio.udp_socket);
        return 0;
    }
    
    printf("UDP configured for %s:%d\n", config.udp_host, config.udp_port);
    return 1;
}

int start_transmission() {
    PaStreamParameters input_params;
    
    input_params.device = Pa_GetDefaultInputDevice();
    if (input_params.device == paNoDevice) {
        fprintf(stderr, "No input device\n");
        return 0;
    }
    
    input_params.channelCount = 1;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    PaError err = Pa_OpenStream(&audio.stream, &input_params, NULL, 48000, 1024, 
                                paClipOff, audio_callback, NULL);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio stream error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    err = Pa_StartStream(audio.stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio.stream);
        return 0;
    }
    
    audio.transmitting = 1;
    printf("Audio transmission started\n");
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
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            printf("WebSocket connection established\n");
            
            char connect_msg[512];
            time_t now = time(NULL);
            
            snprintf(connect_msg, sizeof(connect_msg),
                "{\"connect\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"555\",\"time\":%ld}}",
                now);
            
            printf("Sending connect message: %s\n", connect_msg);
            
            size_t msg_len = strlen(connect_msg);
            unsigned char *buf = malloc(LWS_PRE + msg_len);
            if (buf) {
                memcpy(&buf[LWS_PRE], connect_msg, msg_len);
                lws_write(wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
                free(buf);
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            printf("Received: %.*s\n", (int)len, (char *)in);
            
            char *data = malloc(len + 1);
            if (data) {
                memcpy(data, in, len);
                data[len] = '\0';
                
                if (strstr(data, "users_connected") && !audio.transmitting) {
                    printf("Channel connected, starting transmission...\n");
                    
                    const char* key_b64 = "46dR4QR5KH7JhPyyjh/ZS4ki/3QBVwwOTkkQTdZQkC0=";
                    if (!decode_base64(key_b64, audio.key)) {
                        fprintf(stderr, "Key decode failed\n");
                        free(data);
                        return 0;
                    }
                    printf("AES key decoded\n");
                    
                    if (setup_udp()) {
                        if (start_transmission()) {
                            char transmit_msg[512];
                            time_t now = time(NULL);
                            
                            snprintf(transmit_msg, sizeof(transmit_msg),
                                "{\"transmit_started\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"555\",\"time\":%ld}}",
                                now);
                            
                            printf("Sending transmit_started: %s\n", transmit_msg);
                            
                            size_t msg_len = strlen(transmit_msg);
                            unsigned char *buf = malloc(LWS_PRE + msg_len);
                            if (buf) {
                                memcpy(&buf[LWS_PRE], transmit_msg, msg_len);
                                lws_write(wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
                                free(buf);
                            }
                        }
                    }
                }
                
                free(data);
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("WebSocket closed\n");
            ws_ctx.client_wsi = NULL;
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("WebSocket error: %.*s\n", (int)len, (char *)in);
            ws_ctx.client_wsi = NULL;
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

int connect_websocket(struct server_config *cfg) {
    struct lws_context_creation_info info;
    char ws_url[256];
    
    snprintf(ws_url, sizeof(ws_url), "wss://audio-1.redenes.org/ws/?websocket_id=%d", cfg->websocket_id);
    printf("Connecting to: %s\n", ws_url);
    
    char address[128] = "audio-1.redenes.org";
    char path[256];
    int port = 443;
    
    snprintf(path, sizeof(path), "/ws/?websocket_id=%d", cfg->websocket_id);
    
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    
    ws_ctx.context = lws_create_context(&info);
    if (!ws_ctx.context) {
        fprintf(stderr, "WebSocket context failed\n");
        return 0;
    }
    
    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = ws_ctx.context;
    connect_info.address = address;
    connect_info.port = port;
    connect_info.path = path;
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.ssl_connection = LCCSCF_USE_SSL;
    connect_info.protocol = protocols[0].name;
    connect_info.pwsi = &ws_ctx.client_wsi;
    
    ws_ctx.client_wsi = lws_client_connect_via_info(&connect_info);
    if (ws_ctx.client_wsi == NULL) {
        fprintf(stderr, "WebSocket connect failed\n");
        return 0;
    }
    
    signal(SIGINT, handle_interrupt);
    
    printf("Entering event loop...\n");
    ws_ctx.interrupted = 0;
    while (!ws_ctx.interrupted && ws_ctx.client_wsi) {
        lws_service(ws_ctx.context, 100);
    }
    
    if (ws_ctx.context) {
        lws_context_destroy(ws_ctx.context);
        ws_ctx.context = NULL;
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    CURL *curl;
    CURLcode res;
    struct response_data resp = {0};
    
    if (!setup_audio()) {
        fprintf(stderr, "Audio setup failed\n");
        return 1;
    }
    
    resp.data = malloc(1);
    if (resp.data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    resp.data[0] = '\0';
    resp.size = 0;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://audio-1.redenes.org/audio-server-port");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl failed: %s\n", curl_easy_strerror(res));
            free(resp.data);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        } else {
            printf("Raw Response: %s\n", resp.data);
            
            if (parse_server_response(resp.data, &config)) {
                curl_easy_cleanup(curl);
                curl_global_cleanup();
                free(resp.data);
                
                if (!connect_websocket(&config)) {
                    fprintf(stderr, "WebSocket connection failed\n");
                    return 1;
                }
                
                return 0;
            }
        }
        
        curl_easy_cleanup(curl);
    }
    
    free(resp.data);
    curl_global_cleanup();
    return 1;
}