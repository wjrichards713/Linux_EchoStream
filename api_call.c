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
#include <errno.h>
#include <MQTTClient.h>

void auto_assign_usb_devices();
PaDeviceIndex get_device_for_channel(const char* channel);
int init_gpio_pin(int pin);
int read_gpio_pin(int pin);
void cleanup_gpio(int pin);
void* heartbeat_worker(void* arg);
void send_websocket_transmit_event(const char* channel_id, int is_started);
void* gpio_monitor_worker(void* arg);
void* udp_listener_worker(void* arg);
unsigned char* decrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len);
int decode_base64(const char* input, unsigned char* output);
size_t decode_base64_len(const char* input, unsigned char* output);

struct server_config {
    int udp_port;
    char udp_host[128];
    int websocket_id;
};

struct websocket_ctx {
    struct lws_context *context;
    struct lws *client_wsi;
    int interrupted;
    char channel_id[16];
};

#define JITTER_BUFFER_SIZE 8
#define SAMPLES_PER_FRAME 1920

struct audio_frame {
    float samples[SAMPLES_PER_FRAME];
    int sample_count;
    int valid;
};

struct jitter_buffer {
    struct audio_frame frames[JITTER_BUFFER_SIZE];
    int write_index;
    int read_index;
    int frame_count;
    pthread_mutex_t mutex;
};

struct audio_stream {
    PaStream *input_stream;
    PaStream *output_stream;
    OpusEncoder *encoder;
    OpusDecoder *decoder;
    unsigned char key[32];
    int transmitting;
    int gpio_active;
    float *input_buffer;
    struct jitter_buffer output_jitter;
    int buffer_size;
    int input_buffer_pos;
    int current_output_frame_pos;
    PaDeviceIndex device_index;
    char channel_id[16];
};

struct channel_context {
    struct audio_stream audio;
    pthread_t thread;
    int active;
};

static struct channel_context channels[2] = {0};
static PaDeviceIndex usb_devices[2] = {paNoDevice, paNoDevice};
static int device_assigned = 0;
static int global_interrupted = 0;
static int global_udp_socket = -1;
static struct sockaddr_in global_server_addr;
static pthread_t heartbeat_thread;
static pthread_t udp_listener_thread;
static int gpio_38_state = 0;
static int gpio_40_state = 0;
static pthread_mutex_t gpio_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct server_config global_config = {0};
static struct lws_context *global_ws_context = NULL;
static struct lws *global_ws_client = NULL;
static int global_config_initialized = 0;

// MQTT Client variables
static MQTTClient mqtt_client = NULL;
static MQTTClient_connectOptions mqtt_conn_opts = MQTTClient_connectOptions_initializer;
static int mqtt_connected = 0;
static pthread_mutex_t mqtt_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t mqtt_thread;

// MQTT Configuration
#define MQTT_BROKER_ADDRESS "tcp://localhost:1883"
#define MQTT_CLIENT_ID "EchoStream_Client"
#define MQTT_KEEP_ALIVE_INTERVAL 60
#define MQTT_CLEAN_SESSION 1
#define MQTT_QOS 1

// MQTT Topics
#define MQTT_TOPIC_AUDIO_STATUS "echostream/audio/status"
#define MQTT_TOPIC_GPIO_STATUS "echostream/gpio/status"
#define MQTT_TOPIC_SYSTEM_STATUS "echostream/status"
#define MQTT_TOPIC_COMMANDS "echostream/command"
#define MQTT_TOPIC_AUDIO_DATA "echostream/audio/data"

static void publish_MQTT_message(const char* topic, const char* payload) {
    if (!mqtt_connected || !mqtt_client) {
        printf("MQTT not connected, cannot publish message\n");
        return;
    }
    
    pthread_mutex_lock(&mqtt_mutex);
    
    MQTTClient_deliveryToken token;
    int rc = MQTTClient_publish(mqtt_client, topic, strlen(payload), payload, 
                                MQTT_QOS, 0, &token);
    
    if (rc == MQTTCLIENT_SUCCESS) {
        printf("MQTT: Published message to topic '%s': %s\n", topic, payload);
    } else {
        printf("MQTT: Failed to publish message to topic '%s': %d\n", topic, rc);
    }
    
    pthread_mutex_unlock(&mqtt_mutex);
}

static int mqtt_message_arrived(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
    printf("MQTT: Message received on topic '%s'\n", topicName);
    
    if (message->payloadlen > 0) {
        char* payload = malloc(message->payloadlen + 1);
        if (payload) {
            memcpy(payload, message->payload, message->payloadlen);
            payload[message->payloadlen] = '\0';
            
            printf("MQTT: Message payload: %s\n", payload);
            
            // Handle different command types
            if (strstr(payload, "\"command\"") || strstr(payload, "\"action\"")) {
                printf("MQTT: Processing command message\n");
                // Parse and handle commands here
                // You can add specific command handling logic
            }
            
            free(payload);
        }
    }
    
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    
    return 1;
}

static void mqtt_connection_lost(void *context, char *cause) {
    printf("MQTT: Connection lost. Cause: %s\n", cause ? cause : "Unknown");
    mqtt_connected = 0;
    
    // Attempt to reconnect
    pthread_t reconnect_thread;
    pthread_create(&reconnect_thread, NULL, mqtt_reconnect_worker, NULL);
    pthread_detach(reconnect_thread);
}

static int mqtt_connect() {
    if (mqtt_connected) {
        printf("MQTT: Already connected\n");
        return 1;
    }
    
    int rc;
    
    // Create MQTT client
    rc = MQTTClient_create(&mqtt_client, MQTT_BROKER_ADDRESS, MQTT_CLIENT_ID,
                           MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("MQTT: Failed to create client, return code %d\n", rc);
        return 0;
    }
    
    // Set callbacks
    rc = MQTTClient_setCallbacks(mqtt_client, NULL, mqtt_connection_lost, 
                                 mqtt_message_arrived, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("MQTT: Failed to set callbacks, return code %d\n", rc);
        MQTTClient_destroy(&mqtt_client);
        return 0;
    }
    
    // Setup connection options
    mqtt_conn_opts.keepAliveInterval = MQTT_KEEP_ALIVE_INTERVAL;
    mqtt_conn_opts.cleansession = MQTT_CLEAN_SESSION;
    mqtt_conn_opts.connectTimeout = 10;
    
    // Connect to broker
    printf("MQTT: Connecting to broker at %s\n", MQTT_BROKER_ADDRESS);
    rc = MQTTClient_connect(mqtt_client, &mqtt_conn_opts);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("MQTT: Failed to connect, return code %d\n", rc);
        MQTTClient_destroy(&mqtt_client);
        return 0;
    }
    
    mqtt_connected = 1;
    printf("MQTT: Connected successfully to broker\n");
    
    // Subscribe to topics
    rc = MQTTClient_subscribe(mqtt_client, MQTT_TOPIC_COMMANDS, MQTT_QOS);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("MQTT: Failed to subscribe to commands topic, return code %d\n", rc);
    } else {
        printf("MQTT: Subscribed to topic: %s\n", MQTT_TOPIC_COMMANDS);
    }
    
    // Publish initial status
    char status_msg[256];
    snprintf(status_msg, sizeof(status_msg), 
             "{\"status\":\"connected\",\"client_id\":\"%s\",\"timestamp\":%ld}",
             MQTT_CLIENT_ID, time(NULL));
    publish_MQTT_message(MQTT_TOPIC_SYSTEM_STATUS, status_msg);
    
    return 1;
}

static void mqtt_disconnect() {
    if (mqtt_client && mqtt_connected) {
        MQTTClient_disconnect(mqtt_client, 1000);
        MQTTClient_destroy(&mqtt_client);
        mqtt_connected = 0;
        printf("MQTT: Disconnected from broker\n");
    }
}

void* mqtt_reconnect_worker(void* arg) {
    printf("MQTT: Starting reconnection worker\n");
    
    while (!global_interrupted && !mqtt_connected) {
        printf("MQTT: Attempting to reconnect...\n");
        
        if (mqtt_connect()) {
            printf("MQTT: Reconnection successful\n");
            break;
        }
        
        printf("MQTT: Reconnection failed, waiting 5 seconds before retry\n");
        sleep(5);
    }
    
    printf("MQTT: Reconnection worker stopped\n");
    return NULL;
}

void* mqtt_worker(void* arg) {
    printf("MQTT: Starting MQTT worker thread\n");
    
    // Initial connection
    if (!mqtt_connect()) {
        printf("MQTT: Initial connection failed\n");
        return NULL;
    }
    
    // Main MQTT loop
    time_t last_test_message = 0;
    while (!global_interrupted && mqtt_connected) {
        // Process MQTT messages
        MQTTClient_yield();
        
        // Send periodic test message every 10 seconds
        time_t current_time = time(NULL);
        if (current_time - last_test_message >= 10) {
            char test_msg[256];
            snprintf(test_msg, sizeof(test_msg),
                     "{\"message\":\"This is the test MQTT message\",\"timestamp\":%ld,\"client_id\":\"%s\"}",
                     current_time, MQTT_CLIENT_ID);
            publish_MQTT_message(MQTT_TOPIC_SYSTEM_STATUS, test_msg);
            last_test_message = current_time;
        }
        
        usleep(100000); // 100ms delay
    }
    
    mqtt_disconnect();
    printf("MQTT: Worker thread stopped\n");
    return NULL;
}

static void handle_interrupt(int sig) {
    printf("\nShutdown signal received, cleaning up...\n");
    global_interrupted = 1;
    
    // Close the single WebSocket connection
    if (global_ws_client) {
        lws_close_reason(global_ws_client, LWS_CLOSE_STATUS_GOINGAWAY, NULL, 0);
    }
    
    // Disconnect MQTT client
    mqtt_disconnect();
    
    for (int i = 0; i < 2; i++) {
        if (channels[i].active) {
            channels[i].audio.transmitting = 0;
            
            if (channels[i].audio.input_stream) {
                Pa_AbortStream(channels[i].audio.input_stream);
                Pa_CloseStream(channels[i].audio.input_stream);
                channels[i].audio.input_stream = NULL;
            }
            
            if (channels[i].audio.output_stream) {
                Pa_AbortStream(channels[i].audio.output_stream);
                Pa_CloseStream(channels[i].audio.output_stream);
                channels[i].audio.output_stream = NULL;
            }
        }
    }
    
    if (global_udp_socket >= 0) {
        close(global_udp_socket);
        global_udp_socket = -1;
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
    if (input_len > 0 && input[input_len - 1] == '=') output_len--;
    if (input_len > 1 && input[input_len - 2] == '=') output_len--;
    
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

size_t decode_base64_len(const char* input, unsigned char* output) {
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
    if (input_len > 0 && input[input_len - 1] == '=') output_len--;
    if (input_len > 1 && input[input_len - 2] == '=') output_len--;
    
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
    
    return output_len;
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

unsigned char* decrypt_data(const unsigned char* data, size_t data_len, const unsigned char* key, size_t* out_len) {
    if (data_len < 28) return NULL; // IV(12) + TAG(16) minimum
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    
    const unsigned char* iv = data;
    const unsigned char* ciphertext = data + 12;
    const unsigned char* tag = data + data_len - 16;
    size_t ciphertext_len = data_len - 28;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    unsigned char* decrypted = malloc(ciphertext_len);
    if (!decrypted) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    plaintext_len += len;
    *out_len = plaintext_len;
    
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

static int audio_input_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    if (!audio_stream->transmitting || !input || !audio_stream->gpio_active) {
        return paContinue;
    }
    
    const float *samples = (const float*)input;
    
    for (unsigned long i = 0; i < frames; i++) {
        audio_stream->input_buffer[audio_stream->input_buffer_pos++] = samples[i];
        
        if (audio_stream->input_buffer_pos >= 1920) {
            short pcm[1920];
            for (int j = 0; j < 1920; j++) {
                float sample = audio_stream->input_buffer[j];
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
                        
                        sendto(global_udp_socket, msg, strlen(msg), 0,
                               (struct sockaddr*)&global_server_addr, sizeof(global_server_addr));
                        
                        // Publish MQTT audio status
                        char mqtt_audio_msg[512];
                        snprintf(mqtt_audio_msg, sizeof(mqtt_audio_msg),
                                 "{\"channel_id\":\"%s\",\"type\":\"audio_transmission\",\"opus_len\":%d,\"encrypted_len\":%zu,\"timestamp\":%ld}",
                                 audio_stream->channel_id, opus_len, encrypted_len, time(NULL));
                        publish_MQTT_message(MQTT_TOPIC_AUDIO_STATUS, mqtt_audio_msg);
                        
                        free(b64_data);
                    }
                    free(encrypted);
                }
            }
            
            audio_stream->input_buffer_pos = 0;
        }
    }
    
    return paContinue;
}

static int audio_output_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    float *out = (float*)output;
    struct jitter_buffer *jitter = &audio_stream->output_jitter;
    
    static int callback_count = 0;
    if (callback_count++ % 100 == 0) {
        printf("Audio output callback called (frames=%lu, buffer_count=%d)\n", frames, jitter->frame_count);
    }
    
    pthread_mutex_lock(&jitter->mutex);
    
    unsigned long frames_filled = 0;
    
    while (frames_filled < frames) {
        // Check if we have a current frame to read from
        if (jitter->frame_count > 0) {
            struct audio_frame *current_frame = &jitter->frames[jitter->read_index];
            
            if (current_frame->valid) {
                // Calculate how many samples we can copy from current frame
                int remaining_in_frame = current_frame->sample_count - audio_stream->current_output_frame_pos;
                unsigned long frames_to_copy = frames - frames_filled;
                
                if (frames_to_copy > remaining_in_frame) {
                    frames_to_copy = remaining_in_frame;
                }
                
                // Copy samples from current frame
                for (unsigned long i = 0; i < frames_to_copy; i++) {
                    out[frames_filled + i] = current_frame->samples[audio_stream->current_output_frame_pos + i];
                }
                
                frames_filled += frames_to_copy;
                audio_stream->current_output_frame_pos += frames_to_copy;
                
                // Check if we finished this frame
                if (audio_stream->current_output_frame_pos >= current_frame->sample_count) {
                    // Mark frame as consumed
                    current_frame->valid = 0;
                    jitter->read_index = (jitter->read_index + 1) % JITTER_BUFFER_SIZE;
                    jitter->frame_count--;
                    audio_stream->current_output_frame_pos = 0;
                }
            } else {
                // Frame is invalid, skip it
                jitter->read_index = (jitter->read_index + 1) % JITTER_BUFFER_SIZE;
                jitter->frame_count--;
                audio_stream->current_output_frame_pos = 0;
            }
        } else {
            // No frames available, fill with silence
            for (unsigned long i = frames_filled; i < frames; i++) {
                out[i] = 0.0f;
            }
            frames_filled = frames;
        }
    }
    
    pthread_mutex_unlock(&jitter->mutex);
    return paContinue;
}

int setup_audio_for_channel(struct audio_stream* audio_stream) {
    int error;
    
    // Setup encoder
    audio_stream->encoder = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        fprintf(stderr, "Opus encoder error: %s\n", opus_strerror(error));
        return 0;
    }
    
    opus_encoder_ctl(audio_stream->encoder, OPUS_SET_BITRATE(64000));
    opus_encoder_ctl(audio_stream->encoder, OPUS_SET_VBR(1));
    
    // Setup decoder
    audio_stream->decoder = opus_decoder_create(48000, 1, &error);
    if (error != OPUS_OK) {
        fprintf(stderr, "Opus decoder error: %s\n", opus_strerror(error));
        opus_encoder_destroy(audio_stream->encoder);
        return 0;
    }
    
    // Setup buffers
    audio_stream->buffer_size = 4800;
    audio_stream->input_buffer = malloc(audio_stream->buffer_size * sizeof(float));
    audio_stream->input_buffer_pos = 0;
    audio_stream->current_output_frame_pos = 0;
    audio_stream->gpio_active = 0;
    
    // Initialize jitter buffer
    memset(&audio_stream->output_jitter, 0, sizeof(struct jitter_buffer));
    pthread_mutex_init(&audio_stream->output_jitter.mutex, NULL);
    
    for (int i = 0; i < JITTER_BUFFER_SIZE; i++) {
        audio_stream->output_jitter.frames[i].valid = 0;
        audio_stream->output_jitter.frames[i].sample_count = 0;
    }
    
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

int setup_global_udp(struct server_config* config) {
    if (global_udp_socket >= 0) {
        printf("UDP socket already configured for %s:%d\n", config->udp_host, config->udp_port);
        return 1;
    }
    
    global_udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (global_udp_socket < 0) {
        perror("socket failed");
        return 0;
    }
    
    memset(&global_server_addr, 0, sizeof(global_server_addr));
    global_server_addr.sin_family = AF_INET;
    global_server_addr.sin_port = htons(config->udp_port);
    
    if (inet_aton(config->udp_host, &global_server_addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid UDP host\n");
        close(global_udp_socket);
        global_udp_socket = -1;
        return 0;
    }
    
    printf("Global UDP socket configured for %s:%d\n", config->udp_host, config->udp_port);
    
    // Add socket info for debugging
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(global_udp_socket, (struct sockaddr*)&local_addr, &addr_len) == 0) {
        printf("UDP socket bound to local port: %d\n", ntohs(local_addr.sin_port));
    } else {
        printf("UDP socket local binding info unavailable\n");
    }
    
    // Send immediate heartbeat to establish connection
    const char* heartbeat_msg = "{\"type\":\"KEEP_ALIVE\"}";
    int result = sendto(global_udp_socket, heartbeat_msg, strlen(heartbeat_msg), 0,
                       (struct sockaddr*)&global_server_addr, sizeof(global_server_addr));
    
    if (result >= 0) {
        printf("Initial heartbeat sent immediately upon UDP connection\n");
    } else {
        printf("Initial heartbeat error: %s\n", strerror(errno));
    }
    
    static int heartbeat_started = 0;
    if (!heartbeat_started) {
        if (pthread_create(&heartbeat_thread, NULL, heartbeat_worker, NULL)) {
            fprintf(stderr, "Failed to create heartbeat thread\n");
        } else {
            heartbeat_started = 1;
        }
    }
    
    // Start UDP listener thread now that UDP socket is configured
    static int udp_listener_started = 0;
    if (!udp_listener_started) {
        if (pthread_create(&udp_listener_thread, NULL, udp_listener_worker, NULL)) {
            fprintf(stderr, "Failed to create UDP listener thread\n");
        } else {
            udp_listener_started = 1;
        }
    }
    
    return 1;
}

int start_transmission_for_channel(struct audio_stream* audio_stream) {
    PaStreamParameters input_params, output_params;
    
    audio_stream->device_index = get_device_for_channel(audio_stream->channel_id);
    
    // Setup input stream
    input_params.device = audio_stream->device_index;
    if (input_params.device == paNoDevice) {
        fprintf(stderr, "No input device for channel %s\n", audio_stream->channel_id);
        return 0;
    }
    
    input_params.channelCount = 1;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    PaError err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, 48000, 1024, 
                                paClipOff, audio_input_callback, audio_stream);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input stream error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    // Setup output stream
    output_params.device = audio_stream->device_index;
    output_params.channelCount = 1;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024, 
                        paClipOff, audio_output_callback, audio_stream);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio output stream error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        return 0;
    }
    
    // Start both streams
    err = Pa_StartStream(audio_stream->input_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
    }
    
    err = Pa_StartStream(audio_stream->output_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio output start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
    }
    
    // Check if streams are actually running
    if (Pa_IsStreamActive(audio_stream->input_stream)) {
        printf("Input stream is active for channel %s\n", audio_stream->channel_id);
    } else {
        printf("WARNING: Input stream is NOT active for channel %s\n", audio_stream->channel_id);
    }
    
    if (Pa_IsStreamActive(audio_stream->output_stream)) {
        printf("Output stream is active for channel %s\n", audio_stream->channel_id);
    } else {
        printf("WARNING: Output stream is NOT active for channel %s\n", audio_stream->channel_id);
    }
    
    audio_stream->transmitting = 1;
    printf("Audio transmission started for channel %s (input + output)\n", audio_stream->channel_id);
    return 1;
}

int parse_websocket_config(const char *json_str, struct server_config *cfg) {
    struct json_object *json;
    struct json_object *udp_port, *udp_host, *websocket_id;
    
    json = json_tokener_parse(json_str);
    if (json == NULL) {
        fprintf(stderr, "JSON parse failed\n");
        return 0;
    }
    
    if (json_object_object_get_ex(json, "udp_port", &udp_port) &&
        json_object_object_get_ex(json, "udp_host", &udp_host) &&
        json_object_object_get_ex(json, "websocket_id", &websocket_id)) {
        
        cfg->udp_port = json_object_get_int(udp_port);
        strncpy(cfg->udp_host, json_object_get_string(udp_host), sizeof(cfg->udp_host) - 1);
        cfg->websocket_id = json_object_get_int(websocket_id);
        
        printf("UDP Port: %d\n", cfg->udp_port);
        printf("UDP Host: %s\n", cfg->udp_host);
        printf("WebSocket ID: %d\n", cfg->websocket_id);
        
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
    // Single WebSocket connection handles both channels
    if (wsi != global_ws_client) {
        return 0;
    }
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            printf("WebSocket connection established for both channels\n");
            
            // Send connect message for both active channels
            for (int i = 0; i < 2; i++) {
                if (channels[i].active) {
                    char connect_msg[512];
                    time_t now = time(NULL);
                    
                    snprintf(connect_msg, sizeof(connect_msg),
                        "{\"connect\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"%s\",\"time\":%ld}}",
                        channels[i].audio.channel_id, now);
                    
                    printf("Sending connect message for channel %s: %s\n", channels[i].audio.channel_id, connect_msg);
                    
                    size_t msg_len = strlen(connect_msg);
                    unsigned char *buf = malloc(LWS_PRE + msg_len);
                    if (buf) {
                        memcpy(&buf[LWS_PRE], connect_msg, msg_len);
                        lws_write(wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
                        free(buf);
                    }
                }
            }
            
            printf("Waiting for UDP connection info from WebSocket\n");
            break;
        }
            
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            printf("Received WebSocket message: %.*s\n", (int)len, (char *)in);
            
            char *data = malloc(len + 1);
            if (data) {
                memcpy(data, in, len);
                data[len] = '\0';
                
                // Check if this is the UDP connection info message
                if (strstr(data, "udp_host") && strstr(data, "udp_port") && strstr(data, "websocket_id")) {
                    printf("Received UDP connection info: %s\n", data);
                    
                    // Parse the WebSocket configuration
                    if (parse_websocket_config(data, &global_config)) {
                        printf("Successfully parsed UDP connection info\n");
                        global_config_initialized = 1;
                        
                        // Setup UDP connection
                        if (setup_global_udp(&global_config)) {
                            printf("UDP connection established\n");
                            
                            // Start transmission for all active channels
                            for (int i = 0; i < 2; i++) {
                                if (channels[i].active) {
                                    const char* key_b64 = "46dR4QR5KH7JhPyyjh/ZS4ki/3QBVwwOTkkQTdZQkC0=";
                                    if (!decode_base64(key_b64, channels[i].audio.key)) {
                                        fprintf(stderr, "Key decode failed for channel %s\n", channels[i].audio.channel_id);
                                        continue;
                                    }
                                    printf("AES key decoded for channel %s\n", channels[i].audio.channel_id);
                                    
                                    if (start_transmission_for_channel(&channels[i].audio)) {
                                        printf("Audio transmission ready for channel %s (waiting for GPIO activation)\n", channels[i].audio.channel_id);
                                    }
                                }
                            }
                        }
                    }
                }
                else if (strstr(data, "users_connected")) {
                    printf("Users connected message received, but UDP not yet configured\n");
                }
                
                free(data);
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("WebSocket closed for both channels\n");
            global_ws_client = NULL;
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("WebSocket error: %.*s\n", (int)len, (char *)in);
            global_ws_client = NULL;
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

int connect_global_websocket() {
    if (global_ws_context && global_ws_client) {
        printf("WebSocket already connected\n");
        return 1;
    }
    
    struct lws_context_creation_info info;
    char ws_url[256] = "wss://audio.redenes.org/ws/";
    
    printf("Connecting to: %s for both channels\n", ws_url);
    
    char address[128] = "audio.redenes.org";
    char path[256] = "/ws/";
    int port = 443;
    
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    
    global_ws_context = lws_create_context(&info);
    if (!global_ws_context) {
        fprintf(stderr, "WebSocket context failed\n");
        return 0;
    }
    
    // Create a single WebSocket connection for both channels
    struct lws_client_connect_info connect_info;
    memset(&connect_info, 0, sizeof(connect_info));
    connect_info.context = global_ws_context;
    connect_info.address = address;
    connect_info.port = port;
    connect_info.path = path;
    connect_info.host = connect_info.address;
    connect_info.origin = connect_info.address;
    connect_info.ssl_connection = LCCSCF_USE_SSL;
    connect_info.protocol = protocols[0].name;
    connect_info.pwsi = &global_ws_client;
    
    global_ws_client = lws_client_connect_via_info(&connect_info);
    
    if (global_ws_client == NULL) {
        fprintf(stderr, "WebSocket connect failed\n");
        return 0;
    }
    
    printf("Single WebSocket connection established for both channels\n");
    return 1;
}

void* global_websocket_thread(void* arg) {
    printf("Starting global WebSocket thread\n");
    
    while (!global_interrupted && global_ws_context) {
        lws_service(global_ws_context, 10);
    }
    
    // Close the single WebSocket connection
    if (global_ws_client) {
        lws_close_reason(global_ws_client, LWS_CLOSE_STATUS_GOINGAWAY, NULL, 0);
        global_ws_client = NULL;
    }
    
    // Cleanup all channels
    for (int i = 0; i < 2; i++) {
        if (channels[i].active) {
            if (channels[i].audio.input_stream && !global_interrupted) {
                Pa_AbortStream(channels[i].audio.input_stream);
                Pa_CloseStream(channels[i].audio.input_stream);
                channels[i].audio.input_stream = NULL;
            }
            
            if (channels[i].audio.output_stream && !global_interrupted) {
                Pa_AbortStream(channels[i].audio.output_stream);
                Pa_CloseStream(channels[i].audio.output_stream);
                channels[i].audio.output_stream = NULL;
            }
            
            if (channels[i].audio.encoder) {
                opus_encoder_destroy(channels[i].audio.encoder);
                channels[i].audio.encoder = NULL;
            }
            
            if (channels[i].audio.decoder) {
                opus_decoder_destroy(channels[i].audio.decoder);
                channels[i].audio.decoder = NULL;
            }
            
            if (channels[i].audio.input_buffer) {
                free(channels[i].audio.input_buffer);
                channels[i].audio.input_buffer = NULL;
            }
            
            pthread_mutex_destroy(&channels[i].audio.output_jitter.mutex);
            
            channels[i].active = 0;
        }
    }
    
    if (global_ws_context) {
        lws_context_destroy(global_ws_context);
        global_ws_context = NULL;
    }
    
    printf("Global WebSocket thread terminated\n");
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

int init_gpio_pin(int pin) {
    char path[64], value[8];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/unexport");
    if ((fd = open(path, O_WRONLY)) != -1) {
        snprintf(value, sizeof(value), "%d", pin);
        write(fd, value, strlen(value));
        close(fd);
    }
    
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
        return -1;
    }
    
    if (read(fd, value, 3) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    
    return (value[0] == '0') ? 0 : 1;
}

void cleanup_gpio(int pin) {
    char path[64], value[8];
    int fd;
    
    snprintf(path, sizeof(path), "/sys/class/gpio/unexport");
    if ((fd = open(path, O_WRONLY)) != -1) {
        snprintf(value, sizeof(value), "%d", pin);
        write(fd, value, strlen(value));
        close(fd);
    }
}

void* heartbeat_worker(void* arg) {
    printf("Heartbeat worker started\n");
    
    while (!global_interrupted) {
        if (global_udp_socket >= 0) {
            const char* heartbeat_msg = "{\"type\":\"KEEP_ALIVE\"}";
            int result = sendto(global_udp_socket, heartbeat_msg, strlen(heartbeat_msg), 0,
                               (struct sockaddr*)&global_server_addr, sizeof(global_server_addr));
            
            if (result >= 0) {
                printf("Heartbeat sent to keep NAT mapping active\n");
            } else {
                printf("Heartbeat error: %s\n", strerror(errno));
            }
        }
        
        for (int i = 0; i < 100 && !global_interrupted; i++) {
            usleep(100000);
        }
    }
    
    printf("Heartbeat worker stopped\n");
    return NULL;
}

void send_websocket_transmit_event(const char* channel_id, int is_started) {
    if (!global_ws_client) {
        printf("WebSocket not connected, cannot send transmit event\n");
        return;
    }
    
    char transmit_msg[512];
    time_t now = time(NULL);
    const char* event_type = is_started ? "transmit_started" : "transmit_ended";
    
    snprintf(transmit_msg, sizeof(transmit_msg),
        "{\"%s\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"%s\",\"time\":%ld}}",
        event_type, channel_id, now);
    
    printf("Sending %s for channel %s: %s\n", event_type, channel_id, transmit_msg);
    
    size_t msg_len = strlen(transmit_msg);
    unsigned char *buf = malloc(LWS_PRE + msg_len);
    if (buf) {
        memcpy(&buf[LWS_PRE], transmit_msg, msg_len);
        lws_write(global_ws_client, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
        free(buf);
    }
}

void* gpio_monitor_worker(void* arg) {
    int gpio_pin_38 = 589;  // GPIO 20 (physical pin 38) on RPi5
    int gpio_pin_40 = 590;  // GPIO 21 (physical pin 40) on RPi5
    
    printf("GPIO monitor worker started\n");
    
    if (!init_gpio_pin(gpio_pin_38)) {
        printf("Failed to initialize GPIO pin 38\n");
        return NULL;
    }
    
    if (!init_gpio_pin(gpio_pin_40)) {
        printf("Failed to initialize GPIO pin 40\n");
        cleanup_gpio(gpio_pin_38);
        return NULL;
    }
    
    printf("GPIO pins initialized. Reading initial states...\n");
    
    // Read initial states without sending WebSocket events
    pthread_mutex_lock(&gpio_mutex);
    gpio_38_state = read_gpio_pin(gpio_pin_38);
    gpio_40_state = read_gpio_pin(gpio_pin_40);
    pthread_mutex_unlock(&gpio_mutex);
    
    if (gpio_38_state != -1) {
        printf("PIN 38 (Channel 555) initial state: %s\n", 
               gpio_38_state == 0 ? "ACTIVE (PTT ON)" : "INACTIVE (PTT OFF)");
    }
    
    if (gpio_40_state != -1) {
        printf("PIN 40 (Channel 666) initial state: %s\n", 
               gpio_40_state == 0 ? "ACTIVE (PTT ON)" : "INACTIVE (PTT OFF)");
    }
    
    printf("GPIO pins initialized. Monitoring for changes...\n");
    
    while (!global_interrupted) {
        int curr_val_38 = read_gpio_pin(gpio_pin_38);
        int curr_val_40 = read_gpio_pin(gpio_pin_40);
        
        pthread_mutex_lock(&gpio_mutex);
        
        if (curr_val_38 != gpio_38_state && curr_val_38 != -1) {
            gpio_38_state = curr_val_38;
            printf("PIN 38 (Channel 555): %s\n", 
                   curr_val_38 == 0 ? "ACTIVE (PTT ON)" : "INACTIVE (PTT OFF)");
            
            for (int i = 0; i < 2; i++) {
                if (channels[i].active && strcmp(channels[i].audio.channel_id, "555") == 0) {
                    channels[i].audio.gpio_active = (curr_val_38 == 0) ? 1 : 0;
                    break;
                }
            }
            
            // Send WebSocket transmit event
            send_websocket_transmit_event("555", (curr_val_38 == 0) ? 1 : 0);
            
            // Publish MQTT GPIO status
            char mqtt_gpio_msg[256];
            snprintf(mqtt_gpio_msg, sizeof(mqtt_gpio_msg),
                     "{\"channel\":\"555\",\"gpio_pin\":38,\"state\":\"%s\",\"timestamp\":%ld}",
                     curr_val_38 == 0 ? "active" : "inactive", time(NULL));
            publish_MQTT_message(MQTT_TOPIC_GPIO_STATUS, mqtt_gpio_msg);
        }
        
        if (curr_val_40 != gpio_40_state && curr_val_40 != -1) {
            gpio_40_state = curr_val_40;
            printf("PIN 40 (Channel 666): %s\n", 
                   curr_val_40 == 0 ? "ACTIVE (PTT ON)" : "INACTIVE (PTT OFF)");
            
            for (int i = 0; i < 2; i++) {
                if (channels[i].active && strcmp(channels[i].audio.channel_id, "666") == 0) {
                    channels[i].audio.gpio_active = (curr_val_40 == 0) ? 1 : 0;
                    break;
                }
            }
            
            // Send WebSocket transmit event
            send_websocket_transmit_event("666", (curr_val_40 == 0) ? 1 : 0);
            
            // Publish MQTT GPIO status
            char mqtt_gpio_msg[256];
            snprintf(mqtt_gpio_msg, sizeof(mqtt_gpio_msg),
                     "{\"channel\":\"666\",\"gpio_pin\":40,\"state\":\"%s\",\"timestamp\":%ld}",
                     curr_val_40 == 0 ? "active" : "inactive", time(NULL));
            publish_MQTT_message(MQTT_TOPIC_GPIO_STATUS, mqtt_gpio_msg);
        }
        
        pthread_mutex_unlock(&gpio_mutex);
        
        usleep(100000);
    }
    
    printf("GPIO monitor worker stopped\n");
    cleanup_gpio(gpio_pin_38);
    cleanup_gpio(gpio_pin_40);
    
    return NULL;
}

void* udp_listener_worker(void* arg) {
    printf("UDP listener worker started\n");
    
    if (global_udp_socket < 0) {
        printf("UDP Listener: ERROR - Invalid socket %d\n", global_udp_socket);
        return NULL;
    }
    
    printf("Listening on UDP socket %d...\n", global_udp_socket);
    
    char buffer[8192];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    while (!global_interrupted) {
        int bytes_received = recvfrom(global_udp_socket, buffer, sizeof(buffer) - 1, 0,
                                    (struct sockaddr*)&client_addr, &client_len);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            // printf("UDP Listener: Received %d bytes from %s:%d\n", 
            //        bytes_received, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            // printf("UDP Listener: Raw data: %.*s\n", bytes_received, buffer);
            
            // Parse JSON message
            struct json_object *json = json_tokener_parse(buffer);
            if (json == NULL) {
                printf("UDP Listener: Failed to parse JSON\n");
                continue;
            }
            
            // printf("UDP Listener: JSON parsed successfully\n");
            
            struct json_object *channel_id_obj, *type_obj, *data_obj;
            
            if (json_object_object_get_ex(json, "channel_id", &channel_id_obj) &&
                json_object_object_get_ex(json, "type", &type_obj) &&
                json_object_object_get_ex(json, "data", &data_obj)) {
                
                const char* channel_id = json_object_get_string(channel_id_obj);
                const char* type = json_object_get_string(type_obj);
                const char* data = json_object_get_string(data_obj);
                
                // printf("UDP Listener: Parsed - channel_id='%s', type='%s', data_length=%zu\n", 
                //        channel_id, type, strlen(data));
                
                if (strcmp(type, "audio") == 0) {
                    // printf("UDP Listener: Processing audio message for channel %s\n", channel_id);
                    
                    // Find the channel
                    struct audio_stream* target_stream = NULL;
                    for (int i = 0; i < 2; i++) {
                        if (channels[i].active && strcmp(channels[i].audio.channel_id, channel_id) == 0) {
                            target_stream = &channels[i].audio;
                            // printf("UDP Listener: Found target channel %s at index %d\n", channel_id, i);
                            break;
                        }
                    }
                    
                    if (!target_stream) {
                        printf("UDP Listener: No active channel found for '%s'\n", channel_id);
                        printf("UDP Listener: Active channels: ");
                        for (int i = 0; i < 2; i++) {
                            if (channels[i].active) {
                                printf("'%s' ", channels[i].audio.channel_id);
                            }
                        }
                        printf("\n");
                    }
                    
                    if (target_stream) {
                        // printf("UDP Listener: Decoding base64 data (length=%zu)\n", strlen(data));
                        
                        // Decode base64 data
                        unsigned char encrypted_data[4000];
                        size_t encrypted_len = decode_base64_len(data, encrypted_data);
                        
                        if (encrypted_len > 0) {
                            printf("UDP Listener: Base64 decoded successfully (%zu bytes)\n", encrypted_len);
                            
                            // Debug: Print first few bytes of encrypted data and key
                            printf("UDP Listener: Encrypted data (first 16 bytes): ");
                            for (int k = 0; k < 16 && k < encrypted_len; k++) {
                                printf("%02x ", encrypted_data[k]);
                            }
                            printf("\n");
                            
                            printf("UDP Listener: Using key (first 16 bytes): ");
                            for (int k = 0; k < 16; k++) {
                                printf("%02x ", target_stream->key[k]);
                            }
                            printf("\n");
                            
                            // Decrypt the data
                            size_t decrypted_len;
                            unsigned char* decrypted = decrypt_data(encrypted_data, encrypted_len, 
                                                                  target_stream->key, &decrypted_len);
                            
                            if (decrypted) {
                                printf("UDP Listener: Data decrypted successfully (%zu bytes)\n", decrypted_len);
                                
                                // Decode Opus audio
                                short pcm_data[1920];
                                int samples = opus_decode(target_stream->decoder, decrypted, decrypted_len, 
                                                        pcm_data, 1920, 0);
                                
                                if (samples > 0) {
                                    printf("UDP Listener: Opus decoded successfully (%d samples)\n", samples);
                                    
                                    // Debug: Check audio levels
                                    short max_sample = 0;
                                    for (int s = 0; s < samples; s++) {
                                        if (abs(pcm_data[s]) > max_sample) {
                                            max_sample = abs(pcm_data[s]);
                                        }
                                    }
                                    printf("UDP Listener: Audio level check - max sample: %d (%.2f%%)\n", 
                                           max_sample, (float)max_sample / 32767.0f * 100.0f);
                                    
                                    // Add audio frame to jitter buffer
                                    struct jitter_buffer *jitter = &target_stream->output_jitter;
                                    pthread_mutex_lock(&jitter->mutex);
                                    
                                    if (jitter->frame_count < JITTER_BUFFER_SIZE) {
                                        // Add new frame to buffer
                                        struct audio_frame *frame = &jitter->frames[jitter->write_index];
                                        
                                        // Convert PCM to float and copy to frame (with gain boost)
                                        for (int j = 0; j < samples && j < SAMPLES_PER_FRAME; j++) {
                                            float sample = (float)pcm_data[j] / 32767.0f;
                                            // Apply 10x gain boost for very quiet audio
                                            sample *= 10.0f;
                                            // Clamp to prevent distortion
                                            if (sample > 1.0f) sample = 1.0f;
                                            if (sample < -1.0f) sample = -1.0f;
                                            frame->samples[j] = sample;
                                        }
                                        frame->sample_count = samples;
                                        frame->valid = 1;
                                        
                                        jitter->write_index = (jitter->write_index + 1) % JITTER_BUFFER_SIZE;
                                        jitter->frame_count++;
                                        
                                        printf("UDP: Audio queued for %s (buffer=%d)\n", 
                                               channel_id, jitter->frame_count);
                                    } else {
                                        // Buffer full, drop oldest frame and add new one
                                        jitter->read_index = (jitter->read_index + 1) % JITTER_BUFFER_SIZE;
                                        jitter->frame_count--;
                                        
                                        struct audio_frame *frame = &jitter->frames[jitter->write_index];
                                        for (int j = 0; j < samples && j < SAMPLES_PER_FRAME; j++) {
                                            float sample = (float)pcm_data[j] / 32767.0f;
                                            // Apply 10x gain boost for very quiet audio
                                            sample *= 10.0f;
                                            // Clamp to prevent distortion
                                            if (sample > 1.0f) sample = 1.0f;
                                            if (sample < -1.0f) sample = -1.0f;
                                            frame->samples[j] = sample;
                                        }
                                        frame->sample_count = samples;
                                        frame->valid = 1;
                                        
                                        jitter->write_index = (jitter->write_index + 1) % JITTER_BUFFER_SIZE;
                                        jitter->frame_count++;
                                        
                                        printf("UDP: Buffer full, dropped frame for %s\n", channel_id);
                                    }
                                    
                                    pthread_mutex_unlock(&jitter->mutex);
                                } else {
                                    printf("UDP Listener: Opus decode failed: %s\n", opus_strerror(samples));
                                }
                                
                                free(decrypted);
                            } else {
                                printf("UDP Listener: Decryption failed\n");
                            }
                        } else {
                            printf("UDP Listener: Base64 decode failed\n");
                        }
                    }
                } else {
                    printf("UDP Listener: Non-audio message type '%s', ignoring\n", type);
                }
            } else {
                printf("UDP Listener: JSON missing required fields (channel_id, type, data)\n");
            }
            
            json_object_put(json);
        } else if (bytes_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("UDP Listener: No data available (would block)\n");
                usleep(100000); // Wait 100ms before trying again
            } else {
                if (!global_interrupted) {
                    printf("UDP Listener: Receive error - %s (errno=%d)\n", strerror(errno), errno);
                    perror("UDP receive error");
                }
                break;
            }
        } else if (bytes_received == 0) {
            printf("UDP Listener: Received 0 bytes (connection closed?)\n");
        }
    }
    
    printf("UDP listener worker stopped\n");
    return NULL;
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

int main(int argc, char *argv[]) {
    int run_both = 1;
    
    if (argc > 1) {
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
            fprintf(stderr, "Usage: %s [555|666|both]\n", argv[0]);
            fprintf(stderr, "  555  - Run channel 555 only\n");
            fprintf(stderr, "  666  - Run channel 666 only\n");
            fprintf(stderr, "  both - Run both channels simultaneously (default)\n");
            return 1;
        }
    } else {
        printf("Running both channels simultaneously (default)\n");
    }
    
    if (!initialize_portaudio()) {
        fprintf(stderr, "PortAudio initialization failed\n");
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    signal(SIGINT, handle_interrupt);
    
    pthread_t gpio_thread;
    if (pthread_create(&gpio_thread, NULL, gpio_monitor_worker, NULL)) {
        fprintf(stderr, "Failed to create GPIO monitor thread\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Start MQTT thread
    pthread_t mqtt_thread;
    if (pthread_create(&mqtt_thread, NULL, mqtt_worker, NULL)) {
        fprintf(stderr, "Failed to create MQTT thread\n");
        curl_global_cleanup();
        return 1;
    }
    
    // UDP configuration will be received via WebSocket
    // UDP listener thread will be started after UDP connection is established
    
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
        
        // Connect global WebSocket for both channels
        if (!connect_global_websocket()) {
            fprintf(stderr, "Failed to connect WebSocket\n");
            curl_global_cleanup();
            return 1;
        }
        
        pthread_t ws_thread;
        if (pthread_create(&ws_thread, NULL, global_websocket_thread, NULL)) {
            fprintf(stderr, "Failed to create WebSocket thread\n");
            curl_global_cleanup();
            return 1;
        }
        
        printf("Both channels running with single WebSocket. Press Ctrl+C to stop.\n");
        
        if (global_interrupted) {
            struct timespec timeout;
            clock_gettime(CLOCK_REALTIME, &timeout);
            timeout.tv_sec += 2;
            
            if (pthread_timedjoin_np(ws_thread, NULL, &timeout) != 0) {
                printf("Forcing termination of WebSocket thread\n");
                pthread_cancel(ws_thread);
            }
        } else {
            pthread_join(ws_thread, NULL);
        }
        
    } else {
        int channel_idx = (argc > 1 && atoi(argv[1]) == 666) ? 1 : 0;
        const char* channel_id = (channel_idx == 0) ? "555" : "666";
        
        if (!setup_channel(&channels[channel_idx], channel_id)) {
            fprintf(stderr, "Failed to setup channel %s\n", channel_id);
            curl_global_cleanup();
            return 1;
        }
        
        if (!connect_global_websocket()) {
            fprintf(stderr, "Failed to connect WebSocket\n");
            curl_global_cleanup();
            return 1;
        }
        
        global_websocket_thread(NULL);
    }
    
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}