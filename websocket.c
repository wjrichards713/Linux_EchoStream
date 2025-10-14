#include "websocket.h"
#include "audio.h"
#include "udp.h"
#include "crypto.h"
#include <unistd.h>

// Global WebSocket state
struct lws_context *global_ws_context = NULL;
struct lws *global_ws_client = NULL;
struct server_config global_config = {0};
int global_config_initialized = 0;

static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
                             void *user, void *in, size_t len) {
    // Single WebSocket connection handles all channels
    if (wsi != global_ws_client) {
        return 0;
    }
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            printf("[INFO] WebSocket connection established for all channels\n");
            printf("[DEBUG] LWS_CALLBACK_CLIENT_ESTABLISHED received\n");
            
            // Register all active channels with WebSocket
            printf("[INFO] Registering all active channels with WebSocket\n");
            for (int i = 0; i < 4; i++) {
                if (channels[i].active) {
                    printf("[INFO] Registering channel %s\n", channels[i].audio.channel_id);
                    send_websocket_transmit_event(channels[i].audio.channel_id, 1);
                }
            }
            
            // Send connect message for all active channels
            for (int i = 0; i < 4; i++) {
                if (channels[i].active) {
                    char connect_msg[1024];
                    time_t now = time(NULL);
                    
                    snprintf(connect_msg, sizeof(connect_msg),
                        "{\"connect\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"%s\",\"time\":%ld}}",
                        channels[i].audio.channel_id, now);
                    
                    printf("[INFO] Sending connect message for channel %s\n", channels[i].audio.channel_id);
                    
                    size_t msg_len = strlen(connect_msg);
                    unsigned char *buf = malloc(LWS_PRE + msg_len);
                    if (!buf) {
                        printf("[ERROR] Failed to allocate memory for connect message\n");
                        continue;
                    }
                    
                    memcpy(&buf[LWS_PRE], connect_msg, msg_len);
                    int result = lws_write(wsi, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
                    
                    if (result < 0) {
                        printf("[ERROR] Failed to send connect message for channel %s (result=%d)\n", channels[i].audio.channel_id, result);
                    } else {
                        printf("[INFO] Connect message sent successfully for channel %s (%d bytes)\n", channels[i].audio.channel_id, result);
                    }
                    
                    free(buf);
                }
            }
            
            printf("[INFO] Waiting for UDP connection info from WebSocket\n");
            break;
        }
            
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            static int ws_message_count = 0;
            ws_message_count++;
            // Only log every 50th WebSocket message (or important ones)
            int is_important = (strstr((char*)in, "udp_host") != NULL) || 
                              (strstr((char*)in, "error") != NULL) ||
                              (strstr((char*)in, "disconnect") != NULL);
            if ((ws_message_count % 50 == 0) || is_important) {
                printf("Received WebSocket message (#%d): %.*s\n", ws_message_count, (int)len, (char *)in);
            }
            
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
                            for (int i = 0; i < 4; i++) {
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
            printf("[WARNING] WebSocket closed for all channels\n");
            global_ws_client = NULL;
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("[ERROR] WebSocket connection error: %.*s\n", (int)len, (char *)in);
            global_ws_client = NULL;
            break;
            
        default:
            printf("[DEBUG] WebSocket callback reason: %d\n", reason);
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
        0,  // id field
        NULL,  // user field
    },
    { NULL, NULL, 0, 0, 0, NULL }
};

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

void send_websocket_transmit_event(const char* channel_id, int is_started) {
    if (!global_ws_client) {
        printf("[WARNING] WebSocket not connected, cannot send transmit event for channel %s\n", channel_id);
        return;
    }
    
    char transmit_msg[1024];
    time_t now = time(NULL);
    const char* event_type = is_started ? "transmit_started" : "transmit_ended";
    
    snprintf(transmit_msg, sizeof(transmit_msg),
        "{\"%s\":{\"affiliation_id\":\"12345\",\"user_name\":\"EchoStream\",\"agency_name\":\"TestAgency\",\"channel_id\":\"%s\",\"time\":%ld}}",
        event_type, channel_id, now);
    
    printf("[INFO] Sending %s for channel %s\n", event_type, channel_id);
    
    size_t msg_len = strlen(transmit_msg);
    unsigned char *buf = malloc(LWS_PRE + msg_len);
    if (!buf) {
        printf("[ERROR] Failed to allocate memory for WebSocket message\n");
        return;
    }
    
    memcpy(&buf[LWS_PRE], transmit_msg, msg_len);
    int result = lws_write(global_ws_client, &buf[LWS_PRE], msg_len, LWS_WRITE_TEXT);
    
    if (result < 0) {
        printf("[ERROR] Failed to send WebSocket message for channel %s (result=%d)\n", channel_id, result);
    } else {
        printf("[INFO] WebSocket message sent successfully for channel %s (%d bytes)\n", channel_id, result);
    }
    
    free(buf);
}

void send_websocket_passthrough_event(const char* source_channel_id, const char* target_channel_id, int is_active) {
    // DISABLED: Local passthrough doesn't need server notification
    printf("[DEBUG] Passthrough event (local only): %s -> %s (active: %d)\n", 
           source_channel_id, target_channel_id, is_active);
}

int connect_global_websocket() {
    if (global_ws_context && global_ws_client) {
        printf("WebSocket already connected\n");
        return 1;
    }
    
    struct lws_context_creation_info info;
    char ws_url[256] = "wss://audio.redenes.org/ws/";
    
    printf("Connecting to: %s for all channels\n", ws_url);
    
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
        fprintf(stderr, "[ERROR] WebSocket context creation failed\n");
        return 0;
    }
    printf("[INFO] WebSocket context created successfully\n");
    
    // Register all active channels with WebSocket
    printf("[INFO] Registering all active channels with WebSocket\n");
    for (int i = 0; i < 4; i++) {
        if (channels[i].active) {
            printf("[INFO] Registering channel %s\n", channels[i].audio.channel_id);
            send_websocket_transmit_event(channels[i].audio.channel_id, 1);
        }
    }
    
    // Create a single WebSocket connection for all channels
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
    
    printf("[INFO] Attempting WebSocket connection to %s:%d%s\n", address, port, path);
    global_ws_client = lws_client_connect_via_info(&connect_info);
    
    if (global_ws_client == NULL) {
        fprintf(stderr, "[ERROR] WebSocket connection failed\n");
        return 0;
    }
    
    printf("[INFO] WebSocket connection established for all channels\n");
    return 1;
}

void* global_websocket_thread(void* arg) {
    printf("Starting global WebSocket thread\n");
    
    // Reset global_interrupted to ensure it's not corrupted
    global_interrupted = 0;
    
    printf("DEBUG: global_interrupted = %d, global_ws_context = %p\n", global_interrupted, (void*)global_ws_context);
    
    while (!global_interrupted && global_ws_context) {
        lws_service(global_ws_context, 10);
    }
    
    printf("DEBUG: WebSocket thread exiting. Context: %p, Interrupted: %d\n", (void*)global_ws_context, global_interrupted);
    
    // Close the single WebSocket connection
    if (global_ws_client) {
        // Don't call lws_close_reason() - let the context destruction handle it
        global_ws_client = NULL;
    }
    
    // Cleanup all channels
    for (int i = 0; i < 4; i++) {
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
    
    // Send cleanup events for all active channels before destroying context
    printf("[INFO] Sending cleanup events for all active channels\n");
    for (int i = 0; i < 4; i++) {
        if (channels[i].active) {
            printf("[INFO] Sending transmit_ended event for channel %s\n", channels[i].audio.channel_id);
            send_websocket_transmit_event(channels[i].audio.channel_id, 0);
        }
    }
    
    if (global_ws_context) {
        printf("[INFO] Destroying WebSocket context\n");
        lws_context_destroy(global_ws_context);
        global_ws_context = NULL;
    }
    
    printf("[INFO] Global WebSocket thread terminated\n");
    return NULL;
}
