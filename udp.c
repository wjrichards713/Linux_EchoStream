#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "udp.h"
#include "audio.h"
#include "crypto.h"
#include "websocket.h"
#include <math.h>
#include <unistd.h>
#include <arpa/inet.h>

// Global UDP state
int global_udp_socket = -1;
struct sockaddr_in global_server_addr;
pthread_t heartbeat_thread;
pthread_t udp_listener_thread;

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

void* heartbeat_worker(void* arg) {
    (void)arg; // Suppress unused parameter warning
    printf("Heartbeat worker started\n");
    
    while (!global_interrupted) {
        if (global_udp_socket >= 0) {
            const char* heartbeat_msg = "{\"type\":\"KEEP_ALIVE\"}";
            int result = sendto(global_udp_socket, heartbeat_msg, strlen(heartbeat_msg), 0,
                               (struct sockaddr*)&global_server_addr, sizeof(global_server_addr));
            
            static int heartbeat_count = 0;
            if (result >= 0) {
                heartbeat_count++;
                // Only log every 60th heartbeat (about every 10 minutes)
                if (heartbeat_count % 60 == 0) {
                    printf("Heartbeat sent to keep NAT mapping active (count: %d)\n", heartbeat_count);
                }
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

void* udp_listener_worker(void* arg) {
    (void)arg; // Suppress unused parameter warning
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
        
        static int udp_debug_count = 0;
        if (udp_debug_count++ % 100000 == 0) {  // Much less frequent - about every 10 minutes
            printf("UDP Listener: Still listening... (attempt %d)\n", udp_debug_count);
        }
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            static int receive_count = 0;
            receive_count++;
            // Only log every 1000th UDP message received
            if (receive_count % 1000 == 0) {
                printf("UDP Listener: Received %d bytes from %s:%d (count: %d)\n", 
                       bytes_received, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), receive_count);
            }
            
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
                    for (int i = 0; i < 4; i++) {
                        if (channels[i].active && strcmp(channels[i].audio.channel_id, channel_id) == 0) {
                            target_stream = &channels[i].audio;
                            // printf("UDP Listener: Found target channel %s at index %d\n", channel_id, i);
                            break;
                        }
                    }
                    
                    if (!target_stream) {
                        printf("UDP Listener: No active channel found for '%s'\n", channel_id);
                        printf("UDP Listener: Active channels: ");
                        for (int i = 0; i < 4; i++) {
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
                            for (int k = 0; k < 16 && k < (int)encrypted_len; k++) {
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
                                        float max_sample = 0.0f;
                                        for (int j = 0; j < samples && j < SAMPLES_PER_FRAME; j++) {
                                            float sample = (float)pcm_data[j] / 32767.0f;
                                            // Apply 10x gain boost for very quiet audio
                                            sample *= 10.0f;
                                            // Clamp to prevent distortion
                                            if (sample > 1.0f) sample = 1.0f;
                                            if (sample < -1.0f) sample = -1.0f;
                                            frame->samples[j] = sample;
                                            
                                            // Track max sample for debugging
                                            float abs_sample = fabsf(sample);
                                            if (abs_sample > max_sample) max_sample = abs_sample;
                                        }
                                        frame->sample_count = samples;
                                        frame->valid = 1;
                                        
                                        printf("UDP: Audio frame queued for %s - %d samples, max level: %.4f\n", 
                                               channel_id, samples, max_sample);
                                        
                                        jitter->write_index = (jitter->write_index + 1) % JITTER_BUFFER_SIZE;
                                        jitter->frame_count++;
                                        
                                        printf("UDP: Audio queued for %s (buffer=%d)\n", 
                                               channel_id, jitter->frame_count);
                                    } else {
                                        // Buffer full, drop oldest frame and add new one
                                        jitter->read_index = (jitter->read_index + 1) % JITTER_BUFFER_SIZE;
                                        jitter->frame_count--;
                                        
                                        struct audio_frame *frame = &jitter->frames[jitter->write_index];
                                        float max_sample = 0.0f;
                                        for (int j = 0; j < samples && j < SAMPLES_PER_FRAME; j++) {
                                            float sample = (float)pcm_data[j] / 32767.0f;
                                            // Apply 10x gain boost for very quiet audio
                                            sample *= 10.0f;
                                            // Clamp to prevent distortion
                                            if (sample > 1.0f) sample = 1.0f;
                                            if (sample < -1.0f) sample = -1.0f;
                                            frame->samples[j] = sample;
                                            
                                            // Track max sample for debugging
                                            float abs_sample = fabsf(sample);
                                            if (abs_sample > max_sample) max_sample = abs_sample;
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
