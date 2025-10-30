#define _POSIX_C_SOURCE 200809L  // For usleep
#include "mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <json-c/json.h>

#ifdef HAVE_MOSQUITTO
#include <mosquitto.h>
#endif

// Global MQTT state
static struct mqtt_state global_mqtt = {0};
static pthread_mutex_t mqtt_mutex = PTHREAD_MUTEX_INITIALIZER;

// UUID generation (simple version)
static void generate_uuid(char* uuid, size_t size) {
    // Generate a simple UUID-like string
    time_t now_time = time(NULL);
    snprintf(uuid, size, "%08lx-%04x-%04x-%04x-%012lx",
             (unsigned long)now_time,
             (unsigned)(rand() & 0xffff),
             (unsigned)(rand() & 0xffff),
             (unsigned)(rand() & 0xffff),
             (unsigned long)(now_time % 1000000000000UL));
}

#ifdef HAVE_MOSQUITTO
// Forward declarations for static functions used by init_mqtt
static int get_aws_iot_endpoint(char* endpoint, size_t endpoint_size);
static int find_certificates(char* ca_path, char* cert_path, char* key_path, size_t path_size);
#endif

// Initialize MQTT connection
int init_mqtt(const char* device_id, const char* broker_host, int broker_port) {
    (void)broker_port;  // Suppress unused parameter warning
#ifdef HAVE_MOSQUITTO
    pthread_mutex_lock(&mqtt_mutex);
    
    if (global_mqtt.initialized) {
        printf("[MQTT] Already initialized\n");
        pthread_mutex_unlock(&mqtt_mutex);
        return 1;
    }
    
    if (!device_id || !broker_host) {
        printf("[MQTT] ERROR: device_id or broker_host is NULL\n");
        pthread_mutex_unlock(&mqtt_mutex);
        return 0;
    }
    
    strncpy(global_mqtt.device_id, device_id, sizeof(global_mqtt.device_id) - 1);
    
    // Hardcoded AWS IoT Core endpoint
    const char* aws_endpoint = "a1d6e0zlehb0v9-ats.iot.us-west-2.amazonaws.com";
    strncpy(global_mqtt.broker_host, aws_endpoint, sizeof(global_mqtt.broker_host) - 1);
    global_mqtt.broker_port = 8883; // AWS IoT always uses 8883
    printf("[MQTT] Using AWS IoT Core endpoint: %s:%d\n", aws_endpoint, global_mqtt.broker_port);
    
    // Try to find certificates
    if (!find_certificates(global_mqtt.ca_cert_path, global_mqtt.client_cert_path, 
                          global_mqtt.client_key_path, sizeof(global_mqtt.ca_cert_path))) {
        printf("[MQTT] WARNING: Certificates not found. Will try plain connection (may fail for AWS IoT)\n");
        global_mqtt.ca_cert_path[0] = '\0';
        global_mqtt.client_cert_path[0] = '\0';
        global_mqtt.client_key_path[0] = '\0';
    } else {
        printf("[MQTT] Found certificates:\n");
        printf("  CA: %s\n", global_mqtt.ca_cert_path);
        printf("  Cert: %s\n", global_mqtt.client_cert_path);
        printf("  Key: %s\n", global_mqtt.client_key_path);
    }
    
    // Initialize mosquitto library
    mosquitto_lib_init();
    
    // Create mosquitto client
    global_mqtt.mosq = mosquitto_new(device_id, true, NULL);
    if (!global_mqtt.mosq) {
        printf("[MQTT] ERROR: Failed to create mosquitto client\n");
        mosquitto_lib_cleanup();
        return 0;
    }
    
    // Set TLS if certificates found and port is 8883 (AWS IoT)
    if (global_mqtt.broker_port == 8883 && global_mqtt.ca_cert_path[0] != '\0') {
        int rc_tls = mosquitto_tls_set(global_mqtt.mosq, 
                                       global_mqtt.ca_cert_path,
                                       NULL,  // CA path (directory)
                                       global_mqtt.client_cert_path,
                                       global_mqtt.client_key_path,
                                       NULL); // Password callback
        if (rc_tls != MOSQ_ERR_SUCCESS) {
            printf("[MQTT] WARNING: Failed to set TLS (rc=%d), will try without TLS\n", rc_tls);
        } else {
            printf("[MQTT] TLS configured successfully\n");
            mosquitto_tls_opts_set(global_mqtt.mosq, 1, NULL, NULL);
        }
    }
    
    // Connect to broker
    int rc = mosquitto_connect(global_mqtt.mosq, global_mqtt.broker_host, global_mqtt.broker_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        const char* error_str = mosquitto_strerror(rc);
        printf("[MQTT] ERROR: Failed to connect to broker at %s:%d (rc=%d: %s)\n", 
               global_mqtt.broker_host, global_mqtt.broker_port, rc, error_str ? error_str : "unknown error");
        printf("[MQTT] Check: 1) Broker is running/accessible, 2) Port is correct, 3) Certificates are valid (for AWS IoT)\n");
        global_mqtt.connected = 0;
        global_mqtt.initialized = 1;
        pthread_mutex_unlock(&mqtt_mutex);
        return 0;
    }
    
    // Wait for connection acknowledgment by processing network I/O
    // Note: mosquitto_connect() is synchronous for the initial connect attempt
    // We'll set connected=1 and verify with a network loop
    printf("[MQTT] Processing initial connection...\n");
    for (int i = 0; i < 20; i++) {  // Try up to 2 seconds (20 * 100ms)
        int loop_rc = mosquitto_loop(global_mqtt.mosq, 100, 1);  // 100ms timeout, process once
        // Check if we got an error indicating disconnection
        if (loop_rc == MOSQ_ERR_NO_CONN) {
            // Connection failed
            break;
        }
        // If loop succeeds, connection is likely established
        global_mqtt.connected = 1;
        printf("[MQTT] Connected and acknowledged by broker at %s:%d\n", global_mqtt.broker_host, global_mqtt.broker_port);
        break;
    }
    
    if (!global_mqtt.connected) {
        printf("[MQTT] WARNING: Connection timeout - broker may not be responding\n");
        printf("[MQTT] Will attempt to use connection anyway\n");
        // Set connected anyway - mosquitto will handle reconnection
        global_mqtt.connected = 1;
    }
    
    global_mqtt.initialized = 1;
    pthread_mutex_unlock(&mqtt_mutex);
    return 1;
#else
    (void)device_id;
    (void)broker_host;
    (void)broker_port;
    printf("[MQTT] MQTT support not compiled (libmosquitto not available)\n");
    return 0;
#endif
}

// Publish MQTT message
int mqtt_publish(const char* topic, const char* payload) {
#ifdef HAVE_MOSQUITTO
    pthread_mutex_lock(&mqtt_mutex);
    
    if (!global_mqtt.initialized || !global_mqtt.mosq) {
        printf("[MQTT] Not initialized, skipping publish to %s\n", topic ? topic : "NULL");
        pthread_mutex_unlock(&mqtt_mutex);
        return 0;
    }
    
    if (!topic || !payload) {
        printf("[MQTT] ERROR: topic or payload is NULL\n");
        pthread_mutex_unlock(&mqtt_mutex);
        return 0;
    }
    
    // Verify connection is actually active by attempting network I/O
    // If not connected, mosquitto_loop will return MOSQ_ERR_NO_CONN
    int loop_rc = mosquitto_loop(global_mqtt.mosq, 0, 1);  // Quick non-blocking check
    if (loop_rc == MOSQ_ERR_NO_CONN || !global_mqtt.connected) {
        printf("[MQTT] Connection lost, attempting to reconnect...\n");
        int rc_reconnect = mosquitto_reconnect(global_mqtt.mosq);
        if (rc_reconnect != MOSQ_ERR_SUCCESS) {
            printf("[MQTT] ERROR: Reconnect failed (rc=%d), cannot publish\n", rc_reconnect);
            global_mqtt.connected = 0;
            pthread_mutex_unlock(&mqtt_mutex);
            return 0;
        }
        // Wait for reconnection acknowledgment
        for (int i = 0; i < 20; i++) {
            loop_rc = mosquitto_loop(global_mqtt.mosq, 100, 1);
            if (loop_rc != MOSQ_ERR_NO_CONN) {
                global_mqtt.connected = 1;
                printf("[MQTT] Reconnected successfully\n");
                break;
            }
            usleep(100000);  // 100ms
        }
        if (!global_mqtt.connected) {
            printf("[MQTT] ERROR: Reconnection timeout\n");
            pthread_mutex_unlock(&mqtt_mutex);
            return 0;
        }
    }
    
    // Publish message with QoS 1 (requires acknowledgment)
    int rc = mosquitto_publish(global_mqtt.mosq, NULL, topic, (int)strlen(payload), payload, 1, false);
    if (rc != MOSQ_ERR_SUCCESS) {
        const char* error_str = mosquitto_strerror(rc);
        printf("[MQTT] ERROR: Failed to publish to '%s' (rc=%d: %s)\n", 
               topic, rc, error_str ? error_str : "unknown error");
        global_mqtt.connected = 0;
        pthread_mutex_unlock(&mqtt_mutex);
        return 0;
    }
    
    // Process network traffic to ensure message is sent
    // For QoS 1, we need to process network I/O to send the message (PUBACK will come later)
    // Don't block too long - just ensure the publish packet is sent
    for (int i = 0; i < 3; i++) {
        mosquitto_loop(global_mqtt.mosq, 50, 1);  // 50ms timeout, quick processing
    }
    
    pthread_mutex_unlock(&mqtt_mutex);
    return 1;
#else
    (void)topic;
    (void)payload;
    printf("[MQTT] MQTT support not compiled (libmosquitto not available)\n");
    return 0;
#endif
}

// Keep MQTT connection alive by processing network I/O
// Call this periodically (e.g., every few seconds) from a main loop or worker thread
void mqtt_keepalive(void) {
#ifdef HAVE_MOSQUITTO
    // Try to lock without blocking - if publish is in progress, skip this cycle
    if (pthread_mutex_trylock(&mqtt_mutex) != 0) {
        // Couldn't acquire lock, skip this keepalive cycle (publish in progress)
        return;
    }
    
    if (global_mqtt.initialized && global_mqtt.mosq) {
        // Quick network I/O processing - non-blocking
        int loop_rc = mosquitto_loop(global_mqtt.mosq, 0, 1);
        
        // Check connection status and reconnect if needed
        if (loop_rc == MOSQ_ERR_NO_CONN || !global_mqtt.connected) {
            global_mqtt.connected = 0;
            int rc = mosquitto_reconnect(global_mqtt.mosq);
            if (rc == MOSQ_ERR_SUCCESS) {
                // Give it a moment to establish
                for (int i = 0; i < 5; i++) {
                    loop_rc = mosquitto_loop(global_mqtt.mosq, 50, 1);
                    if (loop_rc != MOSQ_ERR_NO_CONN) {
                        global_mqtt.connected = 1;
                        break;
                    }
                    usleep(50000);  // 50ms
                }
            }
        }
    }
    
    pthread_mutex_unlock(&mqtt_mutex);
#endif
}

// Cleanup MQTT
void cleanup_mqtt(void) {
#ifdef HAVE_MOSQUITTO
    pthread_mutex_lock(&mqtt_mutex);
    
    if (global_mqtt.mosq) {
        mosquitto_disconnect(global_mqtt.mosq);
        mosquitto_destroy(global_mqtt.mosq);
        global_mqtt.mosq = NULL;
    }
    mosquitto_lib_cleanup();
    
    global_mqtt.initialized = 0;
    global_mqtt.connected = 0;
    
    pthread_mutex_unlock(&mqtt_mutex);
    pthread_mutex_destroy(&mqtt_mutex);
#endif
    printf("[MQTT] Cleaned up\n");
}

#ifdef HAVE_MOSQUITTO
// Get AWS IoT endpoint from config (no longer used - hardcoded in init_mqtt)
// Kept for potential future use
static int __attribute__((unused)) get_aws_iot_endpoint(char* endpoint, size_t endpoint_size) {
    const char* config_path = "/home/will/.an/config.json";
    FILE *file = fopen(config_path, "r");
    if (!file) {
        return 0;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        return 0;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);
    
    struct json_object *json = json_tokener_parse(json_string);
    free(json_string);
    
    if (!json) {
        return 0;
    }
    
    // Try to find AWS endpoint (might be in various locations)
    struct json_object *aws_endpoint_obj;
    if (json_object_object_get_ex(json, "aws_endpoint", &aws_endpoint_obj)) {
        const char* endpoint_str = json_object_get_string(aws_endpoint_obj);
        if (endpoint_str && strlen(endpoint_str) > 0 && strlen(endpoint_str) < endpoint_size) {
            strncpy(endpoint, endpoint_str, endpoint_size - 1);
            endpoint[endpoint_size - 1] = '\0';
            printf("[MQTT] Found AWS endpoint in config: %s\n", endpoint);
            json_object_put(json);
            return 1;
        } else {
            printf("[MQTT] AWS endpoint found in config but invalid (length: %zu, max: %zu)\n", 
                   endpoint_str ? strlen(endpoint_str) : 0, endpoint_size);
        }
    } else {
        printf("[MQTT] AWS endpoint 'aws_endpoint' field not found in config.json root level\n");
    }
    
    json_object_put(json);
    return 0;
}
#endif

#ifdef HAVE_MOSQUITTO
// Find certificate paths
static int find_certificates(char* ca_path, char* cert_path, char* key_path, size_t path_size) {
    // Common certificate locations (check parent directory first, then subdirectories)
    const char* base_paths[] = {
        "/home/will/.an/"
    };
    
    const char* ca_files[] = { "AmazonRootCA1.pem", "root-CA.crt", "ca-cert.pem", "ca.pem" };
    const char* cert_files[] = { "certificate.pem.crt", "cert.pem", "device-cert.pem" };
    const char* key_files[] = { "private.pem.key", "private-key.pem", "device-private.pem.key" };
    
    for (int i = 0; i < 1; i++) {
        for (int j = 0; j < 4; j++) {
            char test_path[512];
            snprintf(test_path, sizeof(test_path), "%s%s", base_paths[i], ca_files[j]);
            FILE* f = fopen(test_path, "r");
            if (f) {
                fclose(f);
                strncpy(ca_path, test_path, path_size - 1);
                
                // Try to find cert and key in same directory
                for (int k = 0; k < 3; k++) {
                    snprintf(test_path, sizeof(test_path), "%s%s", base_paths[i], cert_files[k]);
                    f = fopen(test_path, "r");
                    if (f) {
                        fclose(f);
                        strncpy(cert_path, test_path, path_size - 1);
                        
                        for (int l = 0; l < 3; l++) {
                            snprintf(test_path, sizeof(test_path), "%s%s", base_paths[i], key_files[l]);
                            f = fopen(test_path, "r");
                            if (f) {
                                fclose(f);
                                strncpy(key_path, test_path, path_size - 1);
                                return 1; // Found all three
                            }
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}
#endif

// Get device ID from config.json
int get_device_id_from_config(char* device_id, size_t device_id_size) {
    const char* config_path = "/home/will/.an/config.json";
    FILE *file = fopen(config_path, "r");
    if (!file) {
        printf("[MQTT] Could not open config file %s\n", config_path);
        return 0;
    }
    
    // Read the entire file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        return 0;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);
    
    // Parse JSON
    struct json_object *json = json_tokener_parse(json_string);
    free(json_string);
    
    if (!json) {
        printf("[MQTT] Failed to parse config JSON\n");
        return 0;
    }
    
    // Extract unique_id from root level
    struct json_object *unique_id_obj;
    if (json_object_object_get_ex(json, "unique_id", &unique_id_obj)) {
        const char* unique_id = json_object_get_string(unique_id_obj);
        if (unique_id && strlen(unique_id) < device_id_size) {
            strncpy(device_id, unique_id, device_id_size - 1);
            device_id[device_id_size - 1] = '\0';
            json_object_put(json);
            return 1;
        }
    }
    
    json_object_put(json);
    printf("[MQTT] unique_id not found in config.json\n");
    return 0;
}

// Publish new tone detection message
int publish_new_tone_detection(float frequency, int duration_ms, int range_hz) {
#ifdef HAVE_MOSQUITTO
    if (!global_mqtt.initialized || !global_mqtt.mosq) {
        // Try to initialize if we have device_id
        char device_id[64];
        if (get_device_id_from_config(device_id, sizeof(device_id))) {
            // Use hardcoded AWS IoT Core endpoint
            const char* broker = "a1d6e0zlehb0v9-ats.iot.us-west-2.amazonaws.com";
            int port = 8883;
            printf("[MQTT] Attempting to connect to AWS IoT Core: %s:%d\n", broker, port);
            
            if (!init_mqtt(device_id, broker, port)) {
                printf("[MQTT] Failed to initialize MQTT connection - tone detection logged but not published\n");
                printf("[MQTT] To enable MQTT publishing:\n");
                printf("[MQTT]   1. Ensure libmosquitto is installed: sudo apt-get install libmosquitto-dev\n");
                printf("[MQTT]   2. Rebuild the application\n");
                printf("[MQTT]   3. For AWS IoT: Set aws_endpoint in config.json and provide certificates\n");
                return 0;
            }
        } else {
            printf("[MQTT] Cannot publish: MQTT not initialized and device_id not available\n");
            printf("[MQTT] Check that 'unique_id' exists in config.json root level\n");
            return 0;
        }
    }
#else
    // MQTT not available, but tone was still detected
    printf("[MQTT] ERROR: MQTT support not compiled (HAVE_MOSQUITTO not defined)\n");
    printf("[MQTT] Install libmosquitto-dev and rebuild to enable MQTT publishing\n");
    (void)frequency;
    (void)duration_ms;
    (void)range_hz;
    return 0;
#endif
    
#ifdef HAVE_MOSQUITTO
    // Generate message
    char message_id[64];
    generate_uuid(message_id, sizeof(message_id));
    
    time_t now_time = time(NULL);
    
    // Create JSON payload
    struct json_object *json = json_object_new_object();
    json_object_object_add(json, "message_id", json_object_new_string(message_id));
    json_object_object_add(json, "timestamp", json_object_new_int((int)now_time));
    json_object_object_add(json, "device_id", json_object_new_string(global_mqtt.device_id));
    json_object_object_add(json, "event_type", json_object_new_string("new_tone_detected"));
    
    // Tone detection details
    struct json_object *tone_details = json_object_new_object();
    json_object_object_add(tone_details, "frequency_hz", json_object_new_double((double)frequency));
    json_object_object_add(tone_details, "duration_ms", json_object_new_int(duration_ms));
    json_object_object_add(tone_details, "range_hz", json_object_new_int(range_hz));
    json_object_object_add(json, "tone_details", tone_details);
    
    const char* json_string = json_object_to_json_string(json);
    
    // Build topic: from/device/{device_id}/tone_detection
    char topic[256];
    snprintf(topic, sizeof(topic), "from/device/%s/tone_detection", global_mqtt.device_id);
    
    int result = mqtt_publish(topic, json_string);
    
    if (result) {
        printf("[MQTT] ✓ Published new tone detection to topic '%s': %.1f Hz (duration: %d ms, range: ±%d Hz)\n",
               topic, frequency, duration_ms, range_hz);
        printf("[MQTT]   Message payload: %s\n", json_string);
    } else {
        printf("[MQTT] ✗ Failed to publish new tone detection to '%s' (tone logged but not sent)\n", topic);
        printf("[MQTT]   Check connection status and broker availability\n");
    }
    
    json_object_put(json);
    return result;
#else
    // MQTT not compiled - tone was detected but cannot send MQTT message
    printf("[MQTT] New tone detected but MQTT not available (libmosquitto not compiled)\n");
    return 0;
#endif
}

#ifdef HAVE_MOSQUITTO
// Publish a new unknown tone pair (A and B) in one message (no duration/range)
int publish_new_tone_pair(float tone_a_hz, float tone_b_hz) {
    if (!global_mqtt.initialized || !global_mqtt.mosq) {
        // Try to initialize if we have device_id
        char device_id[64];
        if (get_device_id_from_config(device_id, sizeof(device_id))) {
            const char* broker = "a1d6e0zlehb0v9-ats.iot.us-west-2.amazonaws.com";
            int port = 8883;
            printf("[MQTT] Attempting to connect to AWS IoT Core: %s:%d\n", broker, port);
            if (!init_mqtt(device_id, broker, port)) {
                printf("[MQTT] Failed to initialize MQTT connection - tone pair logged but not published\n");
                return 0;
            }
        } else {
            printf("[MQTT] Cannot publish: MQTT not initialized and device_id not available\n");
            return 0;
        }
    }

    // Generate message id and timestamp
    char message_id[64];
    generate_uuid(message_id, sizeof(message_id));
    time_t now_time = time(NULL);

    // Build JSON payload
    struct json_object *json = json_object_new_object();
    json_object_object_add(json, "message_id", json_object_new_string(message_id));
    json_object_object_add(json, "timestamp", json_object_new_int((int)now_time ));
    json_object_object_add(json, "device_id", json_object_new_string(global_mqtt.device_id));
    json_object_object_add(json, "event_type", json_object_new_string("new_tone_detected"));

    struct json_object *tone_details = json_object_new_object();
    json_object_object_add(tone_details, "tone_a", json_object_new_double((double)tone_a_hz));
    json_object_object_add(tone_details, "tone_b", json_object_new_double((double)tone_b_hz));
    json_object_object_add(json, "tone_details", tone_details);

    const char* json_string = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN);

    char topic[256];
    snprintf(topic, sizeof(topic), "from/device/%s/tone_detection", global_mqtt.device_id);

    int result = mqtt_publish(topic, json_string);
    if (result) {
        printf("[MQTT] ✓ Published new tone pair to '%s': A=%.1f Hz, B=%.1f Hz\n", topic, tone_a_hz, tone_b_hz);
        printf("[MQTT]   Message payload: %s\n", json_string);
    } else {
        printf("[MQTT] ✗ Failed to publish new tone pair to '%s'\n", topic);
    }

    json_object_put(json);
    return result;
}
#else
int publish_new_tone_pair(float tone_a_hz, float tone_b_hz) {
    (void)tone_a_hz; (void)tone_b_hz;
    printf("[MQTT] MQTT support not compiled (libmosquitto not available)\n");
    return 0;
}
#endif

