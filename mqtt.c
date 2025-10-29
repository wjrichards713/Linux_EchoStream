#include "mqtt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <json-c/json.h>

#ifdef HAVE_MOSQUITTO
#include <mosquitto.h>
#endif

// Global MQTT state
static struct mqtt_state global_mqtt = {0};

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
#ifdef HAVE_MOSQUITTO
    if (global_mqtt.initialized) {
        printf("[MQTT] Already initialized\n");
        return 1;
    }
    
    if (!device_id || !broker_host) {
        printf("[MQTT] ERROR: device_id or broker_host is NULL\n");
        return 0;
    }
    
    strncpy(global_mqtt.device_id, device_id, sizeof(global_mqtt.device_id) - 1);
    
    // Try to get AWS IoT endpoint from config, fallback to provided broker_host
    char aws_endpoint[256];
    if (get_aws_iot_endpoint(aws_endpoint, sizeof(aws_endpoint))) {
        strncpy(global_mqtt.broker_host, aws_endpoint, sizeof(global_mqtt.broker_host) - 1);
        global_mqtt.broker_port = 8883; // AWS IoT always uses 8883
        printf("[MQTT] Using AWS IoT endpoint from config: %s:%d\n", aws_endpoint, global_mqtt.broker_port);
    } else {
        strncpy(global_mqtt.broker_host, broker_host, sizeof(global_mqtt.broker_host) - 1);
        global_mqtt.broker_port = broker_port;
        printf("[MQTT] Using provided broker: %s:%d\n", broker_host, broker_port);
    }
    
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
    } else {
        printf("[MQTT] Connected to broker at %s:%d\n", global_mqtt.broker_host, global_mqtt.broker_port);
        global_mqtt.connected = 1;
    }
    
    global_mqtt.initialized = 1;
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
    printf("[MQTT DEBUG] mqtt_publish called: topic=%s, initialized=%d, mosq=%p, connected=%d\n",
           topic ? topic : "NULL", global_mqtt.initialized, global_mqtt.mosq, global_mqtt.connected);
    
    if (!global_mqtt.initialized || !global_mqtt.mosq) {
        printf("[MQTT] Not initialized, skipping publish to %s\n", topic ? topic : "NULL");
        return 0;
    }
    
    if (!topic || !payload) {
        printf("[MQTT] ERROR: topic or payload is NULL\n");
        return 0;
    }
    
    // Try to reconnect if not connected
    if (!global_mqtt.connected) {
        printf("[MQTT DEBUG] Not connected, attempting reconnect...\n");
        int rc = mosquitto_reconnect(global_mqtt.mosq);
        if (rc == MOSQ_ERR_SUCCESS) {
            global_mqtt.connected = 1;
            printf("[MQTT] Reconnected to broker\n");
        } else {
            printf("[MQTT] WARNING: Failed to reconnect (rc=%d), attempting to publish anyway\n", rc);
        }
    }
    
    // Publish message
    int rc = mosquitto_publish(global_mqtt.mosq, NULL, topic, strlen(payload), payload, 1, false);
    if (rc != MOSQ_ERR_SUCCESS) {
        const char* error_str = mosquitto_strerror(rc);
        printf("[MQTT] ERROR: Failed to publish to '%s' (rc=%d: %s)\n", 
               topic, rc, error_str ? error_str : "unknown error");
        // Try to reconnect for next time
        global_mqtt.connected = 0;
        
        // Process network to see if there are any pending errors
        mosquitto_loop(global_mqtt.mosq, 0, 1);
        return 0;
    }
    
    // Process network traffic (required for mosquitto to actually send)
    mosquitto_loop(global_mqtt.mosq, 0, 1);
    
    return 1;
#else
    (void)topic;
    (void)payload;
    printf("[MQTT] MQTT support not compiled (libmosquitto not available)\n");
    return 0;
#endif
}

// Cleanup MQTT
void cleanup_mqtt(void) {
#ifdef HAVE_MOSQUITTO
    if (global_mqtt.mosq) {
        mosquitto_disconnect(global_mqtt.mosq);
        mosquitto_destroy(global_mqtt.mosq);
        global_mqtt.mosq = NULL;
    }
    mosquitto_lib_cleanup();
#endif
    global_mqtt.initialized = 0;
    global_mqtt.connected = 0;
    printf("[MQTT] Cleaned up\n");
}

#ifdef HAVE_MOSQUITTO
// Get AWS IoT endpoint from config
static int get_aws_iot_endpoint(char* endpoint, size_t endpoint_size) {
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
        if (endpoint_str && strlen(endpoint_str) < endpoint_size) {
            strncpy(endpoint, endpoint_str, endpoint_size - 1);
            endpoint[endpoint_size - 1] = '\0';
            json_object_put(json);
            return 1;
        }
    }
    
    json_object_put(json);
    return 0;
}
#endif

#ifdef HAVE_MOSQUITTO
// Find certificate paths
static int find_certificates(char* ca_path, char* cert_path, char* key_path, size_t path_size) {
    // Common certificate locations
    const char* base_paths[] = {
        "/home/will/.an/cert/",
        "/home/will/.an/certs/",
        "/home/will/.aws-iot/",
        "./cert/",
        "./certs/",
    };
    
    const char* ca_files[] = { "AmazonRootCA1.pem", "root-CA.crt", "ca-cert.pem", "ca.pem" };
    const char* cert_files[] = { "certificate.pem.crt", "cert.pem", "device-cert.pem" };
    const char* key_files[] = { "private.pem.key", "private-key.pem", "device-private.pem.key" };
    
    for (int i = 0; i < 5; i++) {
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
    printf("[MQTT DEBUG] publish_new_tone_detection called: freq=%.1f Hz, duration=%d ms, range=%d Hz\n",
           frequency, duration_ms, range_hz);
#ifdef HAVE_MOSQUITTO
    printf("[MQTT DEBUG] HAVE_MOSQUITTO is defined\n");
    if (!global_mqtt.initialized || !global_mqtt.mosq) {
        printf("[MQTT DEBUG] MQTT not initialized yet, attempting initialization...\n");
        // Try to initialize if we have device_id
        char device_id[64];
        if (get_device_id_from_config(device_id, sizeof(device_id))) {
            // Try AWS IoT first, then fallback to localhost
            // init_mqtt will try to get AWS endpoint from config
            char broker[256] = "localhost";
            int port = 1883;
            
            // Check if we can get AWS endpoint from config
            char aws_endpoint[256];
            if (get_aws_iot_endpoint(aws_endpoint, sizeof(aws_endpoint))) {
                strncpy(broker, aws_endpoint, sizeof(broker) - 1);
                port = 8883;
                printf("[MQTT] Attempting to connect to AWS IoT Core: %s:%d\n", broker, port);
            } else {
                printf("[MQTT] AWS IoT endpoint not found in config, trying localhost:1883\n");
                printf("[MQTT] For AWS IoT, add 'aws_endpoint' to config.json\n");
            }
            
            if (!init_mqtt(device_id, broker, port)) {
                printf("[MQTT] Failed to initialize MQTT connection - tone detection logged but not published\n");
                printf("[MQTT] To enable MQTT publishing:\n");
                printf("[MQTT]   1. Ensure libmosquitto is installed: sudo apt-get install libmosquitto-dev\n");
                printf("[MQTT]   2. Rebuild the application\n");
                printf("[MQTT]   3. For AWS IoT: Set aws_endpoint in config.json and provide certificates\n");
                return 0;
            } else {
                printf("[MQTT DEBUG] MQTT initialization succeeded\n");
            }
        } else {
            printf("[MQTT] Cannot publish: MQTT not initialized and device_id not available\n");
            printf("[MQTT] Check that 'unique_id' exists in config.json root level\n");
            return 0;
        }
    } else {
        printf("[MQTT DEBUG] MQTT already initialized (device_id=%s, connected=%d)\n", 
               global_mqtt.device_id, global_mqtt.connected);
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
    
    printf("[MQTT DEBUG] Attempting to publish to topic: %s\n", topic);
    printf("[MQTT DEBUG] Payload length: %zu bytes\n", strlen(json_string));
    int result = mqtt_publish(topic, json_string);
    
    if (result) {
        printf("[MQTT] ✓ Published new tone detection to topic '%s': %.1f Hz (duration: %d ms, range: ±%d Hz)\n",
               topic, frequency, duration_ms, range_hz);
        printf("[MQTT]   Message payload: %s\n", json_string);
    } else {
        printf("[MQTT] ✗ Failed to publish new tone detection to '%s' (tone logged but not sent)\n", topic);
        printf("[MQTT]   Check connection status and broker availability\n");
        printf("[MQTT DEBUG] mqtt_publish returned 0 - connection may be down\n");
    }
    
    json_object_put(json);
    return result;
#else
    // MQTT not compiled - tone was detected but cannot send MQTT message
    printf("[MQTT] New tone detected but MQTT not available (libmosquitto not compiled)\n");
    return 0;
#endif
}

