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
    strncpy(global_mqtt.broker_host, broker_host, sizeof(global_mqtt.broker_host) - 1);
    global_mqtt.broker_port = broker_port;
    
    // Initialize mosquitto library
    mosquitto_lib_init();
    
    // Create mosquitto client
    global_mqtt.mosq = mosquitto_new(device_id, true, NULL);
    if (!global_mqtt.mosq) {
        printf("[MQTT] ERROR: Failed to create mosquitto client\n");
        mosquitto_lib_cleanup();
        return 0;
    }
    
    // Connect to broker
    int rc = mosquitto_connect(global_mqtt.mosq, broker_host, broker_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("[MQTT] WARNING: Failed to connect to broker at %s:%d (rc=%d). Will retry on first publish.\n", 
               broker_host, broker_port, rc);
        global_mqtt.connected = 0;
    } else {
        printf("[MQTT] Connected to broker at %s:%d\n", broker_host, broker_port);
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
        printf("[MQTT] ERROR: Failed to publish to %s (rc=%d)\n", topic, rc);
        // Try to reconnect for next time
        global_mqtt.connected = 0;
        return 0;
    }
    
    // Process network traffic (required for mosquitto)
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
    if (!global_mqtt.initialized || !global_mqtt.mosq) {
        // Try to initialize if we have device_id
        char device_id[64];
        if (get_device_id_from_config(device_id, sizeof(device_id))) {
            // Try to connect to local MQTT broker (default port 1883)
            // For AWS IoT, this would need certificate-based connection, 
            // but for now we'll try local broker
            if (!init_mqtt(device_id, "localhost", 1883)) {
                printf("[MQTT] Failed to initialize MQTT connection\n");
                return 0;
            }
        } else {
            printf("[MQTT] Cannot publish: MQTT not initialized and device_id not available\n");
            return 0;
        }
    }
    
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
        printf("[MQTT] Published new tone detection: %.1f Hz (duration: %d ms, range: ±%d Hz)\n",
               frequency, duration_ms, range_hz);
    }
    
    json_object_put(json);
    return result;
}

