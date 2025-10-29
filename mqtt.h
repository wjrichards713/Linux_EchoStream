#ifndef MQTT_H
#define MQTT_H

#include <stdint.h>
#include <stddef.h>

// MQTT connection state
struct mqtt_state {
    void* mosq;  // mosquitto client handle
    char device_id[64];
    char broker_host[256];
    int broker_port;
    int connected;
    int initialized;
    // AWS IoT Core certificate paths
    char ca_cert_path[512];
    char client_cert_path[512];
    char client_key_path[512];
};

// Initialize MQTT connection
int init_mqtt(const char* device_id, const char* broker_host, int broker_port);

// Publish MQTT message
int mqtt_publish(const char* topic, const char* payload);

// Cleanup MQTT
void cleanup_mqtt(void);

// Get device ID from config
int get_device_id_from_config(char* device_id, size_t device_id_size);

// Publish new tone detection message
int publish_new_tone_detection(float frequency, int duration_ms, int range_hz);

#endif // MQTT_H

