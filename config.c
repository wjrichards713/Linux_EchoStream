#include "config.h"
#include <errno.h>

// Global configuration instance
struct global_config global_app_config = {0};

int load_channel_config(char channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN]) {
    const char* config_path = "/home/will/.an/config.json";
    FILE *file = fopen(config_path, "r");
    if (!file) {
        printf("Warning: Could not open config file %s, using default channel IDs\n", config_path);
        return 0;
    }
    
    // Read the entire file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        printf("Error: Memory allocation failed for config file\n");
        return 0;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);
    
    // Parse JSON
    struct json_object *json = json_tokener_parse(json_string);
    free(json_string);
    
    if (!json) {
        printf("Error: Failed to parse config JSON\n");
        return 0;
    }
    
    // Navigate to the channel configuration
    struct json_object *shadow, *state, *desired, *software_config, *config_item;
    if (!json_object_object_get_ex(json, "shadow", &shadow) ||
        !json_object_object_get_ex(shadow, "state", &state) ||
        !json_object_object_get_ex(state, "desired", &desired) ||
        !json_object_object_get_ex(desired, "software_configuration", &software_config) ||
        json_object_array_length(software_config) == 0) {
        printf("Error: Could not find software_configuration in config\n");
        json_object_put(json);
        return 0;
    }
    
    // Get the first (and only) configuration item
    config_item = json_object_array_get_idx(software_config, 0);
    
    // Extract channel IDs
    const char* channel_keys[] = {"channel_one", "channel_two", "channel_three", "channel_four"};
    int channels_loaded = 0;
    
    for (int i = 0; i < 4; i++) {
        struct json_object *channel_obj, *channel_id_obj;
        if (json_object_object_get_ex(config_item, channel_keys[i], &channel_obj) &&
            json_object_object_get_ex(channel_obj, "channel_id", &channel_id_obj)) {
            const char* channel_id = json_object_get_string(channel_id_obj);
            if (channel_id && strlen(channel_id) < 64) {
                strncpy(channel_ids[i], channel_id, 63);
                channel_ids[i][63] = '\0';
                channels_loaded++;
                printf("Loaded channel %d ID: %s\n", i + 1, channel_ids[i]);
            } else {
                // Provide default channel ID if channel_id is empty or invalid
                snprintf(channel_ids[i], 64, "channel_%d", i + 1);
                channels_loaded++;
                printf("Loaded channel %d ID: %s (default)\n", i + 1, channel_ids[i]);
            }
        } else {
            // Provide default channel ID if channel section is missing
            snprintf(channel_ids[i], 64, "channel_%d", i + 1);
            channels_loaded++;
            printf("Loaded channel %d ID: %s (default - missing from config)\n", i + 1, channel_ids[i]);
        }
    }
    
    json_object_put(json);
    
    printf("Successfully loaded %d channel IDs from config\n", channels_loaded);
    return channels_loaded;
}

// Load complete configuration
int load_complete_config(void) {
    const char* config_path = "/home/will/.an/config.json";
    printf("[CONFIG] Attempting to load configuration from: %s\n", config_path);
    FILE *file = fopen(config_path, "r");
    if (!file) {
        printf("[ERROR] Could not open config file %s: %s\n", config_path, strerror(errno));
        printf("Using default configuration\n");
        return 0;
    }
    printf("[CONFIG] Successfully opened config file\n");
    
    // Read the entire file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    printf("[CONFIG] Config file size: %ld bytes\n", file_size);
    fseek(file, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        printf("Error: Memory allocation failed for config file\n");
        return 0;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);
    
    // Parse JSON
    printf("[CONFIG] Parsing JSON configuration...\n");
    struct json_object *json = json_tokener_parse(json_string);
    free(json_string);
    
    if (!json) {
        printf("Error: Failed to parse config JSON\n");
        return 0;
    }
    
    // Navigate to the channel configuration
    struct json_object *shadow, *state, *desired, *software_config, *config_item;
    if (!json_object_object_get_ex(json, "shadow", &shadow) ||
        !json_object_object_get_ex(shadow, "state", &state) ||
        !json_object_object_get_ex(state, "desired", &desired) ||
        !json_object_object_get_ex(desired, "software_configuration", &software_config) ||
        json_object_array_length(software_config) == 0) {
        printf("Error: Could not find software_configuration in config\n");
        json_object_put(json);
        return 0;
    }
    
    // Get the first (and only) configuration item
    config_item = json_object_array_get_idx(software_config, 0);
    
    // Extract channel configurations
    const char* channel_keys[] = {"channel_one", "channel_two", "channel_three", "channel_four"};
    int channels_loaded = 0;
    
    for (int i = 0; i < 4; i++) {
        struct json_object *channel_obj;
        if (json_object_object_get_ex(config_item, channel_keys[i], &channel_obj)) {
            struct channel_config *channel_config = &global_app_config.channels[i];
            
            // Load basic channel info
            struct json_object *channel_id_obj;
            if (json_object_object_get_ex(channel_obj, "channel_id", &channel_id_obj)) {
                const char* channel_id = json_object_get_string(channel_id_obj);
                if (channel_id && strlen(channel_id) < 64) {
                    strncpy(channel_config->channel_id, channel_id, 63);
                    channel_config->channel_id[63] = '\0';
                }
            }
            
            // Load input settings
            struct json_object *input_low_one_obj, *input_low_two_obj, *input_high_one_obj, *input_high_two_obj;
            if (json_object_object_get_ex(channel_obj, "input_low_one", &input_low_one_obj)) {
                channel_config->input_low_one = json_object_get_boolean(input_low_one_obj);
            }
            if (json_object_object_get_ex(channel_obj, "input_low_two", &input_low_two_obj)) {
                channel_config->input_low_two = json_object_get_boolean(input_low_two_obj);
            }
            if (json_object_object_get_ex(channel_obj, "input_high_one", &input_high_one_obj)) {
                channel_config->input_high_one = json_object_get_boolean(input_high_one_obj);
            }
            if (json_object_object_get_ex(channel_obj, "input_high_two", &input_high_two_obj)) {
                channel_config->input_high_two = json_object_get_boolean(input_high_two_obj);
            }
            
            
            channel_config->valid = 1;
            channels_loaded++;
            printf("Loaded channel %d config: ID=%s\n", 
                   i+1, channel_config->channel_id);
        } else {
            // Provide default configuration for missing channels
            struct channel_config *channel_config = &global_app_config.channels[i];
            snprintf(channel_config->channel_id, 64, "channel_%d", i + 1);
            channel_config->input_low_one = 0;
            channel_config->input_low_two = 0;
            channel_config->input_high_one = 0;
            channel_config->input_high_two = 0;
            channel_config->valid = 1;
            channels_loaded++;
            printf("Loaded channel %d config: ID=%s (default - missing from config)\n", 
                   i+1, channel_config->channel_id);
        }
    }
    
    json_object_put(json);
    
    if (channels_loaded > 0) {
        global_app_config.valid = 1;
        printf("Successfully loaded configuration for %d channels\n", channels_loaded);
        return 1;
    } else {
        printf("Warning: No channel configurations loaded\n");
        return 0;
    }
}

// Get channel configuration by index
struct channel_config* get_channel_config(int channel_index) {
    if (channel_index >= 0 && channel_index < 4 && global_app_config.valid) {
        return &global_app_config.channels[channel_index];
    }
    return NULL;
}

