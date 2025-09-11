#include "config.h"

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
            }
        }
    }
    
    json_object_put(json);
    
    if (channels_loaded == 4) {
        printf("Successfully loaded all 4 channel IDs from config\n");
        return 1;
    } else {
        printf("Warning: Only loaded %d out of 4 channel IDs from config\n", channels_loaded);
        return 0;
    }
}
