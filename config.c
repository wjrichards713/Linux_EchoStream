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

// Load complete configuration including tone detection settings
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
            
            // Load tone detection settings
            struct json_object *tone_detect_obj;
            if (json_object_object_get_ex(channel_obj, "tone_detect", &tone_detect_obj)) {
                channel_config->tone_detect = json_object_get_boolean(tone_detect_obj);
                
                if (channel_config->tone_detect) {
                    // Load tone detection configuration
                    struct json_object *tone_detect_config_obj;
                    if (json_object_object_get_ex(channel_obj, "tone_detect_configuration", &tone_detect_config_obj)) {
                        struct tone_detect_config *tone_config = &channel_config->tone_config;
                        
                        // Load tone passthrough settings
                        struct json_object *tone_passthrough_obj, *passthrough_channel_obj;
                        if (json_object_object_get_ex(tone_detect_config_obj, "tone_passthrough", &tone_passthrough_obj)) {
                            tone_config->tone_passthrough = json_object_get_boolean(tone_passthrough_obj);
                        }
                        if (json_object_object_get_ex(tone_detect_config_obj, "passthrough_channel", &passthrough_channel_obj)) {
                            const char* passthrough_channel = json_object_get_string(passthrough_channel_obj);
                            if (passthrough_channel && strlen(passthrough_channel) < 32) {
                                strncpy(tone_config->passthrough_channel, passthrough_channel, 31);
                                tone_config->passthrough_channel[31] = '\0';
                            }
                        }
                        
                        // Load alert details
                        struct json_object *alert_details_obj;
                        if (json_object_object_get_ex(tone_detect_config_obj, "alert_details", &alert_details_obj)) {
                            struct json_object *threshold_obj, *gain_obj, *db_obj, *detect_new_tones_obj, *new_tone_length_obj, *new_tone_range_obj;
                            
                            if (json_object_object_get_ex(alert_details_obj, "threshold", &threshold_obj)) {
                                tone_config->threshold = atof(json_object_get_string(threshold_obj));
                            }
                            if (json_object_object_get_ex(alert_details_obj, "gain", &gain_obj)) {
                                tone_config->gain = atof(json_object_get_string(gain_obj));
                            }
                            if (json_object_object_get_ex(alert_details_obj, "db", &db_obj)) {
                                tone_config->db_threshold = json_object_get_int(db_obj);
                            }
                            if (json_object_object_get_ex(alert_details_obj, "detect_new_tones", &detect_new_tones_obj)) {
                                tone_config->detect_new_tones = json_object_get_boolean(detect_new_tones_obj);
                            }
                            if (json_object_object_get_ex(alert_details_obj, "new_tone_length", &new_tone_length_obj)) {
                                tone_config->new_tone_length_ms = json_object_get_int(new_tone_length_obj);
                            }
                            if (json_object_object_get_ex(alert_details_obj, "new_tone_range", &new_tone_range_obj)) {
                                tone_config->new_tone_range_hz = json_object_get_int(new_tone_range_obj);
                            }
                        }
                        
                        // Load alert tones
                        struct json_object *alert_tones_obj;
                        if (json_object_object_get_ex(tone_detect_config_obj, "alert_tones", &alert_tones_obj)) {
                            int num_tones = json_object_array_length(alert_tones_obj);
                            for (int j = 0; j < num_tones && j < MAX_TONE_DEFINITIONS; j++) {
                                struct json_object *tone_obj = json_object_array_get_idx(alert_tones_obj, j);
                                struct json_object *tone_id_obj, *tone_a_obj, *tone_b_obj, *tone_a_length_obj, *tone_b_length_obj, *tone_a_range_obj, *tone_b_range_obj, *record_length_obj;
                                
                                char tone_id[64] = {0};
                                float tone_a = 0.0f, tone_b = 0.0f;
                                int tone_a_length = 0, tone_b_length = 0, tone_a_range = 0, tone_b_range = 0, record_length = 0;
                                
                                if (json_object_object_get_ex(tone_obj, "tone_id", &tone_id_obj)) {
                                    const char* id = json_object_get_string(tone_id_obj);
                                    if (id) strncpy(tone_id, id, 63);
                                }
                                if (json_object_object_get_ex(tone_obj, "tone_a", &tone_a_obj)) {
                                    tone_a = atof(json_object_get_string(tone_a_obj));
                                }
                                if (json_object_object_get_ex(tone_obj, "tone_b", &tone_b_obj)) {
                                    tone_b = atof(json_object_get_string(tone_b_obj));
                                }
                                if (json_object_object_get_ex(tone_obj, "tone_a_length", &tone_a_length_obj)) {
                                    // Convert seconds to milliseconds
                                    tone_a_length = (int)(json_object_get_double(tone_a_length_obj) * 1000);
                                }
                                if (json_object_object_get_ex(tone_obj, "tone_b_length", &tone_b_length_obj)) {
                                    // Convert seconds to milliseconds  
                                    tone_b_length = (int)(json_object_get_double(tone_b_length_obj) * 1000);
                                }
                                if (json_object_object_get_ex(tone_obj, "tone_a_range", &tone_a_range_obj)) {
                                    tone_a_range = json_object_get_int(tone_a_range_obj);
                                }
                                if (json_object_object_get_ex(tone_obj, "tone_b_range", &tone_b_range_obj)) {
                                    tone_b_range = json_object_get_int(tone_b_range_obj);
                                }
                                if (json_object_object_get_ex(tone_obj, "record_length", &record_length_obj)) {
                                    // Convert seconds to milliseconds
                                    record_length = json_object_get_int(record_length_obj) * 1000;
                                }
                                
                                // Add tone definition
                                printf("[CONFIG] Loading tone from JSON: ID=%s, A=%.1f Hz±%d (dur:%dms), B=%.1f Hz±%d (dur:%dms), rec:%dms\n",
                                       tone_id, tone_a, tone_a_range, tone_a_length, tone_b, tone_b_range, tone_b_length, record_length);
                                add_tone_definition(tone_id, tone_a, tone_b, tone_a_length, tone_b_length, tone_a_range, tone_b_range, record_length);
                            }
                        }
                        
                        // Load filter frequencies
                        struct json_object *filter_frequencies_obj;
                        if (json_object_object_get_ex(tone_detect_config_obj, "filter_frequencies", &filter_frequencies_obj)) {
                            int num_filters = json_object_array_length(filter_frequencies_obj);
                            for (int j = 0; j < num_filters && j < MAX_FILTERS; j++) {
                                struct json_object *filter_obj = json_object_array_get_idx(filter_frequencies_obj, j);
                                struct json_object *filter_id_obj, *frequency_obj, *filter_range_obj, *type_obj;
                                
                                char filter_id[64] = {0};
                                float frequency = 0.0f;
                                int filter_range = 0;
                                char type[16] = {0};
                                
                                if (json_object_object_get_ex(filter_obj, "filter_id", &filter_id_obj)) {
                                    const char* id = json_object_get_string(filter_id_obj);
                                    if (id) strncpy(filter_id, id, 63);
                                }
                                if (json_object_object_get_ex(filter_obj, "frequency", &frequency_obj)) {
                                    frequency = json_object_get_double(frequency_obj);
                                }
                                if (json_object_object_get_ex(filter_obj, "filter_range", &filter_range_obj)) {
                                    filter_range = json_object_get_int(filter_range_obj);
                                }
                                if (json_object_object_get_ex(filter_obj, "type", &type_obj)) {
                                    const char* t = json_object_get_string(type_obj);
                                    if (t) strncpy(type, t, 15);
                                }
                                
                                // Add frequency filter
                                printf("[CONFIG] Loading filter from JSON: ID=%s, freq=%.1f Hz, range=%d, type=%s\n",
                                       filter_id, frequency, filter_range, type);
                                add_frequency_filter(filter_id, frequency, filter_range, type);
                            }
                        }
                        
                        tone_config->valid = 1;
                        
                        // Apply tone configuration to the detection system
                        set_tone_config(tone_config->threshold, tone_config->gain, 
                                      tone_config->db_threshold, tone_config->detect_new_tones,
                                      tone_config->new_tone_length_ms, tone_config->new_tone_range_hz);
                        
                        printf("Loaded tone detection config for channel %d: passthrough=%d, channel=%s\n", 
                               i+1, tone_config->tone_passthrough, tone_config->passthrough_channel);
                        printf("Applied tone config: threshold=%.2f, gain=%.2f, db=%d, detect_new=%d\n",
                               tone_config->threshold, tone_config->gain, tone_config->db_threshold, 
                               tone_config->detect_new_tones);
                    }
                }
            }
            
            channel_config->valid = 1;
            channels_loaded++;
            printf("Loaded channel %d config: ID=%s, tone_detect=%d\n", 
                   i+1, channel_config->channel_id, channel_config->tone_detect);
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

// Get tone detection configuration by channel index
struct tone_detect_config* get_tone_detect_config(int channel_index) {
    struct channel_config* channel_config = get_channel_config(channel_index);
    if (channel_config && channel_config->tone_detect && channel_config->tone_config.valid) {
        return &channel_config->tone_config;
    }
    
    // If no valid config found, return a default configuration for channel 1 (index 0)
    if (channel_index == 0) {
        static struct tone_detect_config default_config = {0};
        static int default_config_initialized = 0;
        
        if (!default_config_initialized) {
            default_config.tone_passthrough = 1;
            strcpy(default_config.passthrough_channel, "channel_four");
            default_config.threshold = 0.7f;
            default_config.gain = 0.4f;
            default_config.db_threshold = -45;
            default_config.detect_new_tones = 1;
            default_config.new_tone_length_ms = 1000;
            default_config.new_tone_range_hz = 3;
            default_config.valid = 1;
            default_config_initialized = 1;
            
            printf("[CONFIG] Using default tone detection config for channel 1: passthrough=%d, channel=%s\n",
                   default_config.tone_passthrough, default_config.passthrough_channel);
        }
        
        return &default_config;
    }
    
    return NULL;
}
