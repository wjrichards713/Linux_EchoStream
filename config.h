#ifndef CONFIG_H
#define CONFIG_H

#include "echostream.h"
#include "tone_detect.h"

// Tone detection configuration structure
struct tone_detect_config {
    int tone_passthrough;
    char passthrough_channel[32];
    float threshold;
    float gain;
    int db_threshold;
    int detect_new_tones;
    int new_tone_length_ms;
    int new_tone_range_hz;
    int valid;
};

// Channel configuration structure
struct channel_config {
    char channel_id[64];
    int input_low_one;
    int input_low_two;
    int input_high_one;
    int input_high_two;
    int tone_detect;
    struct tone_detect_config tone_config;
    int valid;
};

// Global configuration structure
struct global_config {
    struct channel_config channels[4];
    int valid;
};

// Global configuration instance
extern struct global_config global_app_config;

// Function declarations
int load_channel_config(char channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN]);
int load_complete_config(void);
int load_tone_detect_config_from_json(const char* filename);
struct channel_config* get_channel_config(int channel_index);
struct tone_detect_config* get_tone_detect_config(int channel_index);

#endif // CONFIG_H
