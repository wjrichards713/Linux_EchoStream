#ifndef CONFIG_H
#define CONFIG_H

#include "echostream.h"

// Constants for tone detection
#define MAX_TONE_DEFINITIONS 10
#define MAX_FILTERS 20

// Tone detection configuration structure
struct tone_detect_config {
    int tone_passthrough;           // Whether tone passthrough is enabled
    char passthrough_channel[32];   // Target channel for passthrough
    float threshold;                // Detection threshold
    float gain;                     // Audio gain
    int db_threshold;               // dB threshold
    int detect_new_tones;           // Whether to detect new tones
    int new_tone_length_ms;         // New tone length in milliseconds
    int new_tone_range_hz;          // New tone frequency range
    int valid;                      // Whether this config is valid
};

// Channel configuration structure
struct channel_config {
    char channel_id[64];
    int input_low_one;
    int input_low_two;
    int input_high_one;
    int input_high_two;
    int tone_detect;                // Whether this channel has tone detection
    struct tone_detect_config tone_config;  // Tone detection configuration
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
struct channel_config* get_channel_config(int channel_index);
struct tone_detect_config* get_tone_detect_config(int channel_index);

#endif // CONFIG_H
