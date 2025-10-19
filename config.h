#ifndef CONFIG_H
#define CONFIG_H

#include "echostream.h"

// Channel configuration structure
struct channel_config {
    char channel_id[64];
    int input_low_one;
    int input_low_two;
    int input_high_one;
    int input_high_two;
    int tone_detect;
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

#endif // CONFIG_H
