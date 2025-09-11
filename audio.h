#ifndef AUDIO_H
#define AUDIO_H

#include "echostream.h"
#include "tone_detect.h"

// Audio structures
struct audio_frame {
    float samples[SAMPLES_PER_FRAME];
    int sample_count;
    int valid;
};

struct jitter_buffer {
    struct audio_frame frames[JITTER_BUFFER_SIZE];
    int write_index;
    int read_index;
    int frame_count;
    pthread_mutex_t mutex;
};

struct audio_stream {
    PaStream *input_stream;
    PaStream *output_stream;
    OpusEncoder *encoder;
    OpusDecoder *decoder;
    unsigned char key[32];
    int transmitting;
    int gpio_active;
    float *input_buffer;
    struct jitter_buffer output_jitter;
    int buffer_size;
    int input_buffer_pos;
    int current_output_frame_pos;
    PaDeviceIndex device_index;
    char channel_id[CHANNEL_ID_LEN];
    int tone_detect_enabled;  // Flag to enable tone detection for this channel
};

struct channel_context {
    struct audio_stream audio;
    pthread_t thread;
    int active;
};

// Global audio state
extern struct channel_context channels[MAX_CHANNELS];
extern PaDeviceIndex usb_devices[MAX_CHANNELS];
extern int device_assigned;

// Function declarations
int initialize_portaudio(void);
int setup_audio_for_channel(struct audio_stream* audio_stream);
int start_transmission_for_channel(struct audio_stream* audio_stream);
void auto_assign_usb_devices(void);
PaDeviceIndex get_device_for_channel(const char* channel);
int setup_channel(struct channel_context *ctx, const char *channel_id);

// Tone detection integration
int enable_tone_detection_for_channel(int channel_index);
int setup_tone_detection_for_channel(int channel_index, const char* config_json);
void start_tone_detection_threads(void);

// Audio callback functions are static and defined in audio.c

#endif // AUDIO_H
