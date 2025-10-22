#ifndef AUDIO_H
#define AUDIO_H

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
    unsigned char encoded_buffer[4096]; // Buffer for encoded audio data
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



// Debug function to list all audio devices
void list_all_audio_devices(void);

// Function declarations
int initialize_portaudio(void);
int setup_audio_for_channel(struct audio_stream* audio_stream);
int start_transmission_for_channel(struct audio_stream* audio_stream);
void auto_assign_usb_devices(void);
PaDeviceIndex get_device_for_channel(const char* channel);
int setup_channel(struct channel_context *ctx, const char *channel_id);


// Audio device initialization and cleanup
int initialize_audio_devices(void);
int cleanup_audio_devices(void);


// Tone detection integration functions
int init_tone_detect_control(void);
int enable_tone_detection(void);
int disable_tone_detection(void);
int set_passthrough_output_mode(int passthrough_mode);
int is_tone_detect_enabled(void);
int is_card1_input_enabled(void);
int is_passthrough_mode(void);
int get_passthrough_target_channel_index(void);
int channel_has_output_stream(int channel_index);
int repair_passthrough_output_stream(int channel_index);
int start_tone_passthrough(int target_channel);
int stop_tone_passthrough(void);
int is_tone_passthrough_active(void);
int tone_passthrough_callback(const void *input, void *output, unsigned long frames,
                              const PaStreamCallbackTimeInfo *time_info,
                              PaStreamCallbackFlags flags, void *user_data);

// Audio buffer functions
int init_shared_audio_buffer(void);
int update_shared_audio_buffer(const float *samples, int sample_count);

// Audio callback functions
int audio_output_callback(const void *input, void *output, unsigned long frames,
                         const PaStreamCallbackTimeInfo* time_info,
                         PaStreamCallbackFlags flags, void *user_data);



#endif // AUDIO_H