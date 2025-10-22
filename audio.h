#ifndef AUDIO_H
#define AUDIO_H

#include "echostream.h"
#include "tone_detect.h"

// Audio constants
#define AUDIO_BUFFER_SIZE 1024

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
    unsigned char encoded_buffer[1024];  // Buffer for encoded audio data
};

struct channel_context {
    struct audio_stream audio;
    pthread_t thread;
    int active;
};

// Shared audio buffer for real-time passthrough
struct shared_audio_buffer {
    float samples[SAMPLES_PER_FRAME];
    int sample_count;
    int valid;
    pthread_mutex_t mutex;
    pthread_cond_t data_ready;
};

// Audio passthrough context
struct audio_passthrough {
    struct shared_audio_buffer *shared_buffer;
    PaStream *output_stream;
    PaDeviceIndex output_device;
    int active;
    pthread_t thread;
};

// Tone detection control
struct tone_detect_control {
    int enabled;                    // 1 = enabled, 0 = disabled
    int card1_input_enabled;       // 1 = Card 1 input active, 0 = disabled
    int passthrough_mode;          // 1 = passthrough, 0 = echostream
    pthread_mutex_t mutex;
};

// Tone passthrough control
struct tone_passthrough_control {
    int active;                     // 1 = passthrough active, 0 = disabled
    int source_channel;             // Source channel index (0-3)
    int target_channel;             // Target channel index (0-3)
    PaStream *passthrough_stream;   // Direct audio passthrough stream
    pthread_mutex_t mutex;
};

// Global audio state
extern struct channel_context channels[MAX_CHANNELS];
extern PaDeviceIndex usb_devices[MAX_CHANNELS];
extern int device_assigned;

// Global shared audio buffer and passthrough
extern struct shared_audio_buffer global_shared_buffer;
extern struct audio_passthrough global_passthrough;

// Global tone detection control
extern struct tone_detect_control global_tone_detect;

// Global tone passthrough control
extern struct tone_passthrough_control global_tone_passthrough;

// Function declarations
int initialize_portaudio(void);
int setup_audio_for_channel(struct audio_stream* audio_stream);
int start_transmission_for_channel(struct audio_stream* audio_stream);
void auto_assign_usb_devices(void);
PaDeviceIndex get_device_for_channel(const char* channel);
int setup_channel(struct channel_context *ctx, const char *channel_id);

// Audio passthrough functions
int init_shared_audio_buffer(void);
int init_audio_passthrough(void);
void* audio_passthrough_thread(void* arg);
int start_audio_passthrough(void);
void stop_audio_passthrough(void);

// Audio encoding and transmission functions
int encode_audio_data(const float* samples, int frame_count, unsigned char* encoded_buffer, int buffer_size);
int send_audio_data(const char* channel_id, const unsigned char* encoded_data, int data_size);

// Audio device initialization and cleanup
int initialize_audio_devices(void);
int cleanup_audio_devices(void);

// Tone detection control functions
int init_tone_detect_control(void);
int enable_tone_detection(void);
int disable_tone_detection(void);
int set_passthrough_output_mode(int passthrough_mode);
int is_tone_detect_enabled(void);
int is_card1_input_enabled(void);
int is_passthrough_mode(void);

// Tone passthrough control functions
int init_tone_passthrough_control(void);
int setup_tone_passthrough(int source_channel, int target_channel);
int start_tone_passthrough(void);
int stop_tone_passthrough(void);
int get_passthrough_target_channel_index(void);
int channel_has_output_stream(int channel_index);
int is_tone_passthrough_active(void);
int tone_passthrough_callback(const void *input, void *output, unsigned long frames,
                              const PaStreamCallbackTimeInfo* time_info,
                              PaStreamCallbackFlags flags, void *user_data);

// Audio callback functions are static and defined in audio.c

// Tone detection integration
void feed_audio_to_tone_detection(const float* samples, int sample_count);

#endif // AUDIO_H