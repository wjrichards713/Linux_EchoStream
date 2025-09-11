#ifndef TONE_DETECT_H
#define TONE_DETECT_H

#include "echostream.h"
#include <fftw3.h>

// Tone detection constants
#define TONE_DETECT_BUFFER_SIZE 4800  // 100ms at 48kHz
#define FFT_SIZE 1024
#define MAX_TONE_DETAILS 10
#define MAX_FILTER_FREQUENCIES 5
#define TONE_DETECT_THREADS 2  // Support for 2 channels with tone detection

// Tone detection structures
struct tone_detail {
    char tone_id[64];
    float tone_a;
    float tone_b;
    int tone_a_length;
    int tone_b_length;
    int tone_a_range;
    int tone_b_range;
    int record_length;
};

struct tone_config {
    float threshold;
    float gain;
    int db;
    int detect_new_tones;
    int new_tone_length;
    int new_tone_range;
};

struct filter_frequency {
    char filter_id[64];
    float frequency;
    int filter_range;
    char type[8];  // "above", "below", "center"
};

struct tone_detect_channel {
    int active;
    int channel_index;
    struct tone_detail tone_details[MAX_TONE_DETAILS];
    int tone_detail_count;
    struct tone_config config;
    struct filter_frequency filters[MAX_FILTER_FREQUENCIES];
    int filter_count;
    
    // FFT buffers
    fftwf_complex *fft_input;
    fftwf_complex *fft_output;
    fftwf_plan fft_plan;
    
    // Audio processing buffers
    float *audio_buffer;
    int buffer_pos;
    int buffer_size;
    
    // Tone detection state
    int tone_a_detected;
    int tone_b_detected;
    int tone_a_count;
    int tone_b_count;
    float current_tone_frequency;
    int recording;
    int record_count;
    
    // New tone detection
    float *new_tone_buffer;
    int new_tone_buffer_pos;
    int new_tone_detected;
    float new_tone_frequency;
    int new_tone_count;
    
    pthread_mutex_t mutex;
};

// Shared audio buffer for tone detection
struct shared_audio_buffer {
    float samples[TONE_DETECT_BUFFER_SIZE];
    int write_pos;
    int read_pos;
    int available_samples;
    int buffer_size;
    pthread_mutex_t mutex;
    pthread_cond_t data_available;
};

// Global tone detection state
extern struct tone_detect_channel tone_channels[TONE_DETECT_THREADS];
extern struct shared_audio_buffer shared_buffer;
extern int tone_detect_enabled;

// Function declarations
int tone_detect_init(void);
void tone_detect_cleanup(void);
int tone_detect_setup_channel(int channel_index, const char* config_json);
void tone_detect_process_audio(int channel_index, const float* samples, int sample_count);
int tone_detect_start_recording(int channel_index);
void tone_detect_stop_recording(int channel_index);
void* tone_detect_thread(void* arg);

// Shared buffer functions
int shared_buffer_init(void);
void shared_buffer_cleanup(void);
void shared_buffer_write(const float* samples, int sample_count);
int shared_buffer_read(float* samples, int max_samples);

#endif // TONE_DETECT_H
