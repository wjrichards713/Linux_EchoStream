#ifndef TONE_DETECT_H
#define TONE_DETECT_H

#include "echostream.h"
#include <fftw3.h>
#include <complex.h>
#include <pthread.h>

// Tone detection configuration structures
typedef struct {
    char tone_id[64];
    double tone_a;
    double tone_b;
    double tone_a_length;
    double tone_b_length;
    int tone_a_range;
    int tone_b_range;
    int record_length;
    int valid;
} tone_definition_t;

typedef struct {
    char filter_id[64];
    double frequency;
    int filter_range;
    char type[16]; // "above", "below", "center"
    int valid;
} frequency_filter_t;

typedef struct {
    double threshold;
    double gain;
    int db;
    int detect_new_tones;
    double new_tone_length;
    int new_tone_range;
} alert_details_t;

typedef struct {
    int tone_passthrough;
    char passthrough_channel[64];
    tone_definition_t alert_tones[MAX_TONE_DEFINITIONS];
    int alert_tones_count;
    alert_details_t alert_details;
    frequency_filter_t filter_frequencies[MAX_FILTERS];
    int filter_frequencies_count;
    int valid;
} tone_detect_config_t;

// Tone detection state structures
typedef struct {
    int enabled;
    int card1_input_enabled;
    int passthrough_mode;
    pthread_mutex_t mutex;
} tone_detect_control_t;

typedef struct {
    float samples[SAMPLES_PER_FRAME];
    int sample_count;
    int valid;
    pthread_mutex_t mutex;
    pthread_cond_t data_ready;
} shared_audio_buffer_t;

typedef struct {
    int active;
    int target_channel;
    PaStream *passthrough_stream;
    pthread_mutex_t mutex;
} tone_passthrough_t;

typedef struct {
    int enabled;
    int target_channel;
    int active;
    PaStream *passthrough_stream;
    pthread_mutex_t mutex;
} global_tone_passthrough_t;

// Global variables
extern tone_detect_control_t global_tone_detect;
extern shared_audio_buffer_t global_shared_buffer;
extern global_tone_passthrough_t global_tone_passthrough;
extern int force_passthrough_reevaluation;

// Tone detection configuration functions
int init_tone_detection(void);
int start_tone_detection(void);
int cleanup_tone_detection(void);
int load_tone_detection_config(const char *config_file);
tone_detect_config_t* get_tone_detect_config(int channel_index);

// Tone detection control functions
int init_tone_detect_control(void);
int enable_tone_detection(void);
int disable_tone_detection(void);
int set_passthrough_output_mode(int passthrough_mode);
int is_tone_detect_enabled(void);
int is_card1_input_enabled(void);
int is_passthrough_mode(void);

// Passthrough functions
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

// FFT and tone detection functions
double freq_from_fft(const float *samples, int sample_count, int sample_rate);
int detect_tone_sequence(const float *samples, int sample_count, int sample_rate, 
                         tone_definition_t *tone_def, int tolerance);
int apply_frequency_filters(float *samples, int sample_count, int sample_rate,
                           frequency_filter_t *filters, int filter_count);
int detect_new_tones(const float *samples, int sample_count, int sample_rate,
                     alert_details_t *alert_details);

// Constants
#define MAX_TONE_DEFINITIONS 10
#define MAX_FILTERS 10
#define MAX_TONE_LEN 5.0  // Maximum tone length in seconds
#define FFT_SIZE 1024
#define TONE_DETECTION_THREAD_STACK_SIZE 65536

#endif // TONE_DETECT_H
