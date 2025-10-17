#ifndef TONE_DETECT_H
#define TONE_DETECT_H

#include <pthread.h>
#include <fftw3.h>

#define MAX_TONE_DEFINITIONS 10
#define MAX_FILTERS 10
#undef FFT_SIZE
#define FFT_SIZE 4096              /* higher resolution for ±5–6 Hz tone ranges */
#define SAMPLE_RATE 48000
#undef FREQ_BINS
#define FREQ_BINS (FFT_SIZE / 2 + 1)
#define SAMPLES_PER_FRAME 1920
#define MAX_PEAKS 64

#define ACCUM_BUFFER_SIZE FFT_SIZE /* accumulation buffer size for windowed FFT */

struct tone_definition {
    char  tone_id[64];
    float tone_a_freq;
    float tone_b_freq;
    int   tone_a_length_ms;
    int   tone_b_length_ms;
    int   tone_a_range_hz;
    int   tone_b_range_hz;
    int   record_length_ms;
    int   valid;
};

struct frequency_filter {
    char  filter_id[64];
    float frequency;
    int   filter_range_hz;
    char  type[16];   /* below | above | center */
    int   valid;
};

struct tone_detection_config {
    float threshold;
    float gain;
    int   db_threshold;
    int   detect_new_tones;
    int   new_tone_length_ms;
    int   new_tone_range_hz;
    int   valid;
};

struct tone_detection_state {
    fftw_plan     fft_plan;
    double        fft_input[FFT_SIZE];
    fftw_complex  fft_output[FFT_SIZE];
    float         frequency_magnitudes[FREQ_BINS];

    float peak_frequencies[MAX_PEAKS];
    int   peak_count;

    struct tone_definition    tone_definitions[MAX_TONE_DEFINITIONS];
    struct frequency_filter   filters[MAX_FILTERS];
    struct tone_detection_config config;

    int current_tone_a_detected;
    int current_tone_b_detected;
    int tone_sequence_active;
    int recording_active;

    int tone_a_tracking;
    int tone_b_tracking;
    int tone_a_confirmed;
    int tone_b_confirmed;
    int tone_a_tracking_start;
    int tone_b_tracking_start;
    int tone_a_start_time;
    int tone_b_start_time;
    int recording_start_time;   /* added */

    float detected_frequencies[100];
    int   detected_frequency_count;

    pthread_t thread;
    pthread_mutex_t mutex;
    int active;

    int total_detections;
    int tone_a_detections;
    int tone_b_detections;
    int new_tone_detections;
};

extern struct tone_detection_state global_tone_detection;

/* lifecycle */
int init_tone_detection(void);
int start_tone_detection(void);
void stop_tone_detection(void);
void *tone_detection_thread(void *arg);

/* processing */
int analyze_frequency_spectrum(float *audio_samples, int sample_count);
int detect_tone_sequence(float *audio_samples, int sample_count);
int check_tone_definition(float frequency, struct tone_definition *tone_def, int is_tone_b);
int apply_frequency_filters(float *magnitudes, int count);
int apply_audio_frequency_filters(float *audio_samples, int sample_count);
int check_tone_duration(int tone_type, int current_time, struct tone_definition *tone_def);
void reset_tone_tracking(void);
int detect_new_tones(float *magnitudes, int count);

/* utils */
float frequency_to_bin(float frequency);
float bin_to_frequency(int bin);
float calculate_magnitude(fftw_complex cv);
int   is_frequency_in_range(float freq, float target, int range);

/* statistics */
void print_tone_detection_stats(void);
void reset_tone_detection_stats(void);

/* passthrough trigger */
void trigger_tone_passthrough(void);

/* configuration (used by config.c) */
int add_tone_definition(const char *tone_id, float tone_a_freq, float tone_b_freq,
                        int tone_a_length, int tone_b_length, int tone_a_range, int tone_b_range,
                        int record_length);
int add_frequency_filter(const char *filter_id, float frequency, int range, const char *type);
int set_tone_config(float threshold, float gain, int db_threshold, int detect_new_tones,
                    int new_tone_length, int new_tone_range);

#endif