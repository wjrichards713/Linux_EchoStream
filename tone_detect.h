#ifndef TONE_DETECT_H
#define TONE_DETECT_H

#include "echostream.h"
#include <fftw3.h>

// Tone detection configuration
#define MAX_TONE_DEFINITIONS 10
#define MAX_FILTERS 5
#define FFT_SIZE 1024
#define SAMPLE_RATE 48000
#define FREQ_BINS (FFT_SIZE / 2)

// Tone definition structure
struct tone_definition {
    char tone_id[64];
    float tone_a_freq;        // Frequency for tone A
    float tone_b_freq;        // Frequency for tone B
    int tone_a_length_ms;     // Minimum length for tone A (ms)
    int tone_b_length_ms;     // Minimum length for tone B (ms)
    int tone_a_range_hz;      // Frequency range tolerance for tone A
    int tone_b_range_hz;      // Frequency range tolerance for tone B
    int record_length_ms;     // How long to record after detection
    int valid;                // 1 if this definition is valid
};

// Filter definition structure
struct frequency_filter {
    char filter_id[64];
    float frequency;
    int filter_range_hz;
    char type[16];            // "above", "below", "center"
    int valid;                // 1 if this filter is valid
};

// Tone detection configuration
struct tone_config {
    float threshold;           // Detection threshold (0.0 - 1.0)
    float gain;               // Input gain multiplier
    int db_threshold;         // dB threshold for detection
    int detect_new_tones;     // 1 to detect unknown tones
    int new_tone_length_ms;   // Minimum length for new tone detection
    int new_tone_range_hz;    // Frequency range for new tone detection
    int valid;                // 1 if config is valid
};

// Tone detection state
struct tone_detection_state {
    // FFT buffers
    double fft_input[FFT_SIZE];
    fftw_complex fft_output[FFT_SIZE];
    fftw_plan fft_plan;
    
    // Frequency analysis
    float frequency_magnitudes[FREQ_BINS];
    float peak_frequencies[10];  // Top 10 peak frequencies
    int peak_count;
    
    // Tone detection
    struct tone_definition tone_definitions[MAX_TONE_DEFINITIONS];
    struct frequency_filter filters[MAX_FILTERS];
    struct tone_config config;
    
    // Detection state
    int current_tone_a_detected;
    int current_tone_b_detected;
    int tone_sequence_active;
    int recording_active;
    int recording_start_time;
    int recording_duration_ms;     // Current recording duration (ms)
    int tone_a_start_time;
    int tone_b_start_time;
    
    // Passthrough filtering - store which tone frequencies to pass through
    float passthrough_tone_a_freq;  // Frequency of Tone A to pass through (0 if not active)
    float passthrough_tone_b_freq;  // Frequency of Tone B to pass through (0 if not active)
    int passthrough_tone_a_range;   // Range for Tone A filtering
    int passthrough_tone_b_range;   // Range for Tone B filtering
    int passthrough_active;         // 1 if passthrough filtering is active
    
    // Duration tracking for proper tone detection
    int tone_a_tracking;          // 1 if currently tracking tone A
    int tone_b_tracking;          // 1 if currently tracking tone B
    int tone_a_confirmed;         // 1 if tone A has been confirmed (duration met)
    int tone_b_confirmed;         // 1 if tone B has been confirmed (duration met)
    int tone_a_tracking_start;    // Start time when tone A tracking began
    int tone_b_tracking_start;    // Start time when tone B tracking began
    
    // New tone detection
    float detected_frequencies[100];  // Buffer for detected frequencies
    int detected_frequency_count;
    
    // New tone tracking state (for duration validation)
    struct {
        float frequency;
        int tracking_start;      // Start time when tracking began
        int is_tracking;         // 1 if currently tracking this frequency
        int hit_streak;          // Consecutive hits
        int miss_streak;         // Consecutive misses
        int last_seen_ms;        // Last time this frequency was seen
    } new_tone_tracking[10];    // Track up to 10 potential new tones simultaneously
    
    // Thread control
    int active;
    pthread_t thread;
    pthread_mutex_t mutex;
    
    // Statistics
    int total_detections;
    int tone_a_detections;
    int tone_b_detections;
    int new_tone_detections;
};

// Global tone detection state
extern struct tone_detection_state global_tone_detection;

// Function declarations
int init_tone_detection(void);
int start_tone_detection(void);
void stop_tone_detection(void);
void* tone_detection_thread(void* arg);

// Configuration functions
int load_tone_config_from_json(const char* filename);
int add_tone_definition(const char* tone_id, float tone_a_freq, float tone_b_freq,
                       int tone_a_length, int tone_b_length, int tone_a_range, int tone_b_range,
                       int record_length);
int add_frequency_filter(const char* filter_id, float frequency, int range, const char* type);
int set_tone_config(float threshold, float gain, int db_threshold, int detect_new_tones,
                   int new_tone_length, int new_tone_range);

// Detection functions
int detect_tone_sequence(float* audio_samples, int sample_count);
int analyze_frequency_spectrum(float* audio_samples, int sample_count);
int check_tone_definition(float frequency, struct tone_definition* tone_def, int is_tone_b);
int apply_frequency_filters(float* magnitudes, int count);
int detect_new_tones(float* magnitudes, int count);

// Utility functions
float frequency_to_bin(float frequency);
float bin_to_frequency(int bin);
float calculate_magnitude(fftw_complex complex_val);
int is_frequency_in_range(float freq, float target, int range);

// Statistics functions
void print_tone_detection_stats(void);
void reset_tone_detection_stats(void);

// Tone passthrough integration
// Only trigger for known tones (not new/unknown tones)
void trigger_tone_passthrough(struct tone_definition* confirmed_tone_def);

// Get passthrough tone audio samples (generates pure tones at detected frequencies)
int get_passthrough_tone_samples(float* output_buffer, int max_samples, int sample_rate);

// Stop alert playback
void stop_alert_playback(void);

// Audio filtering and duration detection functions
int apply_audio_frequency_filters(float* audio_samples, int sample_count);

// Filter audio to only pass through detected tone frequencies (for passthrough)
// Removes all other frequencies including voice, keeping only tone_a_freq ± tone_a_range and tone_b_freq ± tone_b_range
int filter_audio_for_passthrough(float* audio_samples, int sample_count, 
                                 float tone_a_freq, int tone_a_range,
                                 float tone_b_freq, int tone_b_range);
int check_tone_duration(int tone_type, int current_time, struct tone_definition* tone_def);
void reset_tone_tracking(void);

// Python approach functions
void add_audio_to_sliding_buffer(const float* samples, int count);
float calculate_volume_level(void);
void get_audio_segment(int start_offset_samples, int length_samples, float* output);
int process_audio_python_approach(const float* samples, int sample_count);
int detect_single_tone_for_passthrough(const float* samples, int sample_count);
int get_current_time_ms(void);

// Alert playback functions
void generate_alert_tone(float frequency, float duration_seconds, float* output_buffer, int sample_rate);
void play_alert_tone_locally(int target_channel_idx, float tone_a_freq, float tone_b_freq, 
                            float tone_a_duration, float tone_b_duration);
int get_alert_audio_samples(float* output_buffer, int max_samples);
int is_alert_playing(void);
int should_play_alert_on_channel(int channel_index);

// FFT frequency extraction
float freq_from_fft(float* samples, int sample_count, int sample_rate);

// Recording timer management
int start_recording_timer(int record_length_ms);
void stop_recording_timer(void);
int is_recording_active(void);
int get_recording_time_remaining_ms(void);

#endif // TONE_DETECT_H