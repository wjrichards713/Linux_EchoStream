#ifndef TONE_DETECT_H
#define TONE_DETECT_H

#include <pthread.h>
#include <stdint.h>
#include <complex.h>

// Configuration constants
#define MAX_TONE_DEFINITIONS 10
#define MAX_FILTERS 10
#define SAMPLE_RATE 48000
#define SAMPLES_PER_FRAME 1920
#define MAX_GOERTZEL_FILTERS 20

// Goertzel filter structure for specific frequency detection
struct goertzel_filter {
    char filter_id[64];
    float target_frequency;        // Target frequency to detect
    float threshold;               // Detection threshold (0.0 to 1.0)
    int window_size;              // Number of samples for detection window
    int min_duration_ms;          // Minimum duration for confirmation
    int range_hz;                 // Frequency tolerance range
    
    // Goertzel algorithm state variables
    float q1, q2;                 // Previous state values
    float coeff;                  // Goertzel coefficient
    float magnitude;              // Current magnitude
    int samples_processed;        // Samples processed in current window
    int is_active;                // Whether this filter is currently active
    int confirmed;                // Whether tone has been confirmed
    int tracking_start_time;      // When tracking started (ms)
    
    int valid;                    // Whether this filter is valid/configured
};

// Tone sequence definition
struct tone_sequence {
    char sequence_id[64];
    struct goertzel_filter tone_a;    // First tone in sequence
    struct goertzel_filter tone_b;    // Second tone in sequence
    int sequence_timeout_ms;          // Timeout for complete sequence
    int record_duration_ms;           // How long to record after sequence
    int valid;
};

// Audio filter for frequency band limiting
struct audio_filter {
    char filter_id[64];
    float cutoff_frequency;       // Cutoff frequency
    int filter_type;              // 0=lowpass, 1=highpass, 2=bandpass
    int range_hz;                 // For bandpass: range around cutoff
    int valid;
};

// Detection state machine
enum detection_state {
    DETECT_STATE_IDLE,            // Waiting for tone A
    DETECT_STATE_TONE_A,          // Detecting tone A
    DETECT_STATE_TONE_B,          // Detecting tone B
    DETECT_STATE_RECORDING,       // Recording after sequence
    DETECT_STATE_TIMEOUT          // Sequence timed out
};

// Legacy structures for compatibility
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

// Main tone detection system state
struct tone_detection_state {
    // Goertzel filters for tone detection
    struct goertzel_filter goertzel_filters[MAX_GOERTZEL_FILTERS];
    int active_filter_count;
    
    // Tone sequences
    struct tone_sequence tone_sequences[MAX_TONE_DEFINITIONS];
    int active_sequence_count;
    
    // Audio filters
    struct audio_filter audio_filters[MAX_FILTERS];
    int active_audio_filter_count;
    
    // Detection state
    enum detection_state current_state;
    int current_sequence_index;   // Which sequence we're currently detecting
    int sequence_start_time;      // When current sequence started
    int last_detection_time;      // Last time any tone was detected
    
    // Configuration
    float global_gain;            // Global audio gain
    float global_threshold;       // Global detection threshold
    int detect_new_tones;         // Whether to detect unknown frequencies
    int new_tone_threshold;       // Threshold for new tone detection
    
    // Statistics
    int total_detections;
    int tone_a_detections;
    int tone_b_detections;
    int sequence_detections;
    int new_tone_detections;
    
    // Threading
    pthread_t thread;
    pthread_mutex_t mutex;
    int active;                   // Whether detection is active
    int should_stop;              // Stop flag for thread
    
    // Audio processing
    float audio_buffer[SAMPLES_PER_FRAME];
    int buffer_position;
    int samples_processed;
    
    // Legacy compatibility fields
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
    int recording_start_time;
    
    float detected_frequencies[100];
    int   detected_frequency_count;
};

extern struct tone_detection_state global_tone_detection;

// Core system functions
int init_tone_detection(void);
int start_tone_detection(void);
void stop_tone_detection(void);
void* tone_detection_thread(void* arg);

// Audio processing
int process_audio_samples(const float* samples, int sample_count);
int update_goertzel_filters(const float* samples, int sample_count);
int check_tone_sequences(void);
int apply_audio_filters(float* samples, int sample_count);

// Goertzel algorithm functions
int init_goertzel_filter(struct goertzel_filter* filter, float frequency, 
                        float threshold, int window_size, int min_duration_ms);
int update_goertzel_filter(struct goertzel_filter* filter, float sample);
float get_goertzel_magnitude(const struct goertzel_filter* filter);
int is_goertzel_filter_ready(const struct goertzel_filter* filter);

// Tone sequence management
int add_tone_sequence(const char* sequence_id, 
                     float tone_a_freq, int tone_a_duration_ms, int tone_a_range_hz,
                     float tone_b_freq, int tone_b_duration_ms, int tone_b_range_hz,
                     int sequence_timeout_ms, int record_duration_ms);
int remove_tone_sequence(const char* sequence_id);
int find_tone_sequence(const char* sequence_id);

// Audio filter management
int add_audio_filter(const char* filter_id, float cutoff_freq, 
                    int filter_type, int range_hz);
int remove_audio_filter(const char* filter_id);
int apply_lowpass_filter(float* samples, int count, float cutoff_freq);
int apply_highpass_filter(float* samples, int count, float cutoff_freq);
int apply_bandpass_filter(float* samples, int count, float center_freq, int range_hz);

// Configuration functions
int set_global_gain(float gain);
int set_global_threshold(float threshold);
int set_new_tone_detection(int enabled, int threshold);
int get_detection_statistics(int* total, int* tone_a, int* tone_b, int* sequences, int* new_tones);
void reset_detection_statistics(void);

// Utility functions
float frequency_to_goertzel_coeff(float frequency, int sample_rate);
int is_frequency_in_range(float freq, float target, int range);
uint64_t get_timestamp_ms(void);
void print_detection_status(void);

// Legacy compatibility functions
int analyze_frequency_spectrum(float* audio_samples, int sample_count);
int detect_tone_sequence(float* audio_samples, int sample_count);
int check_tone_definition(float frequency, struct tone_definition* tone_def, int is_tone_b);
int apply_frequency_filters(float* magnitudes, int count);
int apply_audio_frequency_filters(float* audio_samples, int sample_count);
int check_tone_duration(int tone_type, int current_time, struct tone_definition* tone_def);
void reset_tone_tracking(void);
int detect_new_tones(float* magnitudes, int count);
float frequency_to_bin(float frequency);
float bin_to_frequency(int bin);
float calculate_magnitude(double complex cv);
void print_tone_detection_stats(void);
void reset_tone_detection_stats(void);
void trigger_tone_passthrough(void);
int add_tone_definition(const char* tone_id, float tone_a_freq, float tone_b_freq,
                       int tone_a_length, int tone_b_length, int tone_a_range, int tone_b_range,
                       int record_length);
int add_frequency_filter(const char* filter_id, float frequency, int range, const char* type);
int set_tone_config(float threshold, float gain, int db_threshold, int detect_new_tones,
                   int new_tone_length, int new_tone_range);

#endif