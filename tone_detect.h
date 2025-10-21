#ifndef TONE_DETECT_H
#define TONE_DETECT_H

#include "echostream.h"
#include <complex.h>
#include <fftw3.h>

// Include cJSON library - try different paths (note: actual file is cJSON.h with capital C)
#ifdef __has_include
    #if __has_include(<cjson/cJSON.h>)
        #include <cjson/cJSON.h>
    #elif __has_include(<cjson/cjson.h>)
        #include <cjson/cjson.h>
    #elif __has_include(<cJSON.h>)
        #include <cJSON.h>
    #elif __has_include(<cjson.h>)
        #include <cjson.h>
    #else
        #error "cJSON library not found. Please install libcjson-dev"
    #endif
#else
    // Try the most common paths
    #ifdef __linux__
        #include <cjson/cJSON.h>
    #else
        #include <cJSON.h>
    #endif
#endif

// Tone detection configuration constants
#define MAX_TONE_DEFINITIONS 10
#define MAX_TONE_SEQUENCES 10
#define MAX_FILTERS 5
#define FFT_SIZE 1024
#define SAMPLE_RATE 48000
#define FREQ_RESOLUTION ((double)SAMPLE_RATE / FFT_SIZE)  // ~46.9 Hz per bin
#define MAX_PEAKS 10
#define SEQUENCE_TIMEOUT_MS 5000
#define TONE_DETECTION_THREAD_STACK_SIZE 32768

// Tone detection states
typedef enum {
    TONE_STATE_IDLE = 0,
    TONE_STATE_DETECTING_A,
    TONE_STATE_DETECTING_B,
    TONE_STATE_RECORDING,
    TONE_STATE_TIMEOUT
} tone_state_t;

// Filter types
typedef enum {
    FILTER_BELOW = 0,
    FILTER_ABOVE,
    FILTER_CENTER
} filter_type_t;

// Tone definition structure
typedef struct {
    char tone_id[64];
    double tone_a_freq;        // Frequency of tone A (Hz)
    double tone_b_freq;        // Frequency of tone B (Hz)
    double tone_a_length_ms;   // Minimum duration for tone A (ms)
    double tone_b_length_ms;   // Minimum duration for tone B (ms)
    double tone_a_range_hz;    // Frequency tolerance for tone A (±Hz)
    double tone_b_range_hz;    // Frequency tolerance for tone B (±Hz)
    double record_length_ms;   // Recording duration after detection (ms)
    int valid;                 // Whether this definition is valid
} tone_definition_t;

// Frequency filter structure
typedef struct {
    char filter_id[64];
    double frequency;          // Center frequency (Hz)
    double filter_range;       // Range around center frequency (Hz)
    filter_type_t type;        // Filter type (below/above/center)
    int valid;                 // Whether this filter is valid
} frequency_filter_t;

// Alert details structure
typedef struct {
    double threshold;          // Relative threshold (0.0-1.0)
    double gain;              // Input gain multiplier
    double db_threshold;      // Absolute dB threshold
    int detect_new_tones;     // Enable new tone detection
    double new_tone_length_ms; // Minimum duration for new tones (ms)
    double new_tone_range_hz; // Frequency tolerance for new tones (±Hz)
} alert_details_t;

// Tone detection configuration
typedef struct {
    char channel_id[64];                    // Channel ID for this configuration
    int tone_detect_enabled;                // Whether tone detection is enabled for this channel
    int tone_passthrough;                    // Enable tone passthrough
    char passthrough_channel[64];           // Target channel for passthrough
    tone_definition_t alert_tones[MAX_TONE_DEFINITIONS];
    int num_alert_tones;
    alert_details_t alert_details;
    frequency_filter_t filters[MAX_FILTERS];
    int num_filters;
    int valid;                              // Whether configuration is valid
} tone_detect_config_t;

// Peak detection structure
typedef struct {
    int bin_index;           // FFT bin index
    double frequency;        // Frequency in Hz
    double magnitude;        // Magnitude (linear)
    double magnitude_db;     // Magnitude in dB
} peak_t;

// Tone detection state for a specific tone sequence
typedef struct {
    tone_definition_t *definition;
    tone_state_t state;
    double tone_a_detected_duration_ms;
    double tone_b_detected_duration_ms;
    double sequence_start_time_ms;
    double last_detection_time_ms;
    int tone_a_confirmed;
    int tone_b_confirmed;
    int recording_active;
    double recording_start_time_ms;
} tone_sequence_state_t;

// Global tone detection control
typedef struct {
    int enabled;                             // Master enable/disable
    int card1_input_enabled;                // Enable input from card 1
    int passthrough_mode;                   // Enable passthrough mode
    pthread_mutex_t mutex;                  // Thread safety
} tone_detect_control_t;

// Passthrough audio buffer
typedef struct {
    float samples[SAMPLES_PER_FRAME];
    int sample_count;
    int valid;
    pthread_mutex_t mutex;
} passthrough_audio_buffer_t;

// Global tone detection state
typedef struct {
    tone_detect_config_t configs[MAX_CHANNELS];
    tone_sequence_state_t sequences[MAX_TONE_SEQUENCES];
    int num_active_sequences;
    fftw_plan fft_plan;
    fftw_complex *fft_input;
    fftw_complex *fft_output;
    double *magnitude_spectrum;
    peak_t detected_peaks[MAX_PEAKS];
    int num_peaks;
    pthread_t detection_thread;
    int thread_running;
    pthread_mutex_t state_mutex;
    pthread_cond_t data_ready;
    struct timespec last_analysis_time;
} tone_detection_state_t;

// Additional structures for audio passthrough
typedef struct {
    int active;
    int target_channel;
    int source_channel;
    PaStream *output_stream;
    PaStream *passthrough_stream;
    struct shared_audio_buffer *shared_buffer;
    pthread_t thread;
    pthread_mutex_t mutex;
} audio_passthrough_t;

typedef struct {
    int enabled;
    int active;
    int target_channel;
    int source_channel;
    PaStream *passthrough_stream;
    pthread_mutex_t mutex;
} tone_passthrough_control_t;

// Global variables
extern tone_detect_control_t global_tone_detect;
extern passthrough_audio_buffer_t global_passthrough_buffer;
extern tone_detection_state_t global_tone_detection;
extern audio_passthrough_t global_passthrough;
extern tone_passthrough_control_t global_tone_passthrough;

// Function declarations

// Configuration functions
int load_tone_detection_config(void);
tone_detect_config_t* get_tone_detect_config(int channel_index);
int parse_tone_definitions(cJSON *tone_array, tone_definition_t *tones, int max_tones);
int parse_frequency_filters(cJSON *filter_array, frequency_filter_t *filters, int max_filters);
int parse_alert_details(cJSON *details_obj, alert_details_t *details);

// Tone detection functions
int init_tone_detection(void);
int start_tone_detection(void);
int stop_tone_detection(void);
void cleanup_tone_detection(void);

// Audio processing functions
void* tone_detection_thread(void *arg);
int process_audio_frame(float *samples, int sample_count);
int perform_fft_analysis(float *samples, int sample_count);
int detect_peaks(double *magnitude_spectrum, int spectrum_size);
int match_tones_to_definitions(peak_t *peaks, int num_peaks);
int apply_frequency_filters(double *magnitude_spectrum, int spectrum_size, 
                           frequency_filter_t *filters, int num_filters);

// Tone sequence management
int update_tone_sequence_state(tone_sequence_state_t *sequence, 
                               double current_time_ms, 
                               double detected_freq, 
                               double magnitude_db);
int check_sequence_timeout(tone_sequence_state_t *sequence, double current_time_ms);
int trigger_tone_playback(tone_definition_t *definition);
int start_recording(tone_definition_t *definition);

// Utility functions
double get_current_time_ms(void);
double bin_to_frequency(int bin_index);
int frequency_to_bin(double frequency);
double magnitude_to_db(double magnitude);
int is_frequency_in_range(double detected_freq, double target_freq, double tolerance);
int generate_tone_samples(float *samples, int sample_count, double frequency, double duration_ms, double sample_rate);

// Control functions
int enable_tone_detection(void);
int disable_tone_detection(void);
int set_passthrough_output_mode(int passthrough_mode);
int is_tone_detect_enabled(void);
int is_card1_input_enabled(void);
int is_passthrough_mode(void);

// Passthrough functions
int init_tone_passthrough_control(void);
int setup_tone_passthrough(int source_channel, int target_channel);
int start_tone_passthrough(void);
int stop_tone_passthrough(void);
int is_tone_passthrough_active(void);

// Helper functions for passthrough target channel
int get_passthrough_target_channel_index(void);
int channel_has_output_stream(int channel_index);
int repair_passthrough_output_stream(int channel_index);

// Audio passthrough functions
int init_audio_passthrough(void);
int start_audio_passthrough(int target_channel);
int stop_audio_passthrough(void);
void* audio_passthrough_thread(void *arg);
int tone_passthrough_callback(const void *input, void *output, unsigned long frames,
                              const PaStreamCallbackTimeInfo *time_info,
                              PaStreamCallbackFlags flags, void *user_data);

// Global flag for passthrough re-evaluation
extern int force_passthrough_reevaluation;

// Missing constants
#ifndef SAMPLE_RATE
#define SAMPLE_RATE 48000
#endif

#endif // TONE_DETECT_H
