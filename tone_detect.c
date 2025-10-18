#define _GNU_SOURCE
#include "tone_detect.h"
#include "audio.h"
#include "config.h"
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

// Global tone detection system instance
struct tone_detection_state global_tone_detection = {0};

// External references to audio system
extern struct shared_audio_buffer global_shared_buffer;
extern volatile int global_interrupted;

// Silence noisy logs while keeping confirmations
#define NOISY_LOG(...) do { (void)0; } while(0)

// Initialize the tone detection system
int init_tone_detection(void) {
    printf("[TONE] Initializing Goertzel-based tone detection system...\n");
    
    // Clear the system state
    memset(&global_tone_detection, 0, sizeof(struct tone_detection_state));
    
    // Initialize mutex
    if (pthread_mutex_init(&global_tone_detection.mutex, NULL) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize tone detection mutex\n");
        return 0;
    }
    
    // Set default configuration
    global_tone_detection.global_gain = 1.0f;
    global_tone_detection.global_threshold = 0.7f;
    global_tone_detection.detect_new_tones = 1;
    global_tone_detection.new_tone_threshold = 50;
    global_tone_detection.current_state = DETECT_STATE_IDLE;
    global_tone_detection.current_sequence_index = -1;
    
    // Initialize legacy compatibility fields
    global_tone_detection.config.threshold = 0.7f;
    global_tone_detection.config.gain = 0.4f;
    global_tone_detection.config.db_threshold = -45;
    global_tone_detection.config.detect_new_tones = 1;
    global_tone_detection.config.new_tone_length_ms = 1000;
    global_tone_detection.config.new_tone_range_hz = 3;
    global_tone_detection.config.valid = 1;
    
    // Initialize detection state
    global_tone_detection.current_tone_a_detected = 0;
    global_tone_detection.current_tone_b_detected = 0;
    global_tone_detection.tone_sequence_active = 0;
    global_tone_detection.recording_active = 0;
    
    global_tone_detection.tone_a_tracking = 0;
    global_tone_detection.tone_b_tracking = 0;
    global_tone_detection.tone_a_confirmed = 0;
    global_tone_detection.tone_b_confirmed = 0;
    global_tone_detection.tone_a_tracking_start = 0;
    global_tone_detection.tone_b_tracking_start = 0;
    
    global_tone_detection.active = 0;
    
    printf("[TONE] Tone detection system initialized successfully\n");
    return 1;
}

// Start the tone detection system
int start_tone_detection(void) {
    if (global_tone_detection.active) {
        printf("[WARNING] Tone detection system already active\n");
        return 1;
    }
    
    global_tone_detection.active = 1;
    global_tone_detection.should_stop = 0;
    
    if (pthread_create(&global_tone_detection.thread, NULL, 
                      tone_detection_thread, NULL) != 0) {
        fprintf(stderr, "[ERROR] Failed to create tone detection thread\n");
        global_tone_detection.active = 0;
        return 0;
    }
    
    printf("[TONE] Tone detection system started\n");
    return 1;
}

// Stop the tone detection system
void stop_tone_detection(void) {
    if (!global_tone_detection.active) {
        return;
    }
    
    printf("[TONE] Stopping tone detection system...\n");
    
    global_tone_detection.should_stop = 1;
    global_tone_detection.active = 0;
    
    // Signal the thread to wake up
    pthread_mutex_lock(&global_shared_buffer.mutex);
    pthread_cond_signal(&global_shared_buffer.data_ready);
    pthread_mutex_unlock(&global_shared_buffer.mutex);
    
    // Wait for thread to finish
    pthread_join(global_tone_detection.thread, NULL);
    
    printf("[TONE] Tone detection system stopped\n");
}

// Main tone detection thread
void* tone_detection_thread(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    printf("[TONE] Tone detection thread started\n");
    
    float audio_buffer[SAMPLES_PER_FRAME];
    int samples_processed = 0;
    
    while (global_tone_detection.active && !global_interrupted) {
        int samples_to_process = 0;
        
        pthread_mutex_lock(&global_shared_buffer.mutex);
        
        // Wait for new audio data
        while (!global_shared_buffer.valid && global_tone_detection.active && !global_interrupted) {
            pthread_cond_wait(&global_shared_buffer.data_ready, &global_shared_buffer.mutex);
        }
        
        if (global_shared_buffer.valid && global_tone_detection.active && !global_interrupted) {
            // Copy audio data for processing
            samples_to_process = global_shared_buffer.sample_count;
            if (samples_to_process > SAMPLES_PER_FRAME) {
                samples_to_process = SAMPLES_PER_FRAME;
            }
            
            for (int i = 0; i < samples_to_process; i++) {
                audio_buffer[i] = global_shared_buffer.samples[i];
            }
        }
        
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Process audio for tone detection
        if (samples_to_process > 0) {
            // Apply global gain
            for (int i = 0; i < samples_to_process; i++) {
                audio_buffer[i] *= global_tone_detection.global_gain;
            }
            
            // Apply audio filters
            apply_audio_filters(audio_buffer, samples_to_process);
            
            // Process audio samples
            process_audio_samples(audio_buffer, samples_to_process);
            
            samples_processed += samples_to_process;
            
            // Print statistics occasionally
            if (samples_processed % 50000 == 0) {
                static int stats_count = 0;
                if (stats_count++ % 30 == 0) {
                    print_detection_status();
                }
            }
        }
        
        // Small delay to prevent overwhelming the system
        usleep(1000); // 1ms delay
    }
    
    printf("[TONE] Tone detection thread stopped\n");
    return NULL;
}

// Process audio samples for tone detection
int process_audio_samples(const float* samples, int sample_count) {
    // Update all Goertzel filters
    update_goertzel_filters(samples, sample_count);
    
    // Check for tone sequences
    check_tone_sequences();
    
    return 1;
}

// Update Goertzel filters with new audio samples
int update_goertzel_filters(const float* samples, int sample_count) {
    for (int i = 0; i < global_tone_detection.active_filter_count; i++) {
        struct goertzel_filter* filter = &global_tone_detection.goertzel_filters[i];
        
        if (!filter->valid) {
            continue;
        }
        
        // Process each sample
        for (int j = 0; j < sample_count; j++) {
            update_goertzel_filter(filter, samples[j]);
        }
        
        // Check if filter is ready for detection
        if (is_goertzel_filter_ready(filter)) {
            float magnitude = get_goertzel_magnitude(filter);
            
            // Check if magnitude exceeds threshold
            if (magnitude > filter->threshold) {
                if (!filter->is_active) {
                    // Start tracking this tone
                    filter->is_active = 1;
                    filter->tracking_start_time = get_timestamp_ms();
                    printf("[TONE] Tone %s detected: %.1f Hz (magnitude: %.3f)\n", 
                           filter->filter_id, filter->target_frequency, magnitude);
                }
            } else {
                if (filter->is_active) {
                    // Stop tracking this tone
                    filter->is_active = 0;
                    filter->confirmed = 0;
                    printf("[TONE] Tone %s lost: %.1f Hz\n", 
                           filter->filter_id, filter->target_frequency);
                }
            }
        }
    }
    
    return 1;
}

// Check for tone sequences
int check_tone_sequences(void) {
    uint64_t current_time = get_timestamp_ms();
    
    for (int i = 0; i < global_tone_detection.active_sequence_count; i++) {
        struct tone_sequence* sequence = &global_tone_detection.tone_sequences[i];
        
        if (!sequence->valid) {
            continue;
        }
        
        switch (global_tone_detection.current_state) {
            case DETECT_STATE_IDLE:
                // Look for tone A
                if (sequence->tone_a.is_active && !sequence->tone_a.confirmed) {
                    // Check if tone A has been present long enough
                    if (current_time - sequence->tone_a.tracking_start_time >= sequence->tone_a.min_duration_ms) {
                        sequence->tone_a.confirmed = 1;
                        global_tone_detection.current_state = DETECT_STATE_TONE_A;
                        global_tone_detection.current_sequence_index = i;
                        global_tone_detection.sequence_start_time = current_time;
                        global_tone_detection.tone_a_detections++;
                        
                        // Update legacy fields
                        global_tone_detection.tone_a_confirmed = 1;
                        global_tone_detection.current_tone_a_detected = 1;
                        global_tone_detection.tone_sequence_active = 1;
                        
                        printf("[TONE] Tone A confirmed in sequence %s: %.1f Hz\n", 
                               sequence->sequence_id, sequence->tone_a.target_frequency);
                    }
                }
                break;
                
            case DETECT_STATE_TONE_A:
                // Look for tone B (only if we're tracking the right sequence)
                if (global_tone_detection.current_sequence_index == i) {
                    if (sequence->tone_b.is_active && !sequence->tone_b.confirmed) {
                        // Check if tone B has been present long enough
                        if (current_time - sequence->tone_b.tracking_start_time >= sequence->tone_b.min_duration_ms) {
                            sequence->tone_b.confirmed = 1;
                            global_tone_detection.current_state = DETECT_STATE_RECORDING;
                            global_tone_detection.tone_b_detections++;
                            global_tone_detection.sequence_detections++;
                            
                            // Update legacy fields
                            global_tone_detection.tone_b_confirmed = 1;
                            global_tone_detection.current_tone_b_detected = 1;
                            global_tone_detection.recording_active = 1;
                            global_tone_detection.recording_start_time = current_time;
                            
                            printf("[TONE] Tone B confirmed in sequence %s: %.1f Hz\n", 
                                   sequence->sequence_id, sequence->tone_b.target_frequency);
                            printf("[TONE] Complete sequence detected! Starting recording...\n");
                            
                            // Trigger passthrough
                            trigger_tone_passthrough();
                        }
                    }
                    
                    // Check for timeout
                    if (current_time - global_tone_detection.sequence_start_time > sequence->sequence_timeout_ms) {
                        printf("[TONE] Sequence %s timed out\n", sequence->sequence_id);
                        reset_sequence_detection();
                    }
                }
                break;
                
            case DETECT_STATE_RECORDING:
                // Check if recording should stop
                if (global_tone_detection.current_sequence_index == i) {
                    if (current_time - global_tone_detection.sequence_start_time > sequence->record_duration_ms) {
                        printf("[TONE] Recording completed for sequence %s\n", sequence->sequence_id);
                        global_tone_detection.recording_active = 0;
                        reset_sequence_detection();
                    }
                }
                break;
                
            case DETECT_STATE_TIMEOUT:
                // Reset after timeout
                reset_sequence_detection();
                break;
        }
    }
    
    return 1;
}

// Initialize a Goertzel filter
int init_goertzel_filter(struct goertzel_filter* filter, float frequency, 
                        float threshold, int window_size, int min_duration_ms) {
    if (!filter) {
        return 0;
    }
    
    filter->target_frequency = frequency;
    filter->threshold = threshold;
    filter->window_size = window_size;
    filter->min_duration_ms = min_duration_ms;
    filter->coeff = frequency_to_goertzel_coeff(frequency, SAMPLE_RATE);
    filter->q1 = 0.0f;
    filter->q2 = 0.0f;
    filter->magnitude = 0.0f;
    filter->samples_processed = 0;
    filter->is_active = 0;
    filter->confirmed = 0;
    filter->tracking_start_time = 0;
    filter->valid = 1;
    
    return 1;
}

// Update a Goertzel filter with a new sample
int update_goertzel_filter(struct goertzel_filter* filter, float sample) {
    if (!filter || !filter->valid) {
        return 0;
    }
    
    // Goertzel algorithm update
    float q0 = filter->coeff * filter->q1 - filter->q2 + sample;
    filter->q2 = filter->q1;
    filter->q1 = q0;
    filter->samples_processed++;
    
    // Calculate magnitude when window is complete
    if (filter->samples_processed >= filter->window_size) {
        float magnitude_squared = filter->q1 * filter->q1 + filter->q2 * filter->q2 - 
                                 filter->coeff * filter->q1 * filter->q2;
        filter->magnitude = sqrtf(fabsf(magnitude_squared)) / filter->window_size;
        
        // Reset for next window
        filter->q1 = 0.0f;
        filter->q2 = 0.0f;
        filter->samples_processed = 0;
    }
    
    return 1;
}

// Get the current magnitude of a Goertzel filter
float get_goertzel_magnitude(const struct goertzel_filter* filter) {
    if (!filter || !filter->valid) {
        return 0.0f;
    }
    return filter->magnitude;
}

// Check if a Goertzel filter is ready for detection
int is_goertzel_filter_ready(const struct goertzel_filter* filter) {
    if (!filter || !filter->valid) {
        return 0;
    }
    return (filter->samples_processed == 0 && filter->magnitude > 0.0f);
}

// Add a tone sequence
int add_tone_sequence(const char* sequence_id, 
                     float tone_a_freq, int tone_a_duration_ms, int tone_a_range_hz,
                     float tone_b_freq, int tone_b_duration_ms, int tone_b_range_hz,
                     int sequence_timeout_ms, int record_duration_ms) {
    
    if (global_tone_detection.active_sequence_count >= MAX_TONE_DEFINITIONS) {
        fprintf(stderr, "[ERROR] No space for new tone sequence\n");
        return 0;
    }
    
    int seq_index = global_tone_detection.active_sequence_count;
    struct tone_sequence* sequence = &global_tone_detection.tone_sequences[seq_index];
    
    // Initialize sequence
    strncpy(sequence->sequence_id, sequence_id, 63);
    sequence->sequence_id[63] = '\0';
    sequence->sequence_timeout_ms = sequence_timeout_ms;
    sequence->record_duration_ms = record_duration_ms;
    sequence->valid = 1;
    
    // Initialize tone A filter
    int filter_a_index = global_tone_detection.active_filter_count++;
    struct goertzel_filter* filter_a = &global_tone_detection.goertzel_filters[filter_a_index];
    snprintf(filter_a->filter_id, 63, "%s_tone_a", sequence_id);
    init_goertzel_filter(filter_a, tone_a_freq, global_tone_detection.global_threshold, 
                        SAMPLE_RATE / 10, tone_a_duration_ms); // 100ms window
    
    // Initialize tone B filter
    int filter_b_index = global_tone_detection.active_filter_count++;
    struct goertzel_filter* filter_b = &global_tone_detection.goertzel_filters[filter_b_index];
    snprintf(filter_b->filter_id, 63, "%s_tone_b", sequence_id);
    init_goertzel_filter(filter_b, tone_b_freq, global_tone_detection.global_threshold, 
                        SAMPLE_RATE / 10, tone_b_duration_ms); // 100ms window
    
    // Link filters to sequence
    sequence->tone_a = *filter_a;
    sequence->tone_b = *filter_b;
    
    global_tone_detection.active_sequence_count++;
    
    printf("[TONE] Added tone sequence: %s (A: %.1f Hz, B: %.1f Hz)\n", 
           sequence_id, tone_a_freq, tone_b_freq);
    
    return 1;
}

// Remove a tone sequence
int remove_tone_sequence(const char* sequence_id) {
    for (int i = 0; i < global_tone_detection.active_sequence_count; i++) {
        if (strcmp(global_tone_detection.tone_sequences[i].sequence_id, sequence_id) == 0) {
            global_tone_detection.tone_sequences[i].valid = 0;
            
            // Remove associated filters
            for (int j = 0; j < global_tone_detection.active_filter_count; j++) {
                if (strstr(global_tone_detection.goertzel_filters[j].filter_id, sequence_id) != NULL) {
                    global_tone_detection.goertzel_filters[j].valid = 0;
                }
            }
            
            printf("[TONE] Removed tone sequence: %s\n", sequence_id);
            return 1;
        }
    }
    
    return 0;
}

// Find a tone sequence by ID
int find_tone_sequence(const char* sequence_id) {
    for (int i = 0; i < global_tone_detection.active_sequence_count; i++) {
        if (global_tone_detection.tone_sequences[i].valid && 
            strcmp(global_tone_detection.tone_sequences[i].sequence_id, sequence_id) == 0) {
            return i;
        }
    }
    return -1;
}

// Apply audio filters
int apply_audio_filters(float* samples, int sample_count) {
    for (int i = 0; i < global_tone_detection.active_audio_filter_count; i++) {
        struct audio_filter* filter = &global_tone_detection.audio_filters[i];
        
        if (!filter->valid) {
            continue;
        }
        
        switch (filter->filter_type) {
            case 0: // Lowpass
                apply_lowpass_filter(samples, sample_count, filter->cutoff_frequency);
                break;
            case 1: // Highpass
                apply_highpass_filter(samples, sample_count, filter->cutoff_frequency);
                break;
            case 2: // Bandpass
                apply_bandpass_filter(samples, sample_count, filter->cutoff_frequency, filter->range_hz);
                break;
        }
    }
    
    return 1;
}

// Apply lowpass filter (simple moving average)
int apply_lowpass_filter(float* samples, int count, float cutoff_freq) {
    // Simple moving average lowpass filter
    int window_size = (int)(SAMPLE_RATE / (2.0f * cutoff_freq));
    if (window_size < 2) window_size = 2;
    if (window_size > count) window_size = count;
    
    float sum = 0.0f;
            for (int i = 0; i < count; i++) {
        sum += samples[i];
        if (i >= window_size) {
            sum -= samples[i - window_size];
                }
        samples[i] = sum / (float)window_size;
    }
    
    return 1;
}

// Apply highpass filter (simple difference)
int apply_highpass_filter(float* samples, int count, float cutoff_freq) {
    // Simple highpass filter using difference
    float alpha = 1.0f / (1.0f + cutoff_freq / (2.0f * M_PI * SAMPLE_RATE));
    
    static float prev_input = 0.0f;
    static float prev_output = 0.0f;
    
    for (int i = 0; i < count; i++) {
        float output = alpha * (prev_output + samples[i] - prev_input);
        prev_input = samples[i];
        prev_output = output;
        samples[i] = output;
    }
    
    return 1;
}

// Apply bandpass filter (combination of lowpass and highpass)
int apply_bandpass_filter(float* samples, int count, float center_freq, int range_hz) {
    float low_cutoff = center_freq - range_hz / 2.0f;
    float high_cutoff = center_freq + range_hz / 2.0f;
    
    if (low_cutoff > 0) {
        apply_highpass_filter(samples, count, low_cutoff);
    }
    if (high_cutoff < SAMPLE_RATE / 2.0f) {
        apply_lowpass_filter(samples, count, high_cutoff);
    }
    
    return 1;
}

// Add audio filter
int add_audio_filter(const char* filter_id, float cutoff_freq, int filter_type, int range_hz) {
    if (global_tone_detection.active_audio_filter_count >= MAX_FILTERS) {
        fprintf(stderr, "[ERROR] No space for new audio filter\n");
        return 0;
    }
    
    int index = global_tone_detection.active_audio_filter_count++;
    struct audio_filter* filter = &global_tone_detection.audio_filters[index];
    
    strncpy(filter->filter_id, filter_id, 63);
    filter->filter_id[63] = '\0';
    filter->cutoff_frequency = cutoff_freq;
    filter->filter_type = filter_type;
    filter->range_hz = range_hz;
    filter->valid = 1;
    
    printf("[TONE] Added audio filter: %s (%.1f Hz, type %d)\n", 
           filter_id, cutoff_freq, filter_type);
    
    return 1;
}

// Remove audio filter
int remove_audio_filter(const char* filter_id) {
    for (int i = 0; i < global_tone_detection.active_audio_filter_count; i++) {
        if (strcmp(global_tone_detection.audio_filters[i].filter_id, filter_id) == 0) {
            global_tone_detection.audio_filters[i].valid = 0;
            printf("[TONE] Removed audio filter: %s\n", filter_id);
            return 1;
        }
    }
    return 0;
}

// Configuration functions
int set_global_gain(float gain) {
    global_tone_detection.global_gain = gain;
    global_tone_detection.config.gain = gain;
    printf("[TONE] Global gain set to %.2f\n", gain);
    return 1;
}

int set_global_threshold(float threshold) {
    global_tone_detection.global_threshold = threshold;
    global_tone_detection.config.threshold = threshold;
    printf("[TONE] Global threshold set to %.2f\n", threshold);
    return 1;
}

int set_new_tone_detection(int enabled, int threshold) {
    global_tone_detection.detect_new_tones = enabled;
    global_tone_detection.new_tone_threshold = threshold;
    global_tone_detection.config.detect_new_tones = enabled;
    printf("[TONE] New tone detection: %s (threshold: %d)\n", 
           enabled ? "enabled" : "disabled", threshold);
    return 1;
}

int get_detection_statistics(int* total, int* tone_a, int* tone_b, int* sequences, int* new_tones) {
    if (total) *total = global_tone_detection.total_detections;
    if (tone_a) *tone_a = global_tone_detection.tone_a_detections;
    if (tone_b) *tone_b = global_tone_detection.tone_b_detections;
    if (sequences) *sequences = global_tone_detection.sequence_detections;
    if (new_tones) *new_tones = global_tone_detection.new_tone_detections;
    return 1;
}

void reset_detection_statistics(void) {
    global_tone_detection.total_detections = 0;
    global_tone_detection.tone_a_detections = 0;
    global_tone_detection.tone_b_detections = 0;
    global_tone_detection.sequence_detections = 0;
    global_tone_detection.new_tone_detections = 0;
    printf("[TONE] Detection statistics reset\n");
}

// Reset sequence detection
void reset_sequence_detection(void) {
    global_tone_detection.current_state = DETECT_STATE_IDLE;
    global_tone_detection.current_sequence_index = -1;
    global_tone_detection.sequence_start_time = 0;
    
    // Reset legacy fields
    global_tone_detection.tone_a_tracking = 0;
    global_tone_detection.tone_b_tracking = 0;
    global_tone_detection.tone_a_confirmed = 0;
    global_tone_detection.tone_b_confirmed = 0;
    global_tone_detection.tone_a_tracking_start = 0;
    global_tone_detection.tone_b_tracking_start = 0;
    global_tone_detection.current_tone_a_detected = 0;
    global_tone_detection.current_tone_b_detected = 0;
    global_tone_detection.tone_sequence_active = 0;
    global_tone_detection.recording_active = 0;
    
    // Reset all sequence filters
    for (int i = 0; i < global_tone_detection.active_sequence_count; i++) {
        struct tone_sequence* seq = &global_tone_detection.tone_sequences[i];
        if (seq->valid) {
            seq->tone_a.confirmed = 0;
            seq->tone_b.confirmed = 0;
            seq->tone_a.is_active = 0;
            seq->tone_b.is_active = 0;
        }
    }
}

// Utility functions
float frequency_to_goertzel_coeff(float frequency, int sample_rate) {
    return 2.0f * cosf(2.0f * M_PI * frequency / sample_rate);
}

int is_frequency_in_range(float freq, float target, int range) {
    return (freq >= target - range && freq <= target + range);
}

uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void print_detection_status(void) {
    printf("[TONE] Status: Sequences=%d, Filters=%d, State=%d, Total=%d, A=%d, B=%d, Seq=%d\n",
           global_tone_detection.active_sequence_count,
           global_tone_detection.active_filter_count,
           global_tone_detection.current_state,
           global_tone_detection.total_detections,
           global_tone_detection.tone_a_detections,
           global_tone_detection.tone_b_detections,
           global_tone_detection.sequence_detections);
}

// Legacy compatibility functions
int analyze_frequency_spectrum(float* audio_samples, int sample_count) {
    // The new system handles this internally
    (void)audio_samples;
    (void)sample_count;
    return 1;
}

int detect_tone_sequence(float* audio_samples, int sample_count) {
    // The new system handles this internally
    (void)audio_samples;
    (void)sample_count;
    return 1;
}

int check_tone_definition(float frequency, struct tone_definition* tone_def, int is_tone_b) {
    // The new system handles this internally
    (void)frequency;
    (void)tone_def;
    (void)is_tone_b;
    return 0;
}

int apply_frequency_filters(float* magnitudes, int count) {
    // The new system handles this internally
    (void)magnitudes;
    (void)count;
    return 1;
}

int apply_audio_frequency_filters(float* audio_samples, int sample_count) {
    // The new system handles this internally
    (void)audio_samples;
    (void)sample_count;
    return 1;
}

int check_tone_duration(int tone_type, int current_time, struct tone_definition* tone_def) {
    // The new system handles this internally
    (void)tone_type;
    (void)current_time;
    (void)tone_def;
    return 0;
}

void reset_tone_tracking(void) {
    reset_sequence_detection();
}

int detect_new_tones(float* magnitudes, int count) {
    // The new system handles this internally
    (void)magnitudes;
    (void)count;
    return 1;
}

float frequency_to_bin(float frequency) {
    return (frequency * 4096) / SAMPLE_RATE; // Using 4096 as FFT_SIZE equivalent
}

float bin_to_frequency(int bin) {
    return (bin * SAMPLE_RATE) / 4096; // Using 4096 as FFT_SIZE equivalent
}

float calculate_magnitude(double complex complex_val) {
    return sqrt(creal(complex_val) * creal(complex_val) + cimag(complex_val) * cimag(complex_val));
}

void print_tone_detection_stats(void) {
    int total, tone_a, tone_b, sequences, new_tones;
    get_detection_statistics(&total, &tone_a, &tone_b, &sequences, &new_tones);
    
    if (total > 0 || tone_a > 0 || tone_b > 0 || new_tones > 0) {
        printf("[TONE STATS] Total: %d, Tone A: %d, Tone B: %d, Sequences: %d, New: %d\n",
               total, tone_a, tone_b, sequences, new_tones);
    }
}

void reset_tone_detection_stats(void) {
    reset_detection_statistics();
}

// Trigger tone passthrough when tones are detected
void trigger_tone_passthrough(void) {
    // Check if tone passthrough is configured for channel 1 (index 0)
    struct tone_detect_config* tone_config = get_tone_detect_config(0); // Channel 1
    
    if (tone_config && tone_config->tone_passthrough) {
        // Check if the target channel has a working output stream
        int target_channel_idx = get_passthrough_target_channel_index();
        if (target_channel_idx >= 0 && target_channel_idx < MAX_CHANNELS) {
            if (channel_has_output_stream(target_channel_idx)) {
                printf("[TONE PASSTHROUGH] Tone detected, activating passthrough\n");
                // Enable passthrough mode; audio.c routes to the configured target from JSON
                set_passthrough_output_mode(1);
            } else {
                printf("[TONE PASSTHROUGH] Tone detected but target channel has no output stream\n");
                printf("[TONE PASSTHROUGH] Using software passthrough instead\n");
                set_passthrough_output_mode(1);
            }
        } else {
            printf("[TONE PASSTHROUGH] Tone detected but invalid target channel index - passthrough disabled\n");
        }
    } else {
        printf("[TONE PASSTHROUGH] Tone passthrough not configured or not enabled\n");
    }
}

// Configuration functions (compatibility)
int add_tone_definition(const char* tone_id, float tone_a_freq, float tone_b_freq,
                       int tone_a_length, int tone_b_length, int tone_a_range, int tone_b_range,
                       int record_length) {
    printf("[TONE] Adding tone definition: %s (A: %.1f Hz, B: %.1f Hz)\n", 
           tone_id, tone_a_freq, tone_b_freq);
    
    // Find an empty slot in the legacy system
    int old_index = -1;
    for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
        if (!global_tone_detection.tone_definitions[i].valid) {
            old_index = i;
            break;
        }
    }
    
    if (old_index == -1) {
        fprintf(stderr, "[ERROR] No space for new tone definition\n");
        return 0;
    }
    
    // Add to legacy system for compatibility
    struct tone_definition* old_def = &global_tone_detection.tone_definitions[old_index];
    strncpy(old_def->tone_id, tone_id, 63);
    old_def->tone_id[63] = '\0';
    old_def->tone_a_freq = tone_a_freq;
    old_def->tone_b_freq = tone_b_freq;
    old_def->tone_a_length_ms = tone_a_length;
    old_def->tone_b_length_ms = tone_b_length;
    old_def->tone_a_range_hz = tone_a_range;
    old_def->tone_b_range_hz = tone_b_range;
    old_def->record_length_ms = record_length;
    old_def->valid = 1;
    
    // Add to new system
    int new_index = add_tone_sequence(tone_id, tone_a_freq, tone_a_length, tone_a_range,
                                    tone_b_freq, tone_b_length, tone_b_range,
                                    5000, record_length); // 5 second timeout
    
    if (new_index) {
        printf("[TONE] Mapped legacy definition to new sequence\n");
    }
    
    return 1;
}

int add_frequency_filter(const char* filter_id, float frequency, int range, const char* type) {
    printf("[TONE] Adding frequency filter: %s (%.1f Hz, %s)\n", 
           filter_id, frequency, type);
    
    // Find an empty slot in the legacy system
    int old_index = -1;
    for (int i = 0; i < MAX_FILTERS; i++) {
        if (!global_tone_detection.filters[i].valid) {
            old_index = i;
            break;
        }
    }
    
    if (old_index == -1) {
    fprintf(stderr, "[ERROR] No space for new frequency filter\n");
    return 0;
    }
    
    // Add to legacy system for compatibility
    struct frequency_filter* old_filter = &global_tone_detection.filters[old_index];
    strncpy(old_filter->filter_id, filter_id, 63);
    old_filter->filter_id[63] = '\0';
    old_filter->frequency = frequency;
    old_filter->filter_range_hz = range;
    strncpy(old_filter->type, type, 15);
    old_filter->type[15] = '\0';
    old_filter->valid = 1;
    
    // Add to new system
    int filter_type = 0; // Default to lowpass
    if (strcmp(type, "highpass") == 0) {
        filter_type = 1;
    } else if (strcmp(type, "center") == 0) {
        filter_type = 2; // Bandpass
    }
    
    int new_index = add_audio_filter(filter_id, frequency, filter_type, range);
    
    if (new_index) {
        printf("[TONE] Mapped legacy filter to new audio filter\n");
    }
    
    return 1;
}

int set_tone_config(float threshold, float gain, int db_threshold, int detect_new_tones,
                   int new_tone_length, int new_tone_range) {
    // Update legacy system
    global_tone_detection.config.threshold = threshold;
    global_tone_detection.config.gain = gain;
    global_tone_detection.config.db_threshold = db_threshold;
    global_tone_detection.config.detect_new_tones = detect_new_tones;
    global_tone_detection.config.new_tone_length_ms = new_tone_length;
    global_tone_detection.config.new_tone_range_hz = new_tone_range;
    
    // Update new system
    set_global_gain(gain);
    set_global_threshold(threshold);
    set_new_tone_detection(detect_new_tones, 50); // Default threshold
    
    printf("[TONE] Updated configuration: threshold=%.2f, gain=%.2f, db=%d\n",
           threshold, gain, db_threshold);
    return 1;
}