#include "tone_detect.h"
#include "audio.h"
#include <math.h>
#include <string.h>
#include <time.h>

// Global tone detection state
struct tone_detection_state global_tone_detection = {0};

// Initialize tone detection system
int init_tone_detection(void) {
    memset(&global_tone_detection, 0, sizeof(struct tone_detection_state));
    
    // Initialize FFT
    global_tone_detection.fft_plan = fftw_plan_dft_r2c_1d(FFT_SIZE, 
                                                         global_tone_detection.fft_input,
                                                         global_tone_detection.fft_output,
                                                         FFTW_ESTIMATE);
    
    if (!global_tone_detection.fft_plan) {
        fprintf(stderr, "[ERROR] Failed to create FFT plan\n");
        return 0;
    }
    
    // Initialize mutex
    pthread_mutex_init(&global_tone_detection.mutex, NULL);
    
    // Set default configuration
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
    
    global_tone_detection.active = 0;
    
    printf("[INFO] Tone detection system initialized\n");
    return 1;
}

// Start tone detection thread
int start_tone_detection(void) {
    if (global_tone_detection.active) {
        printf("[WARNING] Tone detection already active\n");
        return 1;
    }
    
    global_tone_detection.active = 1;
    
    if (pthread_create(&global_tone_detection.thread, NULL, tone_detection_thread, NULL)) {
        fprintf(stderr, "[ERROR] Failed to create tone detection thread\n");
        global_tone_detection.active = 0;
        return 0;
    }
    
    printf("[INFO] Tone detection thread started\n");
    return 1;
}

// Stop tone detection thread
void stop_tone_detection(void) {
    if (!global_tone_detection.active) {
        return;
    }
    
    global_tone_detection.active = 0;
    
    // Signal the thread to wake up
    pthread_mutex_lock(&global_shared_buffer.mutex);
    pthread_cond_signal(&global_shared_buffer.data_ready);
    pthread_mutex_unlock(&global_shared_buffer.mutex);
    
    // Wait for thread to finish
    pthread_join(global_tone_detection.thread, NULL);
    
    printf("[INFO] Tone detection thread stopped\n");
}

// Main tone detection thread
void* tone_detection_thread(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    printf("[INFO] Tone detection thread started\n");
    
    float audio_buffer[SAMPLES_PER_FRAME];
    int samples_processed = 0;
    
    while (global_tone_detection.active && !global_interrupted) {
        int samples_to_process = 0;
        
        // Only process if tone detection is enabled
        if (!is_tone_detect_enabled()) {
            usleep(10000); // 10ms delay when tone detection is disabled
            continue;
        }
        
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
            // Apply gain
            for (int i = 0; i < samples_to_process; i++) {
                audio_buffer[i] *= global_tone_detection.config.gain;
            }
            
            // Analyze frequency spectrum
            if (analyze_frequency_spectrum(audio_buffer, samples_to_process)) {
                // Detect tone sequences
                detect_tone_sequence(audio_buffer, samples_to_process);
            }
            
            samples_processed += samples_to_process;
            
            // Print statistics every 1000 samples
            if (samples_processed % 1000 == 0) {
                static int stats_count = 0;
                if (stats_count++ % 10 == 0) {
                    print_tone_detection_stats();
                }
            }
        }
        
        // Small delay to prevent overwhelming the system
        usleep(1000); // 1ms delay
    }
    
    printf("[INFO] Tone detection thread stopped\n");
    return NULL;
}

// Analyze frequency spectrum using FFT
int analyze_frequency_spectrum(float* audio_samples, int sample_count) {
    if (sample_count < FFT_SIZE) {
        return 0; // Not enough samples for FFT
    }
    
    // Prepare FFT input (use first FFT_SIZE samples)
    for (int i = 0; i < FFT_SIZE; i++) {
        global_tone_detection.fft_input[i] = (double)audio_samples[i];
    }
    
    // Apply window function (Hanning window)
    for (int i = 0; i < FFT_SIZE; i++) {
        double window = 0.5 * (1.0 - cos(2.0 * M_PI * i / (FFT_SIZE - 1)));
        global_tone_detection.fft_input[i] *= window;
    }
    
    // Perform FFT
    fftw_execute(global_tone_detection.fft_plan);
    
    // Calculate magnitude spectrum
    global_tone_detection.peak_count = 0;
    float max_magnitude = 0.0f;
    
    for (int i = 0; i < FREQ_BINS; i++) {
        float magnitude = calculate_magnitude(global_tone_detection.fft_output[i]);
        global_tone_detection.frequency_magnitudes[i] = magnitude;
        
        if (magnitude > max_magnitude) {
            max_magnitude = magnitude;
        }
    }
    
    // Find peak frequencies
    for (int i = 1; i < FREQ_BINS - 1; i++) {
        float current = global_tone_detection.frequency_magnitudes[i];
        float prev = global_tone_detection.frequency_magnitudes[i-1];
        float next = global_tone_detection.frequency_magnitudes[i+1];
        
        // Check if this is a peak
        if (current > prev && current > next && current > max_magnitude * 0.1f) {
            if (global_tone_detection.peak_count < 10) {
                global_tone_detection.peak_frequencies[global_tone_detection.peak_count] = 
                    bin_to_frequency(i);
                global_tone_detection.peak_count++;
            }
        }
    }
    
    // Apply frequency filters
    apply_frequency_filters(global_tone_detection.frequency_magnitudes, FREQ_BINS);
    
    return 1;
}

// Detect tone sequences
int detect_tone_sequence(float* audio_samples, int sample_count) {
    (void)audio_samples; // Suppress unused parameter warning
    (void)sample_count;  // Suppress unused parameter warning
    
    int current_time = (int)(time(NULL) * 1000); // Current time in milliseconds
    
    // Check each tone definition
    for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
        struct tone_definition* tone_def = &global_tone_detection.tone_definitions[i];
        
        if (!tone_def->valid) {
            continue;
        }
        
        // Check for tone A
        if (!global_tone_detection.current_tone_a_detected) {
            if (check_tone_definition(tone_def->tone_a_freq, tone_def, 0)) {
                global_tone_detection.current_tone_a_detected = 1;
                global_tone_detection.tone_a_start_time = current_time;
                global_tone_detection.tone_sequence_active = 1;
                printf("[TONE] Tone A detected: %.1f Hz (ID: %s)\n", 
                       tone_def->tone_a_freq, tone_def->tone_id);
                global_tone_detection.tone_a_detections++;
            }
        }
        // Check for tone B (only if tone A was detected)
        else if (!global_tone_detection.current_tone_b_detected) {
            if (check_tone_definition(tone_def->tone_b_freq, tone_def, 1)) {
                global_tone_detection.current_tone_b_detected = 1;
                global_tone_detection.tone_b_start_time = current_time;
                printf("[TONE] Tone B detected: %.1f Hz (ID: %s)\n", 
                       tone_def->tone_b_freq, tone_def->tone_id);
                global_tone_detection.tone_b_detections++;
                
                // Start recording
                global_tone_detection.recording_active = 1;
                global_tone_detection.recording_start_time = current_time;
                printf("[TONE] Recording started for %d ms\n", tone_def->record_length_ms);
                
                global_tone_detection.total_detections++;
            }
        }
    }
    
    // Check for new tone detection
    if (global_tone_detection.config.detect_new_tones) {
        detect_new_tones(global_tone_detection.frequency_magnitudes, FREQ_BINS);
    }
    
    // Check if recording should stop
    if (global_tone_detection.recording_active) {
        for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
            struct tone_definition* tone_def = &global_tone_detection.tone_definitions[i];
            if (tone_def->valid && 
                current_time - global_tone_detection.recording_start_time >= tone_def->record_length_ms) {
                global_tone_detection.recording_active = 0;
                printf("[TONE] Recording stopped\n");
                break;
            }
        }
    }
    
    // Reset sequence if tones are too old
    if (global_tone_detection.tone_sequence_active) {
        int time_since_tone_a = current_time - global_tone_detection.tone_a_start_time;
        if (time_since_tone_a > 5000) { // 5 second timeout
            global_tone_detection.current_tone_a_detected = 0;
            global_tone_detection.current_tone_b_detected = 0;
            global_tone_detection.tone_sequence_active = 0;
            global_tone_detection.recording_active = 0;
        }
    }
    
    return 1;
}

// Check if a specific tone definition matches current frequencies
int check_tone_definition(float frequency, struct tone_definition* tone_def, int is_tone_b) {
    int range = is_tone_b ? tone_def->tone_b_range_hz : tone_def->tone_a_range_hz;
    
    // Check if the target frequency is present in peak frequencies
    for (int i = 0; i < global_tone_detection.peak_count; i++) {
        if (is_frequency_in_range(global_tone_detection.peak_frequencies[i], frequency, range)) {
            return 1;
        }
    }
    
    return 0;
}

// Apply frequency filters
int apply_frequency_filters(float* magnitudes, int count) {
    for (int f = 0; f < MAX_FILTERS; f++) {
        struct frequency_filter* filter = &global_tone_detection.filters[f];
        
        if (!filter->valid) {
            continue;
        }
        
        int target_bin = (int)frequency_to_bin(filter->frequency);
        
        if (strcmp(filter->type, "below") == 0) {
            // Remove frequencies below the target
            for (int i = 0; i < target_bin; i++) {
                magnitudes[i] *= 0.1f; // Reduce magnitude
            }
        } else if (strcmp(filter->type, "above") == 0) {
            // Remove frequencies above the target
            for (int i = target_bin; i < count; i++) {
                magnitudes[i] *= 0.1f; // Reduce magnitude
            }
        } else if (strcmp(filter->type, "center") == 0) {
            // Keep only frequencies around the target
            for (int i = 0; i < count; i++) {
                if (abs(i - target_bin) > filter->filter_range_hz) {
                    magnitudes[i] *= 0.1f; // Reduce magnitude
                }
            }
        }
    }
    
    return 1;
}

// Detect new tones
int detect_new_tones(float* magnitudes, int count) {
    // Simple new tone detection - look for strong peaks not in defined tones
    for (int i = 0; i < global_tone_detection.peak_count; i++) {
        float freq = global_tone_detection.peak_frequencies[i];
        int is_known_tone = 0;
        
        // Check if this frequency matches any defined tone
        for (int j = 0; j < MAX_TONE_DEFINITIONS; j++) {
            struct tone_definition* tone_def = &global_tone_detection.tone_definitions[j];
            if (tone_def->valid) {
                if (is_frequency_in_range(freq, tone_def->tone_a_freq, tone_def->tone_a_range_hz) ||
                    is_frequency_in_range(freq, tone_def->tone_b_freq, tone_def->tone_b_range_hz)) {
                    is_known_tone = 1;
                    break;
                }
            }
        }
        
        if (!is_known_tone) {
            // This is a new tone
            if (global_tone_detection.detected_frequency_count < 100) {
                global_tone_detection.detected_frequencies[global_tone_detection.detected_frequency_count] = freq;
                global_tone_detection.detected_frequency_count++;
                global_tone_detection.new_tone_detections++;
                printf("[NEW TONE] Detected unknown frequency: %.1f Hz\n", freq);
            }
        }
    }
    
    return 1;
}

// Utility functions
float frequency_to_bin(float frequency) {
    return (frequency * FFT_SIZE) / SAMPLE_RATE;
}

float bin_to_frequency(int bin) {
    return (bin * SAMPLE_RATE) / FFT_SIZE;
}

float calculate_magnitude(fftw_complex complex_val) {
    return sqrt(complex_val[0] * complex_val[0] + complex_val[1] * complex_val[1]);
}

int is_frequency_in_range(float freq, float target, int range) {
    return (freq >= target - range && freq <= target + range);
}

// Statistics functions
void print_tone_detection_stats(void) {
    printf("[TONE STATS] Total: %d, Tone A: %d, Tone B: %d, New: %d\n",
           global_tone_detection.total_detections,
           global_tone_detection.tone_a_detections,
           global_tone_detection.tone_b_detections,
           global_tone_detection.new_tone_detections);
}

void reset_tone_detection_stats(void) {
    global_tone_detection.total_detections = 0;
    global_tone_detection.tone_a_detections = 0;
    global_tone_detection.tone_b_detections = 0;
    global_tone_detection.new_tone_detections = 0;
}

// Configuration functions
int add_tone_definition(const char* tone_id, float tone_a_freq, float tone_b_freq,
                       int tone_a_length, int tone_b_length, int tone_a_range, int tone_b_range,
                       int record_length) {
    for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
        if (!global_tone_detection.tone_definitions[i].valid) {
            strncpy(global_tone_detection.tone_definitions[i].tone_id, tone_id, 63);
            global_tone_detection.tone_definitions[i].tone_a_freq = tone_a_freq;
            global_tone_detection.tone_definitions[i].tone_b_freq = tone_b_freq;
            global_tone_detection.tone_definitions[i].tone_a_length_ms = tone_a_length;
            global_tone_detection.tone_definitions[i].tone_b_length_ms = tone_b_length;
            global_tone_detection.tone_definitions[i].tone_a_range_hz = tone_a_range;
            global_tone_detection.tone_definitions[i].tone_b_range_hz = tone_b_range;
            global_tone_detection.tone_definitions[i].record_length_ms = record_length;
            global_tone_detection.tone_definitions[i].valid = 1;
            
            printf("[TONE CONFIG] Added tone definition: %s (A: %.1f Hz, B: %.1f Hz)\n",
                   tone_id, tone_a_freq, tone_b_freq);
            return 1;
        }
    }
    
    fprintf(stderr, "[ERROR] No space for new tone definition\n");
    return 0;
}

int add_frequency_filter(const char* filter_id, float frequency, int range, const char* type) {
    for (int i = 0; i < MAX_FILTERS; i++) {
        if (!global_tone_detection.filters[i].valid) {
            strncpy(global_tone_detection.filters[i].filter_id, filter_id, 63);
            global_tone_detection.filters[i].frequency = frequency;
            global_tone_detection.filters[i].filter_range_hz = range;
            strncpy(global_tone_detection.filters[i].type, type, 15);
            global_tone_detection.filters[i].valid = 1;
            
            printf("[FILTER CONFIG] Added filter: %s (%.1f Hz, %s)\n",
                   filter_id, frequency, type);
            return 1;
        }
    }
    
    fprintf(stderr, "[ERROR] No space for new frequency filter\n");
    return 0;
}

int set_tone_config(float threshold, float gain, int db_threshold, int detect_new_tones,
                   int new_tone_length, int new_tone_range) {
    global_tone_detection.config.threshold = threshold;
    global_tone_detection.config.gain = gain;
    global_tone_detection.config.db_threshold = db_threshold;
    global_tone_detection.config.detect_new_tones = detect_new_tones;
    global_tone_detection.config.new_tone_length_ms = new_tone_length;
    global_tone_detection.config.new_tone_range_hz = new_tone_range;
    
    printf("[TONE CONFIG] Updated configuration: threshold=%.2f, gain=%.2f, db=%d\n",
           threshold, gain, db_threshold);
    return 1;
}