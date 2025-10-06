#define _GNU_SOURCE
#include "tone_detect.h"
#include "audio.h"
#include "config.h"
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Silence noisy logs while keeping confirmations
#define NOISY_LOG(...) do { (void)0; } while(0)

// Global tone detection state
struct tone_detection_state global_tone_detection = {0};

// Initialize tone detection system
int init_tone_detection(void) {
    // Save existing tone definitions before clearing
    struct tone_definition saved_tone_definitions[MAX_TONE_DEFINITIONS];
    struct frequency_filter saved_filters[MAX_FILTERS];
    int saved_tone_count = 0;
    int saved_filter_count = 0;
    
    // Backup existing tone definitions
    for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
        if (global_tone_detection.tone_definitions[i].valid) {
            saved_tone_definitions[saved_tone_count] = global_tone_detection.tone_definitions[i];
            saved_tone_count++;
        }
    }
    
    // Backup existing filters
    for (int i = 0; i < MAX_FILTERS; i++) {
        if (global_tone_detection.filters[i].valid) {
            saved_filters[saved_filter_count] = global_tone_detection.filters[i];
            saved_filter_count++;
        }
    }
    
    // Clear the structure
    memset(&global_tone_detection, 0, sizeof(struct tone_detection_state));
    
    // Restore tone definitions
    for (int i = 0; i < saved_tone_count; i++) {
        global_tone_detection.tone_definitions[i] = saved_tone_definitions[i];
    }
    
    // Restore filters
    for (int i = 0; i < saved_filter_count; i++) {
        global_tone_detection.filters[i] = saved_filters[i];
    }
    
    NOISY_LOG("[DEBUG] init_tone_detection() preserved %d tone definitions and %d filters\n", 
           saved_tone_count, saved_filter_count);
    
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
    
    // Initialize duration tracking
    global_tone_detection.tone_a_tracking = 0;
    global_tone_detection.tone_b_tracking = 0;
    global_tone_detection.tone_a_confirmed = 0;
    global_tone_detection.tone_b_confirmed = 0;
    global_tone_detection.tone_a_tracking_start = 0;
    global_tone_detection.tone_b_tracking_start = 0;
    
    global_tone_detection.active = 0;
    
    NOISY_LOG("[INFO] Tone detection system initialized\n");
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
    
    NOISY_LOG("[INFO] Tone detection thread started\n");
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
    
    NOISY_LOG("[INFO] Tone detection thread stopped\n");
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
            
            // Apply frequency filters to actual audio samples
            apply_audio_frequency_filters(audio_buffer, samples_to_process);
            
            // Analyze frequency spectrum
            if (analyze_frequency_spectrum(audio_buffer, samples_to_process)) {
                // Detect tone sequences with proper duration tracking
                detect_tone_sequence(audio_buffer, samples_to_process);
            }
            
            samples_processed += samples_to_process;
            
            // Print statistics much less frequently - every 50000 samples (about every 1 second at 48kHz)
            if (samples_processed % 50000 == 0) {
                static int stats_count = 0;
                if (stats_count++ % 30 == 0) {  // Only every 30th time (about every 30 seconds)
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
    
    // Convert dB threshold to absolute linear magnitude threshold
    // For -45 dB: 20*log10(magnitude) = -45, so magnitude = 10^(-45/20) = 0.00562
    float absolute_db_threshold = powf(10.0f, global_tone_detection.config.db_threshold / 20.0f);
    
    // Use the more permissive of the two thresholds
    float relative_threshold = max_magnitude * 0.1f;  // 10% of max magnitude
    float magnitude_threshold = (absolute_db_threshold > relative_threshold) ? relative_threshold : absolute_db_threshold;
    
    // Debug output for threshold analysis
    static int debug_count = 0;
    if (debug_count++ % 100 == 0) {
        NOISY_LOG("[DEBUG] FFT: max_mag=%.6f, db_thresh=%d, abs_thresh=%.6f, rel_thresh=%.6f, final_thresh=%.6f\n",
               max_magnitude, global_tone_detection.config.db_threshold, 
               absolute_db_threshold, relative_threshold, magnitude_threshold);
    }
    
    // Apply frequency filters BEFORE peak picking so peaks reflect configured filters
    apply_frequency_filters(global_tone_detection.frequency_magnitudes, FREQ_BINS);

    // Find peak frequencies above dB threshold
    for (int i = 1; i < FREQ_BINS - 1; i++) {
        float current = global_tone_detection.frequency_magnitudes[i];
        float prev = global_tone_detection.frequency_magnitudes[i-1];
        float next = global_tone_detection.frequency_magnitudes[i+1];
        
        // Check if this is a peak and above dB threshold
        if (current > prev && current > next && current > magnitude_threshold) {
            if (global_tone_detection.peak_count < 10) {
                // Quadratic (parabolic) interpolation around the peak to estimate sub-bin location
                // delta = 0.5 * (prev - next) / (prev - 2*current + next)
                float denominator = (prev - 2.0f * current + next);
                float delta = 0.0f;
                if (fabsf(denominator) > 1e-12f) {
                    delta = 0.5f * (prev - next) / denominator;
                    // Clamp delta to [-0.5, 0.5] to avoid wild jumps
                    if (delta > 0.5f) delta = 0.5f;
                    if (delta < -0.5f) delta = -0.5f;
                }
                float refined_bin = (float)i + delta;
                float peak_freq = (refined_bin * (float)SAMPLE_RATE) / (float)FFT_SIZE;
                
                global_tone_detection.peak_frequencies[global_tone_detection.peak_count] = peak_freq;
                global_tone_detection.peak_count++;
                
                // Debug output for peak detection (reduced verbosity)
                if ((peak_freq >= 950.0f && peak_freq <= 1050.0f) && debug_count % 50 == 0) {
                    NOISY_LOG("[DEBUG] Peak detected: %.1f Hz (bin %d, delta=%.3f, mag=%.6f, thresh=%.6f)\n",
                           peak_freq, i, delta, current, magnitude_threshold);
                }
            }
        }
    }
    
    return 1;
}

// Detect tone sequences with proper duration tracking
int detect_tone_sequence(float* audio_samples, int sample_count) {
    (void)audio_samples; // Suppress unused parameter warning
    (void)sample_count;  // Suppress unused parameter warning
    
    // Debug: Show when tone detection is called
    static int detect_count = 0;
    if (detect_count++ % 500 == 0) {
        NOISY_LOG("[DEBUG] detect_tone_sequence() called - peak_count=%d\n", 
               global_tone_detection.peak_count);
    }
    
    // Use milliseconds since program start to avoid overflow
    static struct timespec start_time = {0};
    if (start_time.tv_sec == 0) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }
    
    // Debug: Show tone definitions count
    static int tone_def_count = 0;
    for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
        if (global_tone_detection.tone_definitions[i].valid) {
            tone_def_count++;
        }
    }
    if (detect_count % 1000 == 0) {
        NOISY_LOG("[DEBUG] Loaded tone definitions: %d\n", tone_def_count);
        tone_def_count = 0; // Reset counter
    }
    
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int current_time = (int)((now.tv_sec - start_time.tv_sec) * 1000 + 
                            (now.tv_nsec - start_time.tv_nsec) / 1000000);
    
    // Presence smoothing state (N-of-M + grace) for stability
    static int a_hit_streak = 0, a_miss_streak = 0;
    static int b_hit_streak = 0, b_miss_streak = 0;
    static int a_last_seen_ms = 0, b_last_seen_ms = 0;
    static int a_present = 0, b_present = 0;
    const int HIT_REQUIRED = 1;      // require K hits (reduced from 2 to 1 for faster confirmation)
    const int MISS_REQUIRED = 3;     // require K misses (increased from 2 to 3 for stability)
    const int GRACE_MS = 500;        // allow brief gaps without resetting (increased from 250ms)

    // Check each tone definition
    for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
        struct tone_definition* tone_def = &global_tone_detection.tone_definitions[i];
        
        if (!tone_def->valid) {
            continue;
        }
        
        // Check for tone A
        if (!global_tone_detection.tone_a_confirmed) {
            // Debug: Show when we're checking for tone A
            static int tone_a_check_count = 0;
            if (tone_a_check_count++ % 200 == 0) {
                NOISY_LOG("[DEBUG] Checking for Tone A: %.1f Hz ±%d Hz\n", tone_def->tone_a_freq, tone_def->tone_a_range_hz);
            }
            
            if (check_tone_definition(tone_def->tone_a_freq, tone_def, 0)) {
                // Hit update
                a_hit_streak++;
                a_miss_streak = 0;
                a_last_seen_ms = current_time;
                
                // Debug: Show hit progress
                if (a_hit_streak == HIT_REQUIRED) {
                    printf("[TONE] Tone A hit streak reached %d - starting confirmation process\n", HIT_REQUIRED);
                }
                if (a_hit_streak >= HIT_REQUIRED && !a_present) {
                    printf("[TONE] Tone A present flag set - now tracking duration\n");
                }
                if (!a_present && a_hit_streak >= HIT_REQUIRED) {
                    a_present = 1;
                }
                // Tone A frequency detected
                if (!global_tone_detection.tone_a_tracking && a_present) {
                    // Start tracking tone A
                    global_tone_detection.tone_a_tracking = 1;
                    global_tone_detection.tone_a_tracking_start = current_time;
                    printf("[TONE] Tone A duration tracking started - need %d ms\n", tone_def->tone_a_length_ms);
                    // Only log if we haven't been tracking recently (debounce)
                    static int last_tone_a_start_log = 0;
                    if (current_time - last_tone_a_start_log > 5000) { // 5 second debounce
                        printf("[TONE] Tone A tracking started: %.1f Hz (ID: %s)\n", 
                               tone_def->tone_a_freq, tone_def->tone_id);
                        last_tone_a_start_log = current_time;
                    }
                } else {
                    // Check if minimum duration has been met
                    if (a_present && check_tone_duration(0, current_time, tone_def)) {
                        global_tone_detection.tone_a_confirmed = 1;
                        global_tone_detection.current_tone_a_detected = 1;
                        global_tone_detection.tone_a_start_time = current_time;
                        global_tone_detection.tone_sequence_active = 1;
                        printf("[TONE CONFIRMED] Tone A confirmed! (%.1f Hz ±%d Hz, %d ms duration)\n", 
                               tone_def->tone_a_freq, tone_def->tone_a_range_hz, tone_def->tone_a_length_ms);
                        printf("[TONE] Tone A CONFIRMED: %.1f Hz (ID: %s) - Duration: %d ms\n", 
                               tone_def->tone_a_freq, tone_def->tone_id,
                               current_time - global_tone_detection.tone_a_tracking_start);
                        global_tone_detection.tone_a_detections++;
                    }
                }
            } else {
                // Miss update with grace
                a_miss_streak++;
                if ((current_time - a_last_seen_ms) > GRACE_MS && a_miss_streak >= MISS_REQUIRED) {
                    a_present = 0;
                    a_hit_streak = 0;
                    if (global_tone_detection.tone_a_tracking) {
                        global_tone_detection.tone_a_tracking = 0;
                        global_tone_detection.tone_a_tracking_start = 0;
                        // Only log reset if we haven't logged recently (debounce)
                        static int last_tone_a_reset_log = 0;
                        if (current_time - last_tone_a_reset_log > 5000) { // 5 second debounce
                            printf("[TONE] Tone A tracking reset - frequency lost (suppressing further resets for 5s)\n");
                            last_tone_a_reset_log = current_time;
                        }
                    }
                }
            }
        }
        
        // Check for tone B (only if tone A was confirmed)
        else if (!global_tone_detection.tone_b_confirmed) {
            // Debug: Show when we're checking for tone B
            static int tone_b_check_count = 0;
            if (tone_b_check_count++ % 200 == 0) {
                NOISY_LOG("[DEBUG] Checking for Tone B: %.1f Hz ±%d Hz\n", tone_def->tone_b_freq, tone_def->tone_b_range_hz);
            }
            
            if (check_tone_definition(tone_def->tone_b_freq, tone_def, 1)) {
                // Hit update
                b_hit_streak++;
                b_miss_streak = 0;
                b_last_seen_ms = current_time;
                
                // Debug: Show hit progress
                if (b_hit_streak == HIT_REQUIRED) {
                    printf("[TONE] Tone B hit streak reached %d - starting confirmation process\n", HIT_REQUIRED);
                }
                if (b_hit_streak >= HIT_REQUIRED && !b_present) {
                    printf("[TONE] Tone B present flag set - now tracking duration\n");
                }
                if (!b_present && b_hit_streak >= HIT_REQUIRED) {
                    b_present = 1;
                }
                // Tone B frequency detected
                if (!global_tone_detection.tone_b_tracking && b_present) {
                    // Start tracking tone B
                    global_tone_detection.tone_b_tracking = 1;
                    global_tone_detection.tone_b_tracking_start = current_time;
                    printf("[TONE] Tone B duration tracking started - need %d ms\n", tone_def->tone_b_length_ms);
                    // Only log if we haven't been tracking recently (debounce)
                    static int last_tone_b_start_log = 0;
                    if (current_time - last_tone_b_start_log > 5000) { // 5 second debounce
                        printf("[TONE] Tone B tracking started: %.1f Hz (ID: %s)\n", 
                               tone_def->tone_b_freq, tone_def->tone_id);
                        last_tone_b_start_log = current_time;
                    }
                } else {
                    // Check if minimum duration has been met
                    if (b_present && check_tone_duration(1, current_time, tone_def)) {
                        global_tone_detection.tone_b_confirmed = 1;
                        global_tone_detection.current_tone_b_detected = 1;
                        global_tone_detection.tone_b_start_time = current_time;
                        printf("[TONE CONFIRMED] Tone B confirmed! (%.1f Hz ±%d Hz, %d ms duration)\n", 
                               tone_def->tone_b_freq, tone_def->tone_b_range_hz, tone_def->tone_b_length_ms);
                        printf("[TONE] Tone B CONFIRMED: %.1f Hz (ID: %s) - Duration: %d ms\n", 
                               tone_def->tone_b_freq, tone_def->tone_id,
                               current_time - global_tone_detection.tone_b_tracking_start);
                        global_tone_detection.tone_b_detections++;
                        
                        // Start recording
                        global_tone_detection.recording_active = 1;
                        global_tone_detection.recording_start_time = current_time;
                        printf("[TONE] Recording started for %d ms\n", tone_def->record_length_ms);
                        
                        // Trigger tone passthrough if configured
                        trigger_tone_passthrough();
                        
                        global_tone_detection.total_detections++;
                    }
                }
            } else {
                // Miss update with grace
                b_miss_streak++;
                if ((current_time - b_last_seen_ms) > GRACE_MS && b_miss_streak >= MISS_REQUIRED) {
                    b_present = 0;
                    b_hit_streak = 0;
                    if (global_tone_detection.tone_b_tracking) {
                        global_tone_detection.tone_b_tracking = 0;
                        global_tone_detection.tone_b_tracking_start = 0;
                        // Only log reset if we haven't logged recently (debounce)
                        static int last_tone_b_reset_log = 0;
                        if (current_time - last_tone_b_reset_log > 5000) { // 5 second debounce
                            printf("[TONE] Tone B tracking reset - frequency lost (suppressing further resets for 5s)\n");
                            last_tone_b_reset_log = current_time;
                        }
                    }
                }
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
            reset_tone_tracking();
            global_tone_detection.current_tone_a_detected = 0;
            global_tone_detection.current_tone_b_detected = 0;
            global_tone_detection.tone_sequence_active = 0;
            global_tone_detection.recording_active = 0;
            printf("[TONE] Sequence reset due to timeout\n");
        }
    }
    
    return 1;
}

// Check if a specific tone definition matches current frequencies
int check_tone_definition(float frequency, struct tone_definition* tone_def, int is_tone_b) {
    int range = is_tone_b ? tone_def->tone_b_range_hz : tone_def->tone_a_range_hz;
    
    // Debug: Show what we're checking
    static int debug_count = 0;
    if (debug_count++ % 100 == 0) {
        NOISY_LOG("[DEBUG] Checking tone %s: target=%.1f Hz ±%d Hz, peaks=%d\n", 
               is_tone_b ? "B" : "A", frequency, range, global_tone_detection.peak_count);
    }
    
    // Check if the target frequency is present in peak frequencies
    for (int i = 0; i < global_tone_detection.peak_count; i++) {
        if (is_frequency_in_range(global_tone_detection.peak_frequencies[i], frequency, range)) {
            if (debug_count % 50 == 0) {
                NOISY_LOG("[DEBUG] Tone %s MATCH: %.1f Hz matches peak %.1f Hz (range ±%d Hz)\n", 
                       is_tone_b ? "B" : "A", frequency, global_tone_detection.peak_frequencies[i], range);
            }
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
        int range_bins = (int)lroundf(((float)filter->filter_range_hz * (float)FFT_SIZE) / (float)SAMPLE_RATE);
        
        if (strcmp(filter->type, "below") == 0) {
            // Completely remove frequencies below the target
            for (int i = 0; i < target_bin; i++) {
                magnitudes[i] = 0.0f; // Completely remove
            }
        } else if (strcmp(filter->type, "above") == 0) {
            // Completely remove frequencies above the target
            for (int i = target_bin; i < count; i++) {
                magnitudes[i] = 0.0f; // Completely remove
            }
        } else if (strcmp(filter->type, "center") == 0) {
            // Keep only frequencies around the target, remove all others
            for (int i = 0; i < count; i++) {
                if (abs(i - target_bin) > range_bins) {
                    magnitudes[i] = 0.0f; // Completely remove
                }
            }
        }
    }
    
    return 1;
}

// Apply frequency filters to actual audio samples using FFT-based filtering
int apply_audio_frequency_filters(float* audio_samples, int sample_count) {
    // This function completely removes audio in the specified frequency ranges
    // Uses FFT-based filtering for precise frequency domain manipulation
    
    if (sample_count < FFT_SIZE) {
        return 1; // Not enough samples for FFT filtering
    }
    
    // Create temporary FFT buffers for filtering
    static double filter_fft_input[FFT_SIZE];
    static fftw_complex filter_fft_output[FFT_SIZE];
    static fftw_plan forward_plan = NULL;
    static fftw_plan inverse_plan = NULL;
    
    // Initialize FFT plans if not already done
    if (!forward_plan) {
        forward_plan = fftw_plan_dft_r2c_1d(FFT_SIZE, filter_fft_input, filter_fft_output, FFTW_ESTIMATE);
        inverse_plan = fftw_plan_dft_c2r_1d(FFT_SIZE, filter_fft_output, filter_fft_input, FFTW_ESTIMATE);
    }
    
    if (!forward_plan || !inverse_plan) {
        return 0; // FFT plan creation failed
    }
    
    // Process audio in FFT_SIZE chunks
    int processed_samples = 0;
    while (processed_samples + FFT_SIZE <= sample_count) {
        // Copy audio samples to FFT input buffer
        for (int i = 0; i < FFT_SIZE; i++) {
            filter_fft_input[i] = (double)audio_samples[processed_samples + i];
        }
        
        // Apply window function (Hanning window)
        for (int i = 0; i < FFT_SIZE; i++) {
            double window = 0.5 * (1.0 - cos(2.0 * M_PI * i / (FFT_SIZE - 1)));
            filter_fft_input[i] *= window;
        }
        
        // Forward FFT
        fftw_execute(forward_plan);
        
        // Apply frequency filters in frequency domain
        for (int f = 0; f < MAX_FILTERS; f++) {
            struct frequency_filter* filter = &global_tone_detection.filters[f];
            
            if (!filter->valid) {
                continue;
            }
            
            int target_bin = (int)frequency_to_bin(filter->frequency);
            int range_bins = (int)lroundf(((float)filter->filter_range_hz * (float)FFT_SIZE) / (float)SAMPLE_RATE);
            
            if (strcmp(filter->type, "below") == 0) {
                // Completely remove frequencies below the target
                for (int i = 0; i < target_bin && i < FREQ_BINS; i++) {
                    filter_fft_output[i][0] = 0.0;
                    filter_fft_output[i][1] = 0.0;
                }
            } else if (strcmp(filter->type, "above") == 0) {
                // Completely remove frequencies above the target
                for (int i = target_bin; i < FREQ_BINS; i++) {
                    filter_fft_output[i][0] = 0.0;
                    filter_fft_output[i][1] = 0.0;
                }
            } else if (strcmp(filter->type, "center") == 0) {
                // Keep only frequencies around the target, remove all others
                for (int i = 0; i < FREQ_BINS; i++) {
                    if (abs(i - target_bin) > range_bins) {
                        filter_fft_output[i][0] = 0.0;
                        filter_fft_output[i][1] = 0.0;
                    }
                }
            }
        }
        
        // Inverse FFT
        fftw_execute(inverse_plan);
        
        // Copy filtered samples back to audio buffer with normalization
        for (int i = 0; i < FFT_SIZE; i++) {
            audio_samples[processed_samples + i] = (float)(filter_fft_input[i] / FFT_SIZE);
        }
        
        processed_samples += FFT_SIZE;
    }
    
    return 1;
}

// Check if a tone has been present for the minimum required duration
int check_tone_duration(int tone_type, int current_time, struct tone_definition* tone_def) {
    int required_duration = (tone_type == 0) ? tone_def->tone_a_length_ms : tone_def->tone_b_length_ms;
    int tracking_start = (tone_type == 0) ? global_tone_detection.tone_a_tracking_start : global_tone_detection.tone_b_tracking_start;
    
    if (tracking_start == 0) {
        return 0; // Not tracking yet
    }
    
    int duration = current_time - tracking_start;
    
    // Debug output for duration checking (only when close to meeting requirement)
    static int duration_debug_count = 0;
    if (duration_debug_count++ % 100 == 0 || duration >= (required_duration * 0.8)) {
        NOISY_LOG("[DEBUG] Tone %c duration check: %d ms (required: %d ms, tracking_start: %d)\n",
               (tone_type == 0) ? 'A' : 'B', duration, required_duration, tracking_start);
    }
    
    return (duration >= required_duration) ? 1 : 0;
}

// Reset tone tracking state
void reset_tone_tracking(void) {
    global_tone_detection.tone_a_tracking = 0;
    global_tone_detection.tone_b_tracking = 0;
    global_tone_detection.tone_a_confirmed = 0;
    global_tone_detection.tone_b_confirmed = 0;
    global_tone_detection.tone_a_tracking_start = 0;
    global_tone_detection.tone_b_tracking_start = 0;
}

// Detect new tones
int detect_new_tones(float* magnitudes __attribute__((unused)), int count __attribute__((unused))) {
    // Simple new tone detection - look for strong peaks not in defined tones
    for (int i = 0; i < global_tone_detection.peak_count; i++) {
        float freq = global_tone_detection.peak_frequencies[i];
        int is_known_tone = 0;
        int is_duplicate = 0;
        
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
            // Check if we've already detected this frequency recently (within 3 Hz)
            for (int k = 0; k < global_tone_detection.detected_frequency_count; k++) {
                if (fabs(global_tone_detection.detected_frequencies[k] - freq) < 3.0f) {
                    is_duplicate = 1;
                    break;
                }
            }
            
            if (!is_duplicate && global_tone_detection.detected_frequency_count < 100) {
                // This is a genuinely new tone - only log once per frequency
                global_tone_detection.detected_frequencies[global_tone_detection.detected_frequency_count] = freq;
                global_tone_detection.detected_frequency_count++;
                global_tone_detection.new_tone_detections++;
                // Suppress NEW TONE logs for frequencies within any configured tone window
                if (!is_known_tone) {
                    printf("[NEW TONE] Detected unknown frequency: %.1f Hz\n", freq);
                }
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
    // Only print stats if there are any detections to report
    if (global_tone_detection.total_detections > 0 || 
        global_tone_detection.tone_a_detections > 0 || 
        global_tone_detection.tone_b_detections > 0 || 
        global_tone_detection.new_tone_detections > 0) {
        printf("[TONE STATS] Total: %d, Tone A: %d, Tone B: %d, New: %d\n",
               global_tone_detection.total_detections,
               global_tone_detection.tone_a_detections,
               global_tone_detection.tone_b_detections,
               global_tone_detection.new_tone_detections);
    }
}

void reset_tone_detection_stats(void) {
    global_tone_detection.total_detections = 0;
    global_tone_detection.tone_a_detections = 0;
    global_tone_detection.tone_b_detections = 0;
    global_tone_detection.new_tone_detections = 0;
}

// Trigger tone passthrough when tones are detected
void trigger_tone_passthrough(void) {
    // Check if tone passthrough is configured for channel 1 (index 0)
    struct tone_detect_config* tone_config = get_tone_detect_config(0); // Channel 1
    
    if (tone_config && tone_config->tone_passthrough) {
        printf("[TONE PASSTHROUGH] Tone detected, activating passthrough\n");
        // Enable passthrough mode (Channel 4 output callback will play from shared buffer)
        set_card3_output_mode(1);
    } else {
        printf("[TONE PASSTHROUGH] Tone passthrough not configured or not enabled\n");
    }
}

// Configuration functions
int add_tone_definition(const char* tone_id, float tone_a_freq, float tone_b_freq,
                       int tone_a_length, int tone_b_length, int tone_a_range, int tone_b_range,
                       int record_length) {
    printf("[DEBUG] add_tone_definition() called: ID=%s, A=%.1f Hz±%d, B=%.1f Hz±%d\n", 
           tone_id, tone_a_freq, tone_a_range, tone_b_freq, tone_b_range);
    
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
            
            printf("[TONE CONFIG] Added tone definition: %s (A: %.1f Hz ±%d Hz, %d ms, B: %.1f Hz ±%d Hz, %d ms)\n",
                   tone_id, tone_a_freq, tone_a_range, tone_a_length, tone_b_freq, tone_b_range, tone_b_length);
            
            // Debug: Show total count after adding
            int total_count = 0;
            for (int j = 0; j < MAX_TONE_DEFINITIONS; j++) {
                if (global_tone_detection.tone_definitions[j].valid) {
                    total_count++;
                }
            }
            printf("[DEBUG] Total tone definitions now: %d\n", total_count);
            
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
