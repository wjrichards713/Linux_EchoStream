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

// Audio buffer for sliding window analysis (following Python approach)
#define MAX_AUDIO_BUFFER_SAMPLES (10 * SAMPLE_RATE) // 10 seconds max
static float audio_buffer[MAX_AUDIO_BUFFER_SAMPLES];
static int audio_buffer_pos = 0;
static int audio_buffer_size = 0;

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
    // Initialize new tone tracking array
    for (int i = 0; i < 10; i++) {
        global_tone_detection.new_tone_tracking[i].is_tracking = 0;
        global_tone_detection.new_tone_tracking[i].tracking_start = 0;
        global_tone_detection.new_tone_tracking[i].frequency = 0.0f;
        global_tone_detection.new_tone_tracking[i].hit_streak = 0;
        global_tone_detection.new_tone_tracking[i].miss_streak = 0;
        global_tone_detection.new_tone_tracking[i].last_seen_ms = 0;
    }
    
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
                        
                        // Start recording timer if configured
                        if (tone_def->record_length_ms > 0) {
                            printf("[DEBUG] About to start recording timer for %d ms\n", tone_def->record_length_ms);
                            start_recording_timer(tone_def->record_length_ms);
                            printf("[DEBUG] Recording timer started, active=%d\n", global_tone_detection.recording_active);
                        }
                        
                        // Trigger tone passthrough/alert playback if configured
                        trigger_tone_passthrough();
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
                        
                        // Start or extend recording
                        printf("[DEBUG] About to start recording timer for %d ms\n", tone_def->record_length_ms);
                        start_recording_timer(tone_def->record_length_ms);
                        printf("[DEBUG] Recording timer started, active=%d\n", global_tone_detection.recording_active);
                        
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
    
    // Apply frequency filters to audio samples if any are configured
    apply_audio_frequency_filters(audio_samples, sample_count);
    
    // Check for single tone detection for passthrough
    detect_single_tone_for_passthrough(audio_samples, sample_count);
    
    // Check if recording should stop
    if (global_tone_detection.recording_active) {
        int elapsed = current_time - global_tone_detection.recording_start_time;
        if (elapsed >= global_tone_detection.recording_duration_ms) {
            global_tone_detection.recording_active = 0;
            printf("[TONE] Recording stopped - %d ms elapsed\n", elapsed);
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

// Detect new tones with proper duration tracking (similar to Tone A/B)
int detect_new_tones(float* magnitudes __attribute__((unused)), int count __attribute__((unused))) {
    if (!global_tone_detection.config.detect_new_tones) {
        return 0;
    }
    
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    static struct timespec start_time = {0, 0};
    if (start_time.tv_sec == 0) {
        start_time = now;
    }
    int current_time = (int)((now.tv_sec - start_time.tv_sec) * 1000 + 
                            (now.tv_nsec - start_time.tv_nsec) / 1000000);
    
    const int GRACE_MS = 500;
    
    // First, check all peaks for unknown frequencies
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
            // Check if we've already confirmed this frequency before
            int already_confirmed = 0;
            for (int k = 0; k < global_tone_detection.detected_frequency_count; k++) {
                if (fabs(global_tone_detection.detected_frequencies[k] - freq) < global_tone_detection.config.new_tone_range_hz) {
                    already_confirmed = 1;
                    break;
                }
            }
            
            if (already_confirmed) {
                continue; // Skip already confirmed tones
            }
            
            // Find or create tracking slot for this frequency
            int tracking_idx = -1;
            for (int t = 0; t < 10; t++) {
                if (global_tone_detection.new_tone_tracking[t].is_tracking) {
                    // Check if this frequency matches a tracked tone (within range)
                    if (fabs(global_tone_detection.new_tone_tracking[t].frequency - freq) < global_tone_detection.config.new_tone_range_hz) {
                        tracking_idx = t;
                        break;
                    }
                } else if (tracking_idx == -1) {
                    // Empty slot available
                    tracking_idx = t;
                }
            }
            
            if (tracking_idx >= 0) {
                // Update or start tracking
                if (!global_tone_detection.new_tone_tracking[tracking_idx].is_tracking) {
                    // Start new tracking
                    global_tone_detection.new_tone_tracking[tracking_idx].frequency = freq;
                    global_tone_detection.new_tone_tracking[tracking_idx].is_tracking = 1;
                    global_tone_detection.new_tone_tracking[tracking_idx].tracking_start = current_time;
                    global_tone_detection.new_tone_tracking[tracking_idx].hit_streak = 1;
                    global_tone_detection.new_tone_tracking[tracking_idx].miss_streak = 0;
                    global_tone_detection.new_tone_tracking[tracking_idx].last_seen_ms = current_time;
                } else {
                    // Update existing tracking - frequency detected
                    global_tone_detection.new_tone_tracking[tracking_idx].hit_streak++;
                    global_tone_detection.new_tone_tracking[tracking_idx].miss_streak = 0;
                    global_tone_detection.new_tone_tracking[tracking_idx].last_seen_ms = current_time;
                    
                    // Update frequency to average for stability
                    float avg_freq = (global_tone_detection.new_tone_tracking[tracking_idx].frequency + freq) / 2.0f;
                    if (fabs(avg_freq - global_tone_detection.new_tone_tracking[tracking_idx].frequency) < global_tone_detection.config.new_tone_range_hz) {
                        global_tone_detection.new_tone_tracking[tracking_idx].frequency = avg_freq;
                    }
                    
                    // Check if duration requirement is met
                    int elapsed = current_time - global_tone_detection.new_tone_tracking[tracking_idx].tracking_start;
                    if (elapsed >= global_tone_detection.config.new_tone_length_ms) {
                        // Defer publishing single confirmations; require two in same window
                        // Stash this confirmation to evaluate after scanning all peaks
                        static int confirmed_indices[10];
                        static float confirmed_freqs[10];
                        static int confirmed_count = 0;

                        // Initialize list at function entry once per call
                        // (Use a sentinel check on confirmed_count when i==0)
                        if (i == 0) {
                            confirmed_count = 0;
                        }

                        if (confirmed_count < 10) {
                            confirmed_indices[confirmed_count] = tracking_idx;
                            confirmed_freqs[confirmed_count] = global_tone_detection.new_tone_tracking[tracking_idx].frequency;
                            confirmed_count++;
                        }

                        // If this is the last peak, evaluate whether to publish
                        if (i == global_tone_detection.peak_count - 1) {
                            if (confirmed_count >= 2) {
                                // Choose the first two confirmed as A and B (ordered by their tracking_start)
                                int idx_a = confirmed_indices[0];
                                int idx_b = confirmed_indices[1];
                                float tone_a = confirmed_freqs[0];
                                float tone_b = confirmed_freqs[1];

                                // Ensure ordering by earliest tracking start (A then B)
                                if (global_tone_detection.new_tone_tracking[idx_b].tracking_start <
                                    global_tone_detection.new_tone_tracking[idx_a].tracking_start) {
                                    // swap
                                    int tmpi = idx_a; idx_a = idx_b; idx_b = tmpi;
                                    float tmpf = tone_a; tone_a = tone_b; tone_b = tmpf;
                                }

                                printf("[NEW TONE PAIR] A=%.1f Hz, B=%.1f Hz (each ≥ %d ms, ±%d Hz stable)\n",
                                       tone_a, tone_b,
                                       global_tone_detection.config.new_tone_length_ms,
                                       global_tone_detection.config.new_tone_range_hz);

                                // Add both to confirmed list
                                if (global_tone_detection.detected_frequency_count < 100) {
                                    global_tone_detection.detected_frequencies[global_tone_detection.detected_frequency_count++] = tone_a;
                                }
                                if (global_tone_detection.detected_frequency_count < 100) {
                                    global_tone_detection.detected_frequencies[global_tone_detection.detected_frequency_count++] = tone_b;
                                }
                                global_tone_detection.new_tone_detections += 2;

                                // Publish single MQTT message with the pair
                                extern int publish_new_tone_pair(float tone_a_hz, float tone_b_hz);
                                publish_new_tone_pair(tone_a, tone_b);

                                // Reset tracking for used slots
                                global_tone_detection.new_tone_tracking[idx_a].is_tracking = 0;
                                global_tone_detection.new_tone_tracking[idx_a].tracking_start = 0;
                                global_tone_detection.new_tone_tracking[idx_a].hit_streak = 0;
                                global_tone_detection.new_tone_tracking[idx_a].miss_streak = 0;
                                global_tone_detection.new_tone_tracking[idx_b].is_tracking = 0;
                                global_tone_detection.new_tone_tracking[idx_b].tracking_start = 0;
                                global_tone_detection.new_tone_tracking[idx_b].hit_streak = 0;
                                global_tone_detection.new_tone_tracking[idx_b].miss_streak = 0;
                            } else {
                                // Fewer than 2 confirmed in this window: do not publish; continue tracking
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Process misses and cleanup stale tracking slots
    for (int t = 0; t < 10; t++) {
        if (global_tone_detection.new_tone_tracking[t].is_tracking) {
            // Check if any current peak matches this tracked frequency
            int found = 0;
            for (int i = 0; i < global_tone_detection.peak_count; i++) {
                float freq = global_tone_detection.peak_frequencies[i];
                if (fabs(global_tone_detection.new_tone_tracking[t].frequency - freq) < global_tone_detection.config.new_tone_range_hz) {
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                // Frequency not found in current peaks - increment miss streak
                global_tone_detection.new_tone_tracking[t].miss_streak++;
                
                // Reset if grace period exceeded and enough misses
                if ((current_time - global_tone_detection.new_tone_tracking[t].last_seen_ms) > GRACE_MS &&
                    global_tone_detection.new_tone_tracking[t].miss_streak >= 3) {
                    // Reset this tracking slot
                    global_tone_detection.new_tone_tracking[t].is_tracking = 0;
                    global_tone_detection.new_tone_tracking[t].tracking_start = 0;
                    global_tone_detection.new_tone_tracking[t].hit_streak = 0;
                    global_tone_detection.new_tone_tracking[t].miss_streak = 0;
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

// Generate alert tone for local playback
void generate_alert_tone(float frequency, float duration_seconds, float* output_buffer, int sample_rate) {
    int samples = (int)(duration_seconds * sample_rate);
    
    
    for (int i = 0; i < samples; i++) {
        float t = (float)i / sample_rate;
        // Generate sine wave with envelope (fade in/out)
        float envelope = 1.0f;
        if (i < sample_rate * 0.1f) {
            envelope = (float)i / (sample_rate * 0.1f); // Fade in
        } else if (i > samples - sample_rate * 0.1f) {
            envelope = (samples - i) / (sample_rate * 0.1f); // Fade out
        }
        
        output_buffer[i] = envelope * 1.0f * sin(2.0f * M_PI * frequency * t);
        
        
    }
}

// Global alert playback state
static struct {
    int active;
    float tone_a_frequency;
    float tone_b_frequency;
    float tone_a_duration_seconds;
    float tone_b_duration_seconds;
    int samples_played;
    int total_samples;
    float* alert_buffer;
    int target_channel_idx;
    int current_phase; // 0 = playing tone A, 1 = playing tone B
    int tone_a_samples_played;
    int tone_b_samples_played;
} global_alert_playback = {0};

// Play detected Tone A and Tone B sequence through target channel output
void play_alert_tone_locally(int target_channel_idx, float tone_a_freq, float tone_b_freq, 
                            float tone_a_duration, float tone_b_duration) {
    printf("\n🔊 [ALERT PLAYBACK] Generating alert tones...\n");
    printf("   📍 Target Channel: %d\n", target_channel_idx + 1);
    printf("   🎵 Tone A: %.1f Hz for %.1f ms\n", tone_a_freq, tone_a_duration);
    printf("   🎵 Tone B: %.1f Hz for %.1f ms\n", tone_b_freq, tone_b_duration);
    
    if (target_channel_idx < 0 || target_channel_idx >= MAX_CHANNELS) {
        printf("[ALERT PLAYBACK] Invalid target channel index: %d\n", target_channel_idx);
        return;
    }
    
    if (!channel_has_output_stream(target_channel_idx)) {
        printf("[ALERT PLAYBACK] Target channel %d has no output stream\n", target_channel_idx + 1);
        return;
    }
    
    // Get the actual sample rate from the PortAudio stream
    extern struct channel_context channels[MAX_CHANNELS];
    double actual_sample_rate = SAMPLE_RATE; // Default fallback
    if (channels[target_channel_idx].audio.output_stream) {
        const PaStreamInfo* stream_info = Pa_GetStreamInfo(channels[target_channel_idx].audio.output_stream);
        if (stream_info) {
            actual_sample_rate = stream_info->sampleRate;
            printf("   🎛️ Using actual sample rate: %.1f Hz (instead of %d Hz)\n", actual_sample_rate, SAMPLE_RATE);
        }
    }
    
    // Stop any existing alert playback and manage recording timer
    if (global_alert_playback.active) {
        printf("[ALERT PLAYBACK] Stopping previous alert to start new one\n");
        printf("[ALERT PLAYBACK] Previous alert was playing for %d/%d samples\n", 
               global_alert_playback.samples_played, global_alert_playback.total_samples);
        
        // Clean up previous alert
        if (global_alert_playback.alert_buffer) {
            free(global_alert_playback.alert_buffer);
            global_alert_playback.alert_buffer = NULL;
        }
        
        // Reset alert state
        global_alert_playback.active = 0;
        global_alert_playback.samples_played = 0;
        global_alert_playback.total_samples = 0;
    }
    
    // Calculate total samples needed for both tones (convert ms to seconds)
    int tone_a_samples = (int)((tone_a_duration / 1000.0f) * actual_sample_rate);
    int tone_b_samples = (int)((tone_b_duration / 1000.0f) * actual_sample_rate);
    int total_samples = tone_a_samples + tone_b_samples;
    
    // Allocate buffer for both tones
    float* alert_buffer = malloc(total_samples * sizeof(float));
    if (!alert_buffer) {
        printf("[ALERT PLAYBACK] Failed to allocate memory for alert tones\n");
        return;
    }
    
    // Generate Tone A
    printf("   🎼 Generating Tone A: %.1f Hz for %.1f ms (sample_rate=%.1f)\n", tone_a_freq, tone_a_duration, actual_sample_rate);
    generate_alert_tone(tone_a_freq, tone_a_duration / 1000.0f, alert_buffer, (int)actual_sample_rate);
    
    // Generate Tone B (append to buffer after Tone A)
    printf("   🎼 Generating Tone B: %.1f Hz for %.1f ms (sample_rate=%.1f)\n", tone_b_freq, tone_b_duration, actual_sample_rate);
    generate_alert_tone(tone_b_freq, tone_b_duration / 1000.0f, &alert_buffer[tone_a_samples], (int)actual_sample_rate);
    
    
    // Debug: Check if tones were generated correctly
    float max_amplitude = 0.0f;
    for (int i = 0; i < total_samples; i++) {
        if (fabs(alert_buffer[i]) > max_amplitude) {
            max_amplitude = fabs(alert_buffer[i]);
        }
    }
    printf("   🔍 Generated alert buffer: %d samples, max amplitude: %.3f\n", total_samples, max_amplitude);
    
    // Set up global alert playback state
    printf("   ✅ Alert buffer ready: %d samples, playing on channel %d\n", 
           total_samples, target_channel_idx + 1);
    global_alert_playback.active = 1;
    global_alert_playback.tone_a_frequency = tone_a_freq;
    global_alert_playback.tone_b_frequency = tone_b_freq;
    global_alert_playback.tone_a_duration_seconds = tone_a_duration / 1000.0f;
    global_alert_playback.tone_b_duration_seconds = tone_b_duration / 1000.0f;
    global_alert_playback.samples_played = 0;
    global_alert_playback.total_samples = total_samples;
    global_alert_playback.alert_buffer = alert_buffer;
    global_alert_playback.target_channel_idx = target_channel_idx;
    global_alert_playback.current_phase = 0; // Start with Tone A
    global_alert_playback.tone_a_samples_played = 0;
    global_alert_playback.tone_b_samples_played = 0;
    
    printf("[ALERT PLAYBACK] Playing detected tones: A=%.1f Hz (%.1fms), B=%.1f Hz (%.1fms) on channel %d\n", 
           tone_a_freq, tone_a_duration, tone_b_freq, tone_b_duration, target_channel_idx + 1);
    
    // Debug: Verify the alert is actually active
    
}

// Get alert audio samples for output callback (called from audio.c)
int get_alert_audio_samples(float* output_buffer, int max_samples) {
    
    if (!global_alert_playback.active || !global_alert_playback.alert_buffer) {
        return 0; // No alert playing
    }
    
    // Only log occasionally to reduce spam
    static int sample_log_counter = 0;
    if (++sample_log_counter % 50 == 0) {
        printf("   🔊 Playing alert: %d/%d samples\n", 
               global_alert_playback.samples_played, global_alert_playback.total_samples);
    }
    
    int samples_to_copy = max_samples;
    int remaining_samples = global_alert_playback.total_samples - global_alert_playback.samples_played;
    
    if (samples_to_copy > remaining_samples) {
        samples_to_copy = remaining_samples;
    }
    
    // Copy alert samples to output buffer (REPLACE, don't mix)
    for (int i = 0; i < samples_to_copy; i++) {
        output_buffer[i] = global_alert_playback.alert_buffer[global_alert_playback.samples_played + i];
    }
    
    global_alert_playback.samples_played += samples_to_copy;
    
    // Update phase tracking (use actual sample rate from stream)
    extern struct channel_context channels[MAX_CHANNELS];
    double actual_sample_rate = SAMPLE_RATE; // Default fallback
    if (global_alert_playback.target_channel_idx >= 0 && 
        global_alert_playback.target_channel_idx < MAX_CHANNELS &&
        channels[global_alert_playback.target_channel_idx].audio.output_stream) {
        const PaStreamInfo* stream_info = Pa_GetStreamInfo(channels[global_alert_playback.target_channel_idx].audio.output_stream);
        if (stream_info) {
            actual_sample_rate = stream_info->sampleRate;
        }
    }
    
    int tone_a_samples = (int)(global_alert_playback.tone_a_duration_seconds * actual_sample_rate);
    if (global_alert_playback.samples_played <= tone_a_samples) {
        // Still playing Tone A
        if (global_alert_playback.current_phase != 0) {
            global_alert_playback.current_phase = 0;
            printf("   🎵 Now playing Tone A: %.1f Hz\n", global_alert_playback.tone_a_frequency);
        }
    } else {
        // Playing Tone B
        if (global_alert_playback.current_phase != 1) {
            global_alert_playback.current_phase = 1;
            printf("   🎵 Now playing Tone B: %.1f Hz\n", global_alert_playback.tone_b_frequency);
        }
    }
    
    // Check if alert is finished
    if (global_alert_playback.samples_played >= global_alert_playback.total_samples) {
        printf("\n✅ [ALERT COMPLETE] Alert sequence finished playing\n");
        global_alert_playback.active = 0;
        free(global_alert_playback.alert_buffer);
        global_alert_playback.alert_buffer = NULL;
    }
    
    return samples_to_copy;
}

// Check if alert is currently playing
int is_alert_playing(void) {
    return global_alert_playback.active;
}

// Check if alert should be played on the current channel
int should_play_alert_on_channel(int channel_index) {
    return global_alert_playback.active && (global_alert_playback.target_channel_idx == channel_index);
}

// Trigger tone passthrough when tones are detected
void trigger_tone_passthrough(void) {
    // Find which channel has tone detection enabled and get its config
    struct tone_detect_config* tone_config = NULL;
    int source_channel_idx = -1;
    
    // Search through all channels to find the one with tone detection enabled
    for (int i = 0; i < MAX_CHANNELS; i++) {
        struct channel_config* channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid && channel_config->tone_detect) {
            tone_config = &channel_config->tone_config;
            source_channel_idx = i;
            break;
        }
    }
    
    if (!tone_config) {
        printf("[TONE PASSTHROUGH] No tone config found for any channel\n");
        return;
    }
    
    if (!tone_config->tone_passthrough) {
        printf("[TONE PASSTHROUGH] Tone passthrough not enabled in config\n");
        return;
    }
    
    printf("[TONE PASSTHROUGH] Source channel %d detected tone, target: %s\n", 
           source_channel_idx + 1, tone_config->passthrough_channel);
    
    // Check if the target channel has a working output stream
    int target_channel_idx = get_passthrough_target_channel_index();
    printf("[DEBUG] Target channel index: %d\n", target_channel_idx);
    if (target_channel_idx >= 0 && target_channel_idx < MAX_CHANNELS) {
        if (channel_has_output_stream(target_channel_idx)) {
            printf("[TONE PASSTHROUGH] Tone detected, playing alert locally on channel %d\n", 
                   target_channel_idx + 1);
            
            // Play alert tone with duration from config.json record_length
            // Find the tone definition that was detected
            float tone_a_freq = 1000.0f; // Default frequency
            float tone_b_freq = 1000.0f; // Default frequency
            float alert_duration = 20000.0f; // Default 20 seconds
            
            for (int i = 0; i < MAX_TONE_DEFINITIONS; i++) {
                if (global_tone_detection.tone_definitions[i].valid) {
                    // Use the detected Tone A frequency and record_length from config
                    tone_a_freq = global_tone_detection.tone_definitions[i].tone_a_freq;
                    tone_b_freq = global_tone_detection.tone_definitions[i].tone_b_freq;
                    alert_duration = (float)global_tone_detection.tone_definitions[i].record_length_ms;
                    printf("[ALERT] Playing %.1f-second alert tone at %.1f Hz (record_length from config)\n",
                           alert_duration / 1000.0f, tone_a_freq);
                    break;
                }
            }
            
            // Play alert tone with duration from config.json
            play_alert_tone_locally(target_channel_idx, tone_a_freq, tone_b_freq, alert_duration, 0);
            
        } else {
            printf("[TONE PASSTHROUGH] Tone detected but target channel %d has no output stream - alert playback disabled\n", 
                   target_channel_idx + 1);
        }
    } else {
        printf("[TONE PASSTHROUGH] Tone detected but invalid target channel index %d - alert playback disabled\n", 
               target_channel_idx);
    }
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
            
            printf("[TONE CONFIG] Added tone definition: %s (A: %.1f Hz ±%d Hz, %d ms, B: %.1f Hz ±%d Hz, %d ms)\n",
                   tone_id, tone_a_freq, tone_a_range, tone_a_length, tone_b_freq, tone_b_range, tone_b_length);
            
            // Debug: Show total count after adding
            int total_count = 0;
            for (int j = 0; j < MAX_TONE_DEFINITIONS; j++) {
                if (global_tone_detection.tone_definitions[j].valid) {
                    total_count++;
                }
            }
            
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

// Add audio samples to sliding window buffer (Python approach)
void add_audio_to_sliding_buffer(const float* samples, int count) {
    // Add samples to sliding buffer
    for (int i = 0; i < count; i++) {
        audio_buffer[audio_buffer_pos] = samples[i];
        audio_buffer_pos = (audio_buffer_pos + 1) % MAX_AUDIO_BUFFER_SAMPLES;
        if (audio_buffer_size < MAX_AUDIO_BUFFER_SAMPLES) {
            audio_buffer_size++;
        }
    }
}

// Calculate RMS volume level (Python approach)
float calculate_volume_level(void) {
    if (audio_buffer_size == 0) return 0.0f;
    
    float sum_squares = 0.0f;
    int start_pos = (audio_buffer_pos - audio_buffer_size + MAX_AUDIO_BUFFER_SAMPLES) % MAX_AUDIO_BUFFER_SAMPLES;
    
    for (int i = 0; i < audio_buffer_size; i++) {
        int pos = (start_pos + i) % MAX_AUDIO_BUFFER_SAMPLES;
        float sample = audio_buffer[pos];
        sum_squares += sample * sample;
    }
    
    float rms = sqrt(sum_squares / audio_buffer_size);
    return 20.0f * log10(rms + 1e-10f); // Add small value to avoid log(0)
}

// Get audio samples from sliding buffer (Python approach)
void get_audio_segment(int start_offset_samples, int length_samples, float* output) {
    int start_pos = (audio_buffer_pos - start_offset_samples + MAX_AUDIO_BUFFER_SAMPLES) % MAX_AUDIO_BUFFER_SAMPLES;
    
    for (int i = 0; i < length_samples; i++) {
        int pos = (start_pos + i) % MAX_AUDIO_BUFFER_SAMPLES;
        output[i] = audio_buffer[pos];
    }
}

// Get current time in milliseconds
int get_current_time_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int)(now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

// Extract frequency from FFT (Python approach)
float freq_from_fft(float* samples, int sample_count, int sample_rate) {
    if (sample_count < FFT_SIZE) {
        return 0.0f; // Not enough samples
    }
    
    // Create temporary FFT buffers
    static double temp_fft_input[FFT_SIZE];
    static fftw_complex temp_fft_output[FFT_SIZE];
    static fftw_plan temp_plan = NULL;
    
    // Initialize FFT plan if not already done
    if (!temp_plan) {
        temp_plan = fftw_plan_dft_r2c_1d(FFT_SIZE, temp_fft_input, temp_fft_output, FFTW_ESTIMATE);
    }
    
    if (!temp_plan) {
        return 0.0f;
    }
    
    // Copy samples to FFT input
    for (int i = 0; i < FFT_SIZE; i++) {
        temp_fft_input[i] = (double)samples[i];
    }
    
    // Apply window function (Hanning window)
    for (int i = 0; i < FFT_SIZE; i++) {
        double window = 0.5 * (1.0 - cos(2.0 * M_PI * i / (FFT_SIZE - 1)));
        temp_fft_input[i] *= window;
    }
    
    // Perform FFT
    fftw_execute(temp_plan);
    
    // Find peak frequency
    float max_magnitude = 0.0f;
    int peak_bin = 0;
    
    for (int i = 1; i < FREQ_BINS - 1; i++) {
        float magnitude = sqrt(temp_fft_output[i][0] * temp_fft_output[i][0] + 
                              temp_fft_output[i][1] * temp_fft_output[i][1]);
        
        if (magnitude > max_magnitude) {
            max_magnitude = magnitude;
            peak_bin = i;
        }
    }
    
    // Convert bin to frequency
    float frequency = (float)peak_bin * (float)sample_rate / (float)FFT_SIZE;
    
    
    return frequency;
}

// Process audio using Python approach - sliding window with FFT on specific time segments
int process_audio_python_approach(const float* samples, int sample_count) {
    // Add samples to sliding buffer
    add_audio_to_sliding_buffer(samples, sample_count);
    
    // Check if we have enough audio data
    if (audio_buffer_size < SAMPLE_RATE) { // Need at least 1 second
        return 0;
    }
    
    // Calculate volume level
    float volume = calculate_volume_level();
    
    // Only process if volume is above threshold
    if (volume < global_tone_detection.config.db_threshold) {
        return 0;
    }
    
    // Only log volume occasionally to reduce spam
    static int volume_log_counter = 0;
    if (++volume_log_counter % 100 == 0) {
        printf("[TONE] Volume level: %.1f dB (threshold: %d dB)\n", volume, global_tone_detection.config.db_threshold);
    }
    
    // Process each tone definition
    for (int t = 0; t < MAX_TONE_DEFINITIONS; t++) {
        struct tone_definition* tone_def = &global_tone_detection.tone_definitions[t];
        if (!tone_def->valid) continue;
        
        // Calculate required buffer sizes
        int tone_a_samples = (int)(tone_def->tone_a_length_ms * SAMPLE_RATE / 1000.0f);
        int tone_b_samples = (int)(tone_def->tone_b_length_ms * SAMPLE_RATE / 1000.0f);
        int total_samples = tone_a_samples + tone_b_samples;
        
        // Check if we have enough data
        if (audio_buffer_size < total_samples) continue;
        
        // Get audio segments for analysis
        float* tone_a_segment = malloc(tone_a_samples * sizeof(float));
        float* tone_b_segment = malloc(tone_b_samples * sizeof(float));
        
        if (!tone_a_segment || !tone_b_segment) {
            free(tone_a_segment);
            free(tone_b_segment);
            continue;
        }
        
        // Extract Tone A segment (older audio) - goes back (tone_a_samples + tone_b_samples)
        get_audio_segment(tone_a_samples + tone_b_samples, tone_a_samples, tone_a_segment);
        
        // Extract Tone B segment (newer audio) - goes back tone_b_samples
        get_audio_segment(tone_b_samples, tone_b_samples, tone_b_segment);
        
        // Perform FFT on each segment
        float tone_a_freq = freq_from_fft(tone_a_segment, tone_a_samples, SAMPLE_RATE);
        float tone_b_freq = freq_from_fft(tone_b_segment, tone_b_samples, SAMPLE_RATE);
        
        // Check if frequencies match within tolerance
        int tone_a_tolerance = tone_def->tone_a_range_hz; // Use Tone A's configured tolerance
        int tone_b_tolerance = tone_def->tone_b_range_hz; // Use Tone B's configured tolerance
        int tone_a_match = (fabs(tone_a_freq - tone_def->tone_a_freq) < tone_a_tolerance);
        int tone_b_match = (fabs(tone_b_freq - tone_def->tone_b_freq) < tone_b_tolerance);
        
        if (tone_a_match && tone_b_match) {
            printf("\n🎯 [ALERT DETECTED] Tone sequence matched!\n");
            printf("   📊 Alert ID: %s\n", tone_def->tone_id);
            printf("   🔊 Tone A: %.1f Hz (expected: %.1f Hz ±%d Hz)\n", 
                   tone_a_freq, tone_def->tone_a_freq, tone_a_tolerance);
            printf("   🔊 Tone B: %.1f Hz (expected: %.1f Hz ±%d Hz)\n", 
                   tone_b_freq, tone_def->tone_b_freq, tone_b_tolerance);
            printf("   ⚡ Triggering alert playback...\n\n");
            
            // Start or extend recording if configured
            if (tone_def->record_length_ms > 0) {
                start_recording_timer(tone_def->record_length_ms);
            }
            
            // Trigger tone passthrough if configured
            trigger_tone_passthrough();
            
            free(tone_a_segment);
            free(tone_b_segment);
            return 1; // Tone detected
        }
        
        free(tone_a_segment);
        free(tone_b_segment);
    }
    
    return 0; // No tone detected
}

// Single tone detection for passthrough (not A+B pair)
int detect_single_tone_for_passthrough(const float* samples, int sample_count) {
    // Add samples to sliding buffer
    add_audio_to_sliding_buffer(samples, sample_count);
    
    // Check if we have enough audio data
    if (audio_buffer_size < SAMPLE_RATE) { // Need at least 1 second
        return 0;
    }
    
    // Calculate volume level
    float volume = calculate_volume_level();
    
    // Only process if volume is above threshold
    if (volume < global_tone_detection.config.db_threshold) {
        return 0;
    }
    
    // Check each tone definition for individual tone detection
    for (int t = 0; t < MAX_TONE_DEFINITIONS; t++) {
        struct tone_definition* tone_def = &global_tone_detection.tone_definitions[t];
        if (!tone_def->valid) continue;
        
        // Check Tone A individually
        if (tone_def->tone_a_length_ms > 0) {
            int tone_a_samples = (int)(tone_def->tone_a_length_ms * SAMPLE_RATE / 1000.0f);
            if (audio_buffer_size >= tone_a_samples) {
                float* tone_a_segment = malloc(tone_a_samples * sizeof(float));
                if (tone_a_segment) {
                    get_audio_segment(tone_a_samples, tone_a_samples, tone_a_segment);
                    float tone_a_freq = freq_from_fft(tone_a_segment, tone_a_samples, SAMPLE_RATE);
                    
                    int tone_a_tolerance = tone_def->tone_a_range_hz;
                    int tone_a_match = (fabs(tone_a_freq - tone_def->tone_a_freq) < tone_a_tolerance);
                    
                    if (tone_a_match) {
                        printf("\n🎯 [SINGLE TONE DETECTED] Tone A: %.1f Hz (ID: %s)\n", 
                               tone_a_freq, tone_def->tone_id);
                        
                        // Start or extend recording
                        if (tone_def->record_length_ms > 0) {
                            start_recording_timer(tone_def->record_length_ms);
                        }
                        
                        // Play alert tone with duration from config.json record_length
                        extern int get_passthrough_target_channel_index(void);
                        extern int channel_has_output_stream(int channel_index);
                        int target_channel_idx = get_passthrough_target_channel_index();
                        if (target_channel_idx >= 0 && channel_has_output_stream(target_channel_idx)) {
                            float alert_duration = (float)tone_def->record_length_ms;
                            if (global_alert_playback.active) {
                                printf("[ALERT] Interrupting current alert to play new %.1f-second tone at %.1f Hz\n", 
                                       alert_duration / 1000.0f, tone_a_freq);
                            } else {
                                printf("[ALERT] Playing %.1f-second alert tone at %.1f Hz\n", 
                                       alert_duration / 1000.0f, tone_a_freq);
                            }
                            play_alert_tone_locally(target_channel_idx, tone_a_freq, tone_a_freq, alert_duration, 0);
                        }
                        
                        free(tone_a_segment);
                        return 1; // Tone detected
                    }
                    free(tone_a_segment);
                }
            }
        }
        
        // Check Tone B individually
        if (tone_def->tone_b_length_ms > 0) {
            int tone_b_samples = (int)(tone_def->tone_b_length_ms * SAMPLE_RATE / 1000.0f);
            if (audio_buffer_size >= tone_b_samples) {
                float* tone_b_segment = malloc(tone_b_samples * sizeof(float));
                if (tone_b_segment) {
                    get_audio_segment(tone_b_samples, tone_b_samples, tone_b_segment);
                    float tone_b_freq = freq_from_fft(tone_b_segment, tone_b_samples, SAMPLE_RATE);
                    
                    int tone_b_tolerance = tone_def->tone_b_range_hz;
                    int tone_b_match = (fabs(tone_b_freq - tone_def->tone_b_freq) < tone_b_tolerance);
                    
                    if (tone_b_match) {
                        printf("\n🎯 [SINGLE TONE DETECTED] Tone B: %.1f Hz (ID: %s)\n", 
                               tone_b_freq, tone_def->tone_id);
                        
                        // Start or extend recording
                        if (tone_def->record_length_ms > 0) {
                            start_recording_timer(tone_def->record_length_ms);
                        }
                        
                        // Play alert tone with duration from config.json record_length
                        extern int get_passthrough_target_channel_index(void);
                        extern int channel_has_output_stream(int channel_index);
                        int target_channel_idx = get_passthrough_target_channel_index();
                        if (target_channel_idx >= 0 && channel_has_output_stream(target_channel_idx)) {
                            float alert_duration = (float)tone_def->record_length_ms;
                            if (global_alert_playback.active) {
                                printf("[ALERT] Interrupting current alert to play new %.1f-second tone at %.1f Hz\n", 
                                       alert_duration / 1000.0f, tone_b_freq);
                            } else {
                                printf("[ALERT] Playing %.1f-second alert tone at %.1f Hz\n", 
                                       alert_duration / 1000.0f, tone_b_freq);
                            }
                            play_alert_tone_locally(target_channel_idx, tone_b_freq, tone_b_freq, alert_duration, 0);
                        }
                        
                        free(tone_b_segment);
                        return 1; // Tone detected
                    }
                    free(tone_b_segment);
                }
            }
        }
    }
    
    return 0; // No single tone detected
}


// Recording timer management functions
int start_recording_timer(int record_length_ms) {
    pthread_mutex_lock(&global_tone_detection.mutex);
    
    int current_time = get_current_time_ms();
    
    if (global_tone_detection.recording_active) {
        // Recording is already active - check if we should extend the duration
        int elapsed = current_time - global_tone_detection.recording_start_time;
        int remaining_time = global_tone_detection.recording_duration_ms - elapsed;
        
        printf("[RECORDING] Overlapping detection: %d ms elapsed, %d ms remaining, new tone: %d ms\n", 
               elapsed, remaining_time, record_length_ms);
        
        // Use the longer of remaining time vs new tone length
        if (record_length_ms > remaining_time) {
            printf("[RECORDING] Timer extended: %d ms remaining -> %d ms (new tone longer)\n", 
                   remaining_time, record_length_ms);
            global_tone_detection.recording_duration_ms = record_length_ms;
        } else {
            printf("[RECORDING] Timer unchanged: %d ms remaining (current recording longer)\n", 
                   remaining_time);
        }
    } else {
        // Start new recording
        printf("[RECORDING] Started: %d ms duration\n", record_length_ms);
        global_tone_detection.recording_active = 1;
        global_tone_detection.recording_start_time = current_time;
        global_tone_detection.recording_duration_ms = record_length_ms;
    }
    
    pthread_mutex_unlock(&global_tone_detection.mutex);
    return 1;
}

void stop_recording_timer(void) {
    pthread_mutex_lock(&global_tone_detection.mutex);
    global_tone_detection.recording_active = 0;
    printf("[RECORDING] Timer stopped\n");
    pthread_mutex_unlock(&global_tone_detection.mutex);
}

int is_recording_active(void) {
    pthread_mutex_lock(&global_tone_detection.mutex);
    int active = global_tone_detection.recording_active;
    pthread_mutex_unlock(&global_tone_detection.mutex);
    return active;
}

int get_recording_time_remaining_ms(void) {
    pthread_mutex_lock(&global_tone_detection.mutex);
    
    if (!global_tone_detection.recording_active) {
        pthread_mutex_unlock(&global_tone_detection.mutex);
        return 0;
    }
    
    int current_time = get_current_time_ms();
    int elapsed = current_time - global_tone_detection.recording_start_time;
    int remaining = global_tone_detection.recording_duration_ms - elapsed;
    
    if (remaining < 0) remaining = 0;
    
    pthread_mutex_unlock(&global_tone_detection.mutex);
    return remaining;
}
