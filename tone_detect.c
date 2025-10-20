#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "tone_detect.h"
#include "audio.h"
#include "config.h"
#include <math.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

// Global tone detection state
tone_detect_control_t global_tone_detect = {0};
passthrough_audio_buffer_t global_passthrough_buffer = {0};
tone_detection_state_t global_tone_detection = {0};
audio_passthrough_t global_passthrough = {0};
tone_passthrough_control_t global_tone_passthrough = {0};
int force_passthrough_reevaluation = 0;

// Forward declarations
static int initialize_fft(void);
static void cleanup_fft(void);
static int process_tone_sequences(double current_time_ms);
static int find_local_maxima(double *magnitude_spectrum, int spectrum_size, 
                            peak_t *peaks, int max_peaks);
static int compare_peaks(const void *a, const void *b);

// Initialize tone detection system
int init_tone_detection(void) {
    printf("[TONE_DETECT] Initializing tone detection system...\n");
    
    // Initialize global tone detection control
    memset(&global_tone_detect, 0, sizeof(tone_detect_control_t));
    global_tone_detect.enabled = 1;
    global_tone_detect.card1_input_enabled = 1;
    global_tone_detect.passthrough_mode = 0;
    pthread_mutex_init(&global_tone_detect.mutex, NULL);
    
    // Initialize passthrough buffer
    memset(&global_passthrough_buffer, 0, sizeof(passthrough_audio_buffer_t));
    pthread_mutex_init(&global_passthrough_buffer.mutex, NULL);
    
    // Initialize tone detection state
    memset(&global_tone_detection, 0, sizeof(tone_state_t));
    global_tone_detection.thread_running = 0;
    pthread_mutex_init(&global_tone_detection.state_mutex, NULL);
    pthread_cond_init(&global_tone_detection.data_ready, NULL);
    
    // Initialize FFT
    if (!initialize_fft()) {
        printf("[ERROR] Failed to initialize FFT\n");
        return 0;
    }
    
    // Load tone detection configuration
    if (!load_tone_detection_config()) {
        printf("[WARNING] Failed to load tone detection configuration\n");
        return 0;
    }
    
    printf("[TONE_DETECT] Tone detection system initialized successfully\n");
    return 1;
}

// Initialize FFT system
static int initialize_fft(void) {
    printf("[TONE_DETECT] Initializing FFT system...\n");
    
    // Allocate FFT buffers
    global_tone_detection.fft_input = fftw_malloc(FFT_SIZE * sizeof(fftw_complex));
    global_tone_detection.fft_output = fftw_malloc(FFT_SIZE * sizeof(fftw_complex));
    global_tone_detection.magnitude_spectrum = malloc((FFT_SIZE / 2) * sizeof(double));
    
    if (!global_tone_detection.fft_input || 
        !global_tone_detection.fft_output || 
        !global_tone_detection.magnitude_spectrum) {
        printf("[ERROR] Failed to allocate FFT buffers\n");
        cleanup_fft();
        return 0;
    }
    
    // Create FFT plan
    global_tone_detection.fft_plan = fftw_plan_dft_1d(FFT_SIZE, 
                                                     global_tone_detection.fft_input,
                                                     global_tone_detection.fft_output,
                                                     FFTW_FORWARD, FFTW_ESTIMATE);
    
    if (!global_tone_detection.fft_plan) {
        printf("[ERROR] Failed to create FFT plan\n");
        cleanup_fft();
        return 0;
    }
    
    printf("[TONE_DETECT] FFT system initialized (size=%d, resolution=%.2f Hz)\n", 
           FFT_SIZE, FREQ_RESOLUTION);
    return 1;
}

// Cleanup FFT system
static void cleanup_fft(void) {
    if (global_tone_detection.fft_plan) {
        fftw_destroy_plan(global_tone_detection.fft_plan);
        global_tone_detection.fft_plan = NULL;
    }
    
    if (global_tone_detection.fft_input) {
        fftw_free(global_tone_detection.fft_input);
        global_tone_detection.fft_input = NULL;
    }
    
    if (global_tone_detection.fft_output) {
        fftw_free(global_tone_detection.fft_output);
        global_tone_detection.fft_output = NULL;
    }
    
    if (global_tone_detection.magnitude_spectrum) {
        free(global_tone_detection.magnitude_spectrum);
        global_tone_detection.magnitude_spectrum = NULL;
    }
}

// Start tone detection thread
int start_tone_detection(void) {
    if (global_tone_detection.thread_running) {
        printf("[WARNING] Tone detection thread already running\n");
        return 1;
    }
    
    printf("[TONE_DETECT] Starting tone detection thread...\n");
    
    // Create detection thread
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, TONE_DETECTION_THREAD_STACK_SIZE);
    
    int result = pthread_create(&global_tone_detection.detection_thread, &thread_attr, 
                               tone_detection_thread, NULL);
    if (result != 0) {
        printf("[ERROR] Failed to create tone detection thread (error %d: %s)\n", 
               result, strerror(result));
        pthread_attr_destroy(&thread_attr);
        return 0;
    }
    
    printf("[TONE_DETECT] Thread creation successful, waiting for thread to start...\n");
    
    pthread_attr_destroy(&thread_attr);
    global_tone_detection.thread_running = 1;
    
    // Give the thread a moment to start
    usleep(100000); // 100ms delay
    
    printf("[TONE_DETECT] Tone detection thread started successfully\n");
    return 1;
}

// Stop tone detection thread
int stop_tone_detection(void) {
    if (!global_tone_detection.thread_running) {
        return 1;
    }
    
    printf("[TONE_DETECT] Stopping tone detection thread...\n");
    
    global_tone_detection.thread_running = 0;
    
    // Signal the thread to wake up
    pthread_mutex_lock(&global_tone_detection.state_mutex);
    pthread_cond_signal(&global_tone_detection.data_ready);
    pthread_mutex_unlock(&global_tone_detection.state_mutex);
    
    // Wait for thread to finish
    pthread_join(global_tone_detection.detection_thread, NULL);
    
    printf("[TONE_DETECT] Tone detection thread stopped\n");
    return 1;
}

// Cleanup tone detection system
void cleanup_tone_detection(void) {
    printf("[TONE_DETECT] Cleaning up tone detection system...\n");
    
    // Stop detection thread
    stop_tone_detection();
    
    // Cleanup FFT
    cleanup_fft();
    
    // Cleanup mutexes and conditions
    pthread_mutex_destroy(&global_tone_detection.state_mutex);
    pthread_cond_destroy(&global_tone_detection.data_ready);
    pthread_mutex_destroy(&global_tone_detect.mutex);
    pthread_mutex_destroy(&global_passthrough_buffer.mutex);
    
    printf("[TONE_DETECT] Tone detection system cleaned up\n");
}

// Main tone detection thread
void* tone_detection_thread(void *arg) {
    (void)arg; // Suppress unused parameter warning
    
    printf("[TONE_DETECT] Tone detection thread started\n");
    
    float audio_buffer[FFT_SIZE];
    int buffer_pos = 0;
    struct timespec last_analysis = {0};
    (void)last_analysis; // Suppress unused variable warning
    
    while (global_tone_detection.thread_running && !global_interrupted) {
        // Check if tone detection is enabled
        if (!is_tone_detect_enabled()) {
            usleep(10000); // 10ms delay when disabled
            continue;
        }
        
        // Get audio data from shared buffer
        pthread_mutex_lock(&global_shared_buffer.mutex);
        
        if (global_shared_buffer.valid && global_shared_buffer.sample_count > 0) {
            static int buffer_count = 0;
            buffer_count++;
            if (buffer_count % 50 == 0) {  // Print every 50 buffer updates
                printf("[TONE_DETECT] Received audio buffer #%d (samples=%d, buffer_pos=%d)\n", 
                       buffer_count, global_shared_buffer.sample_count, buffer_pos);
            }
            
            // Copy samples to our processing buffer
            int samples_to_copy = global_shared_buffer.sample_count;
            if (samples_to_copy > FFT_SIZE - buffer_pos) {
                samples_to_copy = FFT_SIZE - buffer_pos;
            }
            
            for (int i = 0; i < samples_to_copy; i++) {
                audio_buffer[buffer_pos + i] = global_shared_buffer.samples[i];
            }
            
            buffer_pos += samples_to_copy;
            global_shared_buffer.valid = 0; // Mark as consumed
            
            // Process when we have enough samples
            if (buffer_pos >= FFT_SIZE) {
                static int frame_count = 0;
                frame_count++;
                if (frame_count % 100 == 0) {  // Print every 100 frames (about every 2 seconds)
                    printf("[TONE_DETECT] Processing audio frame #%d (FFT analysis)\n", frame_count);
                }
                process_audio_frame(audio_buffer, FFT_SIZE);
                buffer_pos = 0; // Reset buffer
            }
        } else {
            // Wait for new data
            static int wait_count = 0;
            wait_count++;
            if (wait_count % 100 == 0) {  // Print every 100 waits (about every 1 second)
                printf("[TONE_DETECT] Waiting for audio data... (wait #%d)\n", wait_count);
            }
            if (wait_count % 100 == 0) {  // Print every 100 waits
                printf("[TONE_DETECT] About to wait on condition variable...\n");
            }
            pthread_cond_wait(&global_shared_buffer.data_ready, &global_shared_buffer.mutex);
            if (wait_count % 100 == 0) {  // Print every 100 waits
                printf("[TONE_DETECT] Woke up from condition variable wait\n");
            }
        }
        
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Small delay to prevent overwhelming the system
        usleep(1000); // 1ms delay
    }
    
    printf("[TONE_DETECT] Tone detection thread stopped\n");
    return NULL;
}

// Process audio frame for tone detection
int process_audio_frame(float *samples, int sample_count) {
    if (sample_count != FFT_SIZE) {
        printf("[WARNING] Invalid sample count for tone detection: %d (expected %d)\n", 
               sample_count, FFT_SIZE);
        return 0;
    }
    
    // Perform FFT analysis
    if (!perform_fft_analysis(samples, sample_count)) {
        return 0;
    }
    
    // Detect peaks in frequency spectrum
    global_tone_detection.num_peaks = detect_peaks(global_tone_detection.magnitude_spectrum, 
                                                   FFT_SIZE / 2);
    
    // Match detected peaks to tone definitions
    if (global_tone_detection.num_peaks > 0) {
        match_tones_to_definitions(global_tone_detection.detected_peaks, 
                                  global_tone_detection.num_peaks);
    }
    
    // Process tone sequences
    double current_time_ms = get_current_time_ms();
    process_tone_sequences(current_time_ms);
    
    return 1;
}

// Perform FFT analysis on audio samples
int perform_fft_analysis(float *samples, int sample_count) {
    if (sample_count != FFT_SIZE) {
        return 0;
    }
    
    // Apply gain and prepare FFT input
    for (int i = 0; i < FFT_SIZE; i++) {
        // Apply gain (1.5x as specified in requirements)
        float sample = samples[i] * 1.5f;
        
        // Clamp to prevent overflow
        if (sample > 1.0f) sample = 1.0f;
        if (sample < -1.0f) sample = -1.0f;
        
        // Convert to complex format for FFT
        global_tone_detection.fft_input[i] = sample + 0.0 * I;
    }
    
    // Perform FFT
    fftw_execute(global_tone_detection.fft_plan);
    
    // Calculate magnitude spectrum
    for (int i = 0; i < FFT_SIZE / 2; i++) {
        double real = creal(global_tone_detection.fft_output[i]);
        double imag = cimag(global_tone_detection.fft_output[i]);
        global_tone_detection.magnitude_spectrum[i] = sqrt(real * real + imag * imag);
    }
    
    return 1;
}

// Detect peaks in magnitude spectrum
int detect_peaks(double *magnitude_spectrum, int spectrum_size) {
    if (spectrum_size != FFT_SIZE / 2) {
        return 0;
    }
    
    // Find local maxima
    int num_peaks = find_local_maxima(magnitude_spectrum, spectrum_size, 
                                     global_tone_detection.detected_peaks, MAX_PEAKS);
    
    // Sort peaks by magnitude (descending)
    qsort(global_tone_detection.detected_peaks, num_peaks, sizeof(peak_t), compare_peaks);
    
    // Debug: Show detected peaks
    if (num_peaks > 0) {
        static int peak_debug_count = 0;
        peak_debug_count++;
        if (peak_debug_count % 50 == 0) {  // Print every 50 detections
            printf("[TONE_DETECT] Detected %d peaks: ", num_peaks);
            for (int i = 0; i < num_peaks && i < 3; i++) {
                double freq = global_tone_detection.detected_peaks[i].frequency;
                double db = magnitude_to_db(global_tone_detection.detected_peaks[i].magnitude);
                printf("%.1fHz(%.1fdB) ", freq, db);
            }
            printf("\n");
        }
    }
    
    return num_peaks;
}

// Find local maxima in magnitude spectrum
static int find_local_maxima(double *magnitude_spectrum, int spectrum_size, 
                            peak_t *peaks, int max_peaks) {
    int num_peaks = 0;
    const double MIN_PEAK_DB = -45.0; // Minimum dB threshold
    
    for (int i = 1; i < spectrum_size - 1 && num_peaks < max_peaks; i++) {
        double magnitude = magnitude_spectrum[i];
        double magnitude_db = magnitude_to_db(magnitude);
        
        // Check if this is a local maximum and above threshold
        if (magnitude > magnitude_spectrum[i-1] && 
            magnitude > magnitude_spectrum[i+1] && 
            magnitude_db > MIN_PEAK_DB) {
            
            peaks[num_peaks].bin_index = i;
            peaks[num_peaks].frequency = bin_to_frequency(i);
            peaks[num_peaks].magnitude = magnitude;
            peaks[num_peaks].magnitude_db = magnitude_db;
            num_peaks++;
        }
    }
    
    return num_peaks;
}

// Compare peaks by magnitude (for sorting)
static int compare_peaks(const void *a, const void *b) {
    const peak_t *peak_a = (const peak_t*)a;
    const peak_t *peak_b = (const peak_t*)b;
    
    if (peak_a->magnitude > peak_b->magnitude) return -1;
    if (peak_a->magnitude < peak_b->magnitude) return 1;
    return 0;
}

// Match detected peaks to tone definitions
int match_tones_to_definitions(peak_t *peaks, int num_peaks) {
    double current_time_ms = get_current_time_ms();
    
    // Process each active tone sequence
    for (int i = 0; i < global_tone_detection.num_active_sequences; i++) {
        tone_sequence_state_t *sequence = &global_tone_detection.sequences[i];
        
        if (!sequence->definition || !sequence->definition->valid) {
            continue;
        }
        
        // Check for tone matches
        for (int j = 0; j < num_peaks; j++) {
            double detected_freq = peaks[j].frequency;
            double magnitude_db = peaks[j].magnitude_db;
            
            // Check if this peak matches tone A or tone B
            if (sequence->state == TONE_STATE_IDLE || sequence->state == TONE_STATE_DETECTING_A) {
                if (is_frequency_in_range(detected_freq, sequence->definition->tone_a_freq, 
                                         sequence->definition->tone_a_range_hz)) {
                    update_tone_sequence_state(sequence, current_time_ms, detected_freq, magnitude_db);
                }
            } else if (sequence->state == TONE_STATE_DETECTING_B) {
                if (is_frequency_in_range(detected_freq, sequence->definition->tone_b_freq, 
                                         sequence->definition->tone_b_range_hz)) {
                    update_tone_sequence_state(sequence, current_time_ms, detected_freq, magnitude_db);
                }
            }
        }
    }
    
    return 1;
}

// Process tone sequences and handle state transitions
static int process_tone_sequences(double current_time_ms) {
    for (int i = 0; i < global_tone_detection.num_active_sequences; i++) {
        tone_sequence_state_t *sequence = &global_tone_detection.sequences[i];
        
        if (!sequence->definition || !sequence->definition->valid) {
            continue;
        }
        
        // Check for sequence timeout
        if (check_sequence_timeout(sequence, current_time_ms)) {
            // Reset sequence on timeout
            sequence->state = TONE_STATE_IDLE;
            sequence->tone_a_confirmed = 0;
            sequence->tone_b_confirmed = 0;
            sequence->tone_a_detected_duration_ms = 0;
            sequence->tone_b_detected_duration_ms = 0;
            continue;
        }
        
        // Handle state transitions
        switch (sequence->state) {
            case TONE_STATE_DETECTING_A:
                if (sequence->tone_a_confirmed) {
                    sequence->state = TONE_STATE_DETECTING_B;
                    sequence->sequence_start_time_ms = current_time_ms;
                    printf("[TONE_DETECT] Tone A confirmed, now detecting tone B (%.1f Hz)\n", 
                           sequence->definition->tone_b_freq);
                }
                break;
                
            case TONE_STATE_DETECTING_B:
                if (sequence->tone_b_confirmed) {
                    sequence->state = TONE_STATE_RECORDING;
                    sequence->recording_active = 1;
                    sequence->recording_start_time_ms = current_time_ms;
                    printf("[TONE_DETECT] Tone sequence detected! Starting recording for %.1f ms\n", 
                           sequence->definition->record_length_ms);
                    
                    // Trigger tone playback
                    trigger_tone_playback(sequence->definition);
                }
                break;
                
            case TONE_STATE_RECORDING:
                // Check if recording should stop
                if (current_time_ms - sequence->recording_start_time_ms >= sequence->definition->record_length_ms) {
                    sequence->state = TONE_STATE_IDLE;
                    sequence->recording_active = 0;
                    printf("[TONE_DETECT] Recording completed for tone sequence\n");
                }
                break;
                
            default:
                break;
        }
    }
    
    return 1;
}

// Update tone sequence state based on detected frequency
int update_tone_sequence_state(tone_sequence_state_t *sequence, 
                               double current_time_ms, 
                               double detected_freq, 
                               double magnitude_db) {
    (void)magnitude_db; // Suppress unused parameter warning
    if (!sequence->definition) {
        return 0;
    }
    
    // Check if this is tone A
    if (is_frequency_in_range(detected_freq, sequence->definition->tone_a_freq, 
                             sequence->definition->tone_a_range_hz)) {
        if (sequence->state == TONE_STATE_IDLE) {
            sequence->state = TONE_STATE_DETECTING_A;
            sequence->sequence_start_time_ms = current_time_ms;
            sequence->tone_a_detected_duration_ms = 0;
            sequence->tone_a_confirmed = 0;
            printf("[TONE_DETECT] Started detecting tone A (%.1f Hz)\n", detected_freq);
        }
        
        // Update duration
        sequence->tone_a_detected_duration_ms += (1000.0 / SAMPLE_RATE) * FFT_SIZE;
        sequence->last_detection_time_ms = current_time_ms;
        
        // Check if tone A duration requirement is met
        if (sequence->tone_a_detected_duration_ms >= sequence->definition->tone_a_length_ms) {
            sequence->tone_a_confirmed = 1;
            printf("[TONE_DETECT] Tone A confirmed (%.1f Hz, %.1f ms)\n", 
                   detected_freq, sequence->tone_a_detected_duration_ms);
        }
    }
    
    // Check if this is tone B
    if (is_frequency_in_range(detected_freq, sequence->definition->tone_b_freq, 
                             sequence->definition->tone_b_range_hz)) {
        if (sequence->state == TONE_STATE_DETECTING_B) {
            // Update duration
            sequence->tone_b_detected_duration_ms += (1000.0 / SAMPLE_RATE) * FFT_SIZE;
            sequence->last_detection_time_ms = current_time_ms;
            
            // Check if tone B duration requirement is met
            if (sequence->tone_b_detected_duration_ms >= sequence->definition->tone_b_length_ms) {
                sequence->tone_b_confirmed = 1;
                printf("[TONE_DETECT] Tone B confirmed (%.1f Hz, %.1f ms)\n", 
                       detected_freq, sequence->tone_b_detected_duration_ms);
            }
        }
    }
    
    return 1;
}

// Check if tone sequence has timed out
int check_sequence_timeout(tone_sequence_state_t *sequence, double current_time_ms) {
    if (sequence->state == TONE_STATE_IDLE) {
        return 0;
    }
    
    // Check for timeout
    if (current_time_ms - sequence->last_detection_time_ms > SEQUENCE_TIMEOUT_MS) {
        printf("[TONE_DETECT] Tone sequence timed out\n");
        return 1;
    }
    
    return 0;
}

// Generate tone samples
int generate_tone_samples(float *samples, int sample_count, double frequency, double duration_ms, double sample_rate) {
    if (!samples || sample_count <= 0) {
        return 0;
    }
    
    int samples_to_generate = (int)(duration_ms * sample_rate / 1000.0);
    if (samples_to_generate > sample_count) {
        samples_to_generate = sample_count;
    }
    
    double phase_increment = 2.0 * M_PI * frequency / sample_rate;
    double phase = 0.0;
    
    for (int i = 0; i < samples_to_generate; i++) {
        samples[i] = 0.3f * sin(phase); // 0.3 amplitude to prevent clipping
        phase += phase_increment;
        
        // Keep phase in range [0, 2π]
        if (phase >= 2.0 * M_PI) {
            phase -= 2.0 * M_PI;
        }
    }
    
    // Fill remaining samples with silence
    for (int i = samples_to_generate; i < sample_count; i++) {
        samples[i] = 0.0f;
    }
    
    return samples_to_generate;
}

// Trigger tone playback to target channel
int trigger_tone_playback(tone_definition_t *definition) {
    if (!definition || !definition->valid) {
        return 0;
    }
    
    printf("[TONE_DETECT] Triggering tone playback for sequence %.1f Hz -> %.1f Hz\n", 
           definition->tone_a_freq, definition->tone_b_freq);
    
    // Get the passthrough target channel
    int target_channel = get_passthrough_target_channel_index();
    if (target_channel < 0) {
        printf("[WARNING] No passthrough target channel configured\n");
        return 0;
    }
    
    // Enable passthrough mode for the target channel
    set_passthrough_output_mode(1);
    
    // Generate tone sequence and copy to passthrough buffer
    pthread_mutex_lock(&global_passthrough_buffer.mutex);
    
    float tone_samples[SAMPLES_PER_FRAME];
    int samples_generated = 0;
    
    // Generate tone A followed by tone B
    int tone_a_samples = generate_tone_samples(tone_samples, SAMPLES_PER_FRAME / 2, 
                                              definition->tone_a_freq, 
                                              definition->tone_a_length_ms, 
                                              SAMPLE_RATE);
    
    int tone_b_samples = generate_tone_samples(tone_samples + tone_a_samples, 
                                              SAMPLES_PER_FRAME - tone_a_samples,
                                              definition->tone_b_freq, 
                                              definition->tone_b_length_ms, 
                                              SAMPLE_RATE);
    
    samples_generated = tone_a_samples + tone_b_samples;
    
    // Copy generated tones to passthrough buffer
    for (int i = 0; i < samples_generated && i < SAMPLES_PER_FRAME; i++) {
        global_passthrough_buffer.samples[i] = tone_samples[i];
    }
    
    // Fill remaining with silence
    for (int i = samples_generated; i < SAMPLES_PER_FRAME; i++) {
        global_passthrough_buffer.samples[i] = 0.0f;
    }
    
    global_passthrough_buffer.sample_count = SAMPLES_PER_FRAME;
    global_passthrough_buffer.valid = 1;
    
    pthread_mutex_unlock(&global_passthrough_buffer.mutex);
    
    printf("[TONE_DETECT] Generated %d tone samples (%.1f Hz -> %.1f Hz) on channel %d\n", 
           samples_generated, definition->tone_a_freq, definition->tone_b_freq, target_channel);
    return 1;
}

// Start recording (placeholder for future implementation)
int start_recording(tone_definition_t *definition) {
    (void)definition; // Suppress unused parameter warning
    printf("[TONE_DETECT] Recording started (placeholder implementation)\n");
    return 1;
}

// Utility function to get current time in milliseconds
double get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

// Convert FFT bin index to frequency
double bin_to_frequency(int bin_index) {
    return (double)bin_index * FREQ_RESOLUTION;
}

// Convert frequency to FFT bin index
int frequency_to_bin(double frequency) {
    return (int)round(frequency / FREQ_RESOLUTION);
}

// Convert magnitude to dB
double magnitude_to_db(double magnitude) {
    if (magnitude <= 0.0) {
        return -100.0; // Very low dB for zero magnitude
    }
    return 20.0 * log10(magnitude);
}

// Check if detected frequency is within range of target frequency
int is_frequency_in_range(double detected_freq, double target_freq, double tolerance) {
    return (fabs(detected_freq - target_freq) <= tolerance);
}

// Control functions are defined in audio.c to avoid multiple definitions

// Create default tone detection configuration
static int create_default_tone_config(void) {
    printf("[TONE_DETECT] Creating default tone detection configuration\n");
    
    // Initialize default configuration for all channels
    for (int i = 0; i < MAX_CHANNELS; i++) {
        tone_detect_config_t *config = &global_tone_detection.configs[i];
        memset(config, 0, sizeof(tone_detect_config_t));
        
        // Set default values
        config->valid = 1;
        config->tone_passthrough = 0;  // Disabled by default
        strcpy(config->passthrough_channel, "channel_one");
        
        // Add some default tone definitions
        config->num_alert_tones = 1;
        
        // Default tone definition: 1000Hz -> 2000Hz sequence
        config->alert_tones[0].valid = 1;
        config->alert_tones[0].tone_a_freq = 1000.0;
        config->alert_tones[0].tone_b_freq = 2000.0;
        config->alert_tones[0].tone_a_length_ms = 100.0;
        config->alert_tones[0].tone_b_length_ms = 100.0;
        config->alert_tones[0].tone_a_range_hz = 50.0;
        config->alert_tones[0].tone_b_range_hz = 50.0;
        config->alert_tones[0].record_length_ms = 1000.0;
        strcpy(config->alert_tones[0].tone_id, "Default_Sequence");
        
        // Alert details
        config->alert_details.threshold = 0.5;
        config->alert_details.gain = 1.0;
        config->alert_details.db_threshold = -40.0;
        config->alert_details.detect_new_tones = 1;
        config->alert_details.new_tone_length_ms = 100.0;
        config->alert_details.new_tone_range_hz = 50.0;
        config->num_filters = 0;
    }
    
    printf("[TONE_DETECT] Default configuration created successfully\n");
    printf("[TONE_DETECT] Configured tone sequence: 1000Hz -> 2000Hz\n");
    printf("[TONE_DETECT] Tolerance: ±50Hz, Duration: 100ms each\n");
    return 1;
}

// Load tone detection configuration from JSON
int load_tone_detection_config(void) {
    const char* config_path = "/home/will/.an/config.json";
    printf("[TONE_DETECT] Loading tone detection configuration from %s\n", config_path);
    
    FILE *file = fopen(config_path, "r");
    if (!file) {
        printf("[ERROR] Could not open config file %s: %s\n", config_path, strerror(errno));
        return 0;
    }
    
    // Read the entire file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        printf("[ERROR] Memory allocation failed for config file\n");
        return 0;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);
    
    // Parse JSON
    cJSON *json = cJSON_Parse(json_string);
    free(json_string);
    
    if (!json) {
        printf("[WARNING] Failed to parse config JSON, using default tone detection configuration\n");
        return create_default_tone_config();
    }
    
    // Try to navigate to software configuration, but provide fallback
    cJSON *shadow = cJSON_GetObjectItemCaseSensitive(json, "shadow");
    cJSON *state = NULL;
    
    if (cJSON_IsObject(shadow)) {
        state = cJSON_GetObjectItemCaseSensitive(shadow, "state");
    }
    
    if (!cJSON_IsObject(state)) {
        printf("[WARNING] No shadow.state object in config, using default tone detection configuration\n");
        // Create a default configuration
        cJSON_Delete(json);
        return create_default_tone_config();
    }
    
    cJSON *desired = cJSON_GetObjectItemCaseSensitive(state, "desired");
    if (!cJSON_IsObject(desired)) {
        printf("[ERROR] No desired object in config\n");
        cJSON_Delete(json);
        return 0;
    }
    
    cJSON *software_config = cJSON_GetObjectItemCaseSensitive(desired, "software_configuration");
    if (!cJSON_IsArray(software_config) || cJSON_GetArraySize(software_config) == 0) {
        printf("[ERROR] No software_configuration array in config\n");
        cJSON_Delete(json);
        return 0;
    }
    
    cJSON *config_item = cJSON_GetArrayItem(software_config, 0);
    if (!cJSON_IsObject(config_item)) {
        printf("[ERROR] No configuration item in software_configuration\n");
        cJSON_Delete(json);
        return 0;
    }
    
    // Process each channel
    const char* channel_keys[] = {"channel_one", "channel_two", "channel_three", "channel_four"};
    int channels_loaded = 0;
    
    for (int i = 0; i < 4; i++) {
        cJSON *channel_obj = cJSON_GetObjectItemCaseSensitive(config_item, channel_keys[i]);
        if (cJSON_IsObject(channel_obj)) {
            tone_detect_config_t *config = &global_tone_detection.configs[i];
            memset(config, 0, sizeof(tone_detect_config_t));
            
            // Load basic channel info
            cJSON *channel_id = cJSON_GetObjectItemCaseSensitive(channel_obj, "channel_id");
            if (cJSON_IsString(channel_id)) {
                strncpy(config->passthrough_channel, cJSON_GetStringValue(channel_id), 63);
                config->passthrough_channel[63] = '\0';
            }
            
            // Load tone detection settings
            cJSON *tone_detect = cJSON_GetObjectItemCaseSensitive(channel_obj, "tone_detect");
            if (cJSON_IsBool(tone_detect)) {
                if (cJSON_IsTrue(tone_detect)) {
                    // Load tone detection configuration
                    cJSON *tone_config = cJSON_GetObjectItemCaseSensitive(channel_obj, "tone_detect_configuration");
                    if (cJSON_IsObject(tone_config)) {
                        // Load tone passthrough settings
                        cJSON *tone_passthrough = cJSON_GetObjectItemCaseSensitive(tone_config, "tone_passthrough");
                        if (cJSON_IsBool(tone_passthrough)) {
                            config->tone_passthrough = cJSON_IsTrue(tone_passthrough);
                        }
                        
                        cJSON *passthrough_channel = cJSON_GetObjectItemCaseSensitive(tone_config, "passthrough_channel");
                        if (cJSON_IsString(passthrough_channel)) {
                            strncpy(config->passthrough_channel, cJSON_GetStringValue(passthrough_channel), 63);
                            config->passthrough_channel[63] = '\0';
                        }
                        
                        // Load alert tones
                        cJSON *alert_tones = cJSON_GetObjectItemCaseSensitive(tone_config, "alert_tones");
                        if (cJSON_IsArray(alert_tones)) {
                            config->num_alert_tones = parse_tone_definitions(alert_tones, config->alert_tones, MAX_TONE_DEFINITIONS);
                            printf("[TONE_DETECT] Loaded %d alert tones for channel %d\n", config->num_alert_tones, i);
                        }
                        
                        // Load alert details
                        cJSON *alert_details = cJSON_GetObjectItemCaseSensitive(tone_config, "alert_details");
                        if (cJSON_IsObject(alert_details)) {
                            parse_alert_details(alert_details, &config->alert_details);
                        }
                        
                        // Load frequency filters
                        cJSON *filters = cJSON_GetObjectItemCaseSensitive(tone_config, "filter_frequencies");
                        if (cJSON_IsArray(filters)) {
                            config->num_filters = parse_frequency_filters(filters, config->filters, MAX_FILTERS);
                            printf("[TONE_DETECT] Loaded %d frequency filters for channel %d\n", config->num_filters, i);
                        }
                        
                        config->valid = 1;
                        channels_loaded++;
                        printf("[TONE_DETECT] Loaded tone detection config for channel %d (%s)\n", 
                               i, config->passthrough_channel);
                    }
                }
            }
        }
    }
    
    cJSON_Delete(json);
    
    if (channels_loaded > 0) {
        printf("[TONE_DETECT] Successfully loaded tone detection configuration for %d channels\n", channels_loaded);
        return 1;
    } else {
        printf("[WARNING] No tone detection configurations loaded\n");
        return 0;
    }
}

// Parse tone definitions from JSON array
int parse_tone_definitions(cJSON *tone_array, tone_definition_t *tones, int max_tones) {
    if (!cJSON_IsArray(tone_array)) {
        return 0;
    }
    
    int array_size = cJSON_GetArraySize(tone_array);
    int tones_loaded = 0;
    
    for (int i = 0; i < array_size && tones_loaded < max_tones; i++) {
        cJSON *tone_obj = cJSON_GetArrayItem(tone_array, i);
        if (!cJSON_IsObject(tone_obj)) {
            continue;
        }
        
        tone_definition_t *tone = &tones[tones_loaded];
        memset(tone, 0, sizeof(tone_definition_t));
        
        // Load tone ID
        cJSON *tone_id = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_id");
        if (cJSON_IsString(tone_id)) {
            strncpy(tone->tone_id, cJSON_GetStringValue(tone_id), 63);
            tone->tone_id[63] = '\0';
        }
        
        // Load tone A frequency
        cJSON *tone_a = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_a");
        if (cJSON_IsString(tone_a)) {
            tone->tone_a_freq = atof(cJSON_GetStringValue(tone_a));
        }
        
        // Load tone B frequency
        cJSON *tone_b = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_b");
        if (cJSON_IsString(tone_b)) {
            tone->tone_b_freq = atof(cJSON_GetStringValue(tone_b));
        }
        
        // Load tone A length
        cJSON *tone_a_length = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_a_length");
        if (cJSON_IsNumber(tone_a_length)) {
            tone->tone_a_length_ms = cJSON_GetNumberValue(tone_a_length) * 1000.0; // Convert to ms
        }
        
        // Load tone B length
        cJSON *tone_b_length = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_b_length");
        if (cJSON_IsNumber(tone_b_length)) {
            tone->tone_b_length_ms = cJSON_GetNumberValue(tone_b_length) * 1000.0; // Convert to ms
        }
        
        // Load tone A range
        cJSON *tone_a_range = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_a_range");
        if (cJSON_IsNumber(tone_a_range)) {
            tone->tone_a_range_hz = cJSON_GetNumberValue(tone_a_range);
        }
        
        // Load tone B range
        cJSON *tone_b_range = cJSON_GetObjectItemCaseSensitive(tone_obj, "tone_b_range");
        if (cJSON_IsNumber(tone_b_range)) {
            tone->tone_b_range_hz = cJSON_GetNumberValue(tone_b_range);
        }
        
        // Load record length
        cJSON *record_length = cJSON_GetObjectItemCaseSensitive(tone_obj, "record_length");
        if (cJSON_IsNumber(record_length)) {
            tone->record_length_ms = cJSON_GetNumberValue(record_length) * 1000.0; // Convert to ms
        }
        
        tone->valid = 1;
        tones_loaded++;
        
        printf("[TONE_DETECT] Loaded tone definition: %s (%.1f Hz -> %.1f Hz)\n", 
               tone->tone_id, tone->tone_a_freq, tone->tone_b_freq);
    }
    
    return tones_loaded;
}

// Parse frequency filters from JSON array
int parse_frequency_filters(cJSON *filter_array, frequency_filter_t *filters, int max_filters) {
    if (!cJSON_IsArray(filter_array)) {
        return 0;
    }
    
    int array_size = cJSON_GetArraySize(filter_array);
    int filters_loaded = 0;
    
    for (int i = 0; i < array_size && filters_loaded < max_filters; i++) {
        cJSON *filter_obj = cJSON_GetArrayItem(filter_array, i);
        if (!cJSON_IsObject(filter_obj)) {
            continue;
        }
        
        frequency_filter_t *filter = &filters[filters_loaded];
        memset(filter, 0, sizeof(frequency_filter_t));
        
        // Load filter ID
        cJSON *filter_id = cJSON_GetObjectItemCaseSensitive(filter_obj, "filter_id");
        if (cJSON_IsString(filter_id)) {
            strncpy(filter->filter_id, cJSON_GetStringValue(filter_id), 63);
            filter->filter_id[63] = '\0';
        }
        
        // Load frequency
        cJSON *frequency = cJSON_GetObjectItemCaseSensitive(filter_obj, "frequency");
        if (cJSON_IsNumber(frequency)) {
            filter->frequency = cJSON_GetNumberValue(frequency);
        }
        
        // Load filter range
        cJSON *filter_range = cJSON_GetObjectItemCaseSensitive(filter_obj, "filter_range");
        if (cJSON_IsNumber(filter_range)) {
            filter->filter_range = cJSON_GetNumberValue(filter_range);
        }
        
        // Load filter type
        cJSON *type = cJSON_GetObjectItemCaseSensitive(filter_obj, "type");
        if (cJSON_IsString(type)) {
            const char *type_str = cJSON_GetStringValue(type);
            if (strcmp(type_str, "below") == 0) {
                filter->type = FILTER_BELOW;
            } else if (strcmp(type_str, "above") == 0) {
                filter->type = FILTER_ABOVE;
            } else if (strcmp(type_str, "center") == 0) {
                filter->type = FILTER_CENTER;
            }
        }
        
        filter->valid = 1;
        filters_loaded++;
        
        printf("[TONE_DETECT] Loaded frequency filter: %s (%.1f Hz, %s)\n", 
               filter->filter_id, filter->frequency, 
               filter->type == FILTER_BELOW ? "below" : 
               filter->type == FILTER_ABOVE ? "above" : "center");
    }
    
    return filters_loaded;
}

// Parse alert details from JSON object
int parse_alert_details(cJSON *details_obj, alert_details_t *details) {
    if (!cJSON_IsObject(details_obj)) {
        return 0;
    }
    
    memset(details, 0, sizeof(alert_details_t));
    
    // Load threshold
    cJSON *threshold = cJSON_GetObjectItemCaseSensitive(details_obj, "threshold");
    if (cJSON_IsString(threshold)) {
        details->threshold = atof(cJSON_GetStringValue(threshold));
    }
    
    // Load gain
    cJSON *gain = cJSON_GetObjectItemCaseSensitive(details_obj, "gain");
    if (cJSON_IsString(gain)) {
        details->gain = atof(cJSON_GetStringValue(gain));
    }
    
    // Load dB threshold
    cJSON *db = cJSON_GetObjectItemCaseSensitive(details_obj, "db");
    if (cJSON_IsNumber(db)) {
        details->db_threshold = cJSON_GetNumberValue(db);
    }
    
    // Load detect new tones
    cJSON *detect_new_tones = cJSON_GetObjectItemCaseSensitive(details_obj, "detect_new_tones");
    if (cJSON_IsBool(detect_new_tones)) {
        details->detect_new_tones = cJSON_IsTrue(detect_new_tones);
    }
    
    // Load new tone length
    cJSON *new_tone_length = cJSON_GetObjectItemCaseSensitive(details_obj, "new_tone_length");
    if (cJSON_IsNumber(new_tone_length)) {
        details->new_tone_length_ms = cJSON_GetNumberValue(new_tone_length) * 1000.0; // Convert to ms
    }
    
    // Load new tone range
    cJSON *new_tone_range = cJSON_GetObjectItemCaseSensitive(details_obj, "new_tone_range");
    if (cJSON_IsNumber(new_tone_range)) {
        details->new_tone_range_hz = cJSON_GetNumberValue(new_tone_range);
    }
    
    printf("[TONE_DETECT] Loaded alert details: threshold=%.2f, gain=%.2f, db=%.1f\n", 
           details->threshold, details->gain, details->db_threshold);
    
    return 1;
}

// Get tone detection configuration for a specific channel
tone_detect_config_t* get_tone_detect_config(int channel_index) {
    if (channel_index >= 0 && channel_index < MAX_CHANNELS) {
        return &global_tone_detection.configs[channel_index];
    }
    return NULL;
}

// Apply frequency filters to magnitude spectrum
int apply_frequency_filters(double *magnitude_spectrum, int spectrum_size, 
                           frequency_filter_t *filters, int num_filters) {
    if (!magnitude_spectrum || spectrum_size != FFT_SIZE / 2) {
        return 0;
    }
    
    for (int f = 0; f < num_filters; f++) {
        frequency_filter_t *filter = &filters[f];
        if (!filter->valid) {
            continue;
        }
        
        int center_bin = frequency_to_bin(filter->frequency);
        (void)center_bin; // Suppress unused variable warning
        
        for (int i = 0; i < spectrum_size; i++) {
            double freq = bin_to_frequency(i);
            int should_zero = 0;
            
            switch (filter->type) {
                case FILTER_BELOW:
                    if (freq < filter->frequency) {
                        should_zero = 1;
                    }
                    break;
                    
                case FILTER_ABOVE:
                    if (freq > filter->frequency) {
                        should_zero = 1;
                    }
                    break;
                    
                case FILTER_CENTER:
                    if (fabs(freq - filter->frequency) > filter->filter_range) {
                        should_zero = 1;
                    }
                    break;
            }
            
            if (should_zero) {
                magnitude_spectrum[i] = 0.0;
            }
        }
    }
    
    return 1;
}

// Get passthrough target channel index
int get_passthrough_target_channel_index(void) {
    // Look for channel with tone_passthrough enabled
    for (int i = 0; i < MAX_CHANNELS; i++) {
        tone_detect_config_t *config = get_tone_detect_config(i);
        if (config && config->valid && config->tone_passthrough) {
            return i;
        }
    }
    return -1;
}

// Passthrough functions are defined in audio.c to avoid multiple definitions
