#include "tone_detect.h"
#include "config.h"
#include "audio.h"
#include <cjson/cJSON.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

// Global variables
tone_detect_control_t global_tone_detect = {0};
shared_audio_buffer_t global_shared_buffer = {0};
global_tone_passthrough_t global_tone_passthrough = {0};
int force_passthrough_reevaluation = 0;

// Tone detection configurations for each channel
static tone_detect_config_t tone_configs[MAX_CHANNELS] = {0};

// Threading variables
static pthread_t tone_detection_thread;
static volatile int thread_running = 0;
static volatile int global_interrupted = 0;

// FFT buffers
static fftwf_complex *fft_input;
static fftwf_complex *fft_output;
static fftwf_plan fft_plan;
static int fft_initialized = 0;

// Tone detection state
static float *audio_buffer = NULL;
static int buffer_size = 0;
static int buffer_pos = 0;
static time_t last_detect_time = 0;
static tone_definition_t *last_unknown_tone = NULL;
static int unknown_tone_count = 0;

// Initialize FFT system
static int init_fft_system(void) {
    if (fft_initialized) {
        return 1;
    }
    
    printf("[TONE_DETECT] Initializing FFT system...\n");
    
    fft_input = fftwf_malloc(sizeof(fftwf_complex) * FFT_SIZE);
    fft_output = fftwf_malloc(sizeof(fftwf_complex) * FFT_SIZE);
    
    if (!fft_input || !fft_output) {
        printf("[ERROR] Failed to allocate FFT buffers\n");
        return 0;
    }
    
    fft_plan = fftwf_plan_dft_1d(FFT_SIZE, fft_input, fft_output, FFTW_FORWARD, FFTW_ESTIMATE);
    
    if (!fft_plan) {
        printf("[ERROR] Failed to create FFT plan\n");
        return 0;
    }
    
    // Initialize audio buffer
    buffer_size = MAX_TONE_LEN * SAMPLE_RATE;
    audio_buffer = malloc(sizeof(float) * buffer_size);
    if (!audio_buffer) {
        printf("[ERROR] Failed to allocate audio buffer\n");
        return 0;
    }
    
    fft_initialized = 1;
    printf("[TONE_DETECT] FFT system initialized (size=%d, resolution=%.2f Hz)\n", 
           FFT_SIZE, (double)SAMPLE_RATE / FFT_SIZE);
    
    return 1;
}

// Cleanup FFT system
static void cleanup_fft_system(void) {
    if (fft_initialized) {
        fftwf_destroy_plan(fft_plan);
        fftwf_free(fft_input);
        fftwf_free(fft_output);
        free(audio_buffer);
        fft_initialized = 0;
    }
}

// Extract frequency from FFT
double freq_from_fft(const float *samples, int sample_count, int sample_rate) {
    if (!fft_initialized || sample_count < FFT_SIZE) {
        return 0.0;
    }
    
    // Copy samples to FFT input (use last FFT_SIZE samples)
    int start_idx = (sample_count > FFT_SIZE) ? sample_count - FFT_SIZE : 0;
    for (int i = 0; i < FFT_SIZE; i++) {
        fft_input[i] = samples[start_idx + i] + 0.0 * I;
    }
    
    // Perform FFT
    fftwf_execute(fft_plan);
    
    // Find peak frequency
    double max_magnitude = 0.0;
    int peak_bin = 0;
    
    for (int i = 1; i < FFT_SIZE / 2; i++) { // Skip DC component
        double magnitude = cabs(fft_output[i]);
        if (magnitude > max_magnitude) {
            max_magnitude = magnitude;
            peak_bin = i;
        }
    }
    
    // Convert bin to frequency
    double frequency = (double)peak_bin * sample_rate / FFT_SIZE;
    return frequency;
}

// Apply frequency filters
int apply_frequency_filters(float *samples, int sample_count, int sample_rate,
                           frequency_filter_t *filters, int filter_count) {
    if (!fft_initialized || sample_count < FFT_SIZE) {
        return 0;
    }
    
    // For each filter, apply notch filtering
    for (int f = 0; f < filter_count; f++) {
        if (!filters[f].valid) continue;
        
        double filter_freq = filters[f].frequency;
        int filter_range = filters[f].range;
        
        // Calculate frequency bins
        int center_bin = (int)(filter_freq * FFT_SIZE / sample_rate);
        int range_bins = (int)(filter_range * FFT_SIZE / sample_rate);
        
        // Apply filtering in chunks
        for (int start = 0; start < sample_count; start += FFT_SIZE) {
            int chunk_size = (start + FFT_SIZE > sample_count) ? sample_count - start : FFT_SIZE;
            
            // Copy chunk to FFT input
            for (int i = 0; i < chunk_size; i++) {
                fft_input[i] = samples[start + i] + 0.0 * I;
            }
            for (int i = chunk_size; i < FFT_SIZE; i++) {
                fft_input[i] = 0.0 + 0.0 * I;
            }
            
            // Perform FFT
            fftwf_execute(fft_plan);
            
            // Apply filter based on type
            if (strcmp(filters[f].type, "above") == 0) {
                // Remove frequencies above the threshold
                for (int i = center_bin; i < FFT_SIZE / 2; i++) {
                    fft_output[i] = 0.0 + 0.0 * I;
                    fft_output[FFT_SIZE - i] = 0.0 + 0.0 * I;
                }
            } else if (strcmp(filters[f].type, "below") == 0) {
                // Remove frequencies below the threshold
                for (int i = 1; i <= center_bin; i++) {
                    fft_output[i] = 0.0 + 0.0 * I;
                    fft_output[FFT_SIZE - i] = 0.0 + 0.0 * I;
                }
            } else if (strcmp(filters[f].type, "center") == 0) {
                // Remove frequencies around the center frequency
                for (int i = center_bin - range_bins; i <= center_bin + range_bins; i++) {
                    if (i > 0 && i < FFT_SIZE / 2) {
                        fft_output[i] = 0.0 + 0.0 * I;
                        fft_output[FFT_SIZE - i] = 0.0 + 0.0 * I;
                    }
                }
            }
            
            // Perform inverse FFT
            fftwf_plan ifft_plan = fftwf_plan_dft_1d(FFT_SIZE, fft_output, fft_input, FFTW_BACKWARD, FFTW_ESTIMATE);
            fftwf_execute(ifft_plan);
            fftwf_destroy_plan(ifft_plan);
            
            // Copy filtered samples back
            for (int i = 0; i < chunk_size; i++) {
                samples[start + i] = creal(fft_input[i]) / FFT_SIZE;
            }
        }
    }
    
    return 1;
}

// Detect tone sequence (tone_a followed by tone_b)
int detect_tone_sequence(const float *samples, int sample_count, int sample_rate, 
                         tone_definition_t *tone_def, int tolerance) {
    if (!tone_def || !tone_def->valid || sample_count < (tone_def->tone_a_length + tone_def->tone_b_length) * sample_rate) {
        return 0;
    }
    
    int tone_a_samples = (int)(tone_def->tone_a_length * sample_rate);
    int tone_b_samples = (int)(tone_def->tone_b_length * sample_rate);
    
    // Extract tone_a (first part)
    int tone_a_start = sample_count - tone_a_samples - tone_b_samples;
    double tone_a_freq = freq_from_fft(samples + tone_a_start, tone_a_samples, sample_rate);
    
    // Extract tone_b (second part)
    int tone_b_start = sample_count - tone_b_samples;
    double tone_b_freq = freq_from_fft(samples + tone_b_start, tone_b_samples, sample_rate);
    
    // Check if frequencies match within tolerance
    int tone_a_match = (fabs(tone_a_freq - tone_def->tone_a) <= tolerance);
    int tone_b_match = (fabs(tone_b_freq - tone_def->tone_b) <= tolerance);
    
    if (tone_a_match && tone_b_match) {
        printf("[TONE_DETECT] Tone sequence detected: %.1fHz -> %.1fHz (expected: %.1fHz -> %.1fHz)\n",
               tone_a_freq, tone_b_freq, tone_def->tone_a, tone_def->tone_b);
        return 1;
    }
    
    return 0;
}

// Detect new tones
int detect_new_tones(const float *samples, int sample_count, int sample_rate,
                     alert_details_t *alert_details) {
    if (!alert_details || !alert_details->detect_new_tones) {
        return 0;
    }
    
    double new_tone_length_samples = alert_details->new_tone_length * sample_rate;
    if (sample_count < new_tone_length_samples) {
        return 0;
    }
    
    // Extract the last new_tone_length seconds
    int start_idx = sample_count - new_tone_length_samples;
    double frequency = freq_from_fft(samples + start_idx, new_tone_length_samples, sample_rate);
    
    // Check if this is a stable tone (frequency doesn't change much)
    // For simplicity, we'll consider it stable if it's within the range
    if (frequency > 0 && frequency < sample_rate / 2) {
        printf("[TONE_DETECT] New tone detected: %.1fHz (length: %.1fs)\n", 
               frequency, alert_details->new_tone_length);
        return 1;
    }
    
    return 0;
}

// Load tone detection configuration from JSON
int load_tone_detection_config(const char *config_file) {
    printf("[TONE_DETECT] Loading tone detection configuration from %s\n", config_file);
    
    FILE *file = fopen(config_file, "r");
    if (!file) {
        printf("[ERROR] Failed to open config file: %s\n", config_file);
        return 0;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fclose(file);
        return 0;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);
    
    cJSON *json = cJSON_Parse(json_string);
    free(json_string);
    
    if (!json) {
        printf("[ERROR] Failed to parse JSON configuration\n");
        return 0;
    }
    
    // Navigate to software configuration
    cJSON *shadow = cJSON_GetObjectItem(json, "shadow");
    if (!shadow) {
        printf("[ERROR] No shadow object found\n");
        cJSON_Delete(json);
        return 0;
    }
    
    cJSON *state = cJSON_GetObjectItem(shadow, "state");
    if (!state) {
        printf("[ERROR] No state object found\n");
        cJSON_Delete(json);
        return 0;
    }
    
    cJSON *desired = cJSON_GetObjectItem(state, "desired");
    if (!desired) {
        printf("[ERROR] No desired object found\n");
        cJSON_Delete(json);
        return 0;
    }
    
    cJSON *software_config = cJSON_GetObjectItem(desired, "software_configuration");
    if (!software_config || !cJSON_IsArray(software_config)) {
        printf("[ERROR] No software_configuration array found\n");
        cJSON_Delete(json);
        return 0;
    }
    
    cJSON *config_item = cJSON_GetArrayItem(software_config, 0);
    if (!config_item) {
        printf("[ERROR] No configuration item found\n");
        cJSON_Delete(json);
        return 0;
    }
    
    // Process each channel
    for (int channel_idx = 0; channel_idx < MAX_CHANNELS; channel_idx++) {
        char channel_name[32];
        snprintf(channel_name, sizeof(channel_name), "channel_%s", 
                (channel_idx == 0) ? "one" : 
                (channel_idx == 1) ? "two" : 
                (channel_idx == 2) ? "three" : "four");
        
        cJSON *channel = cJSON_GetObjectItem(config_item, channel_name);
        if (!channel) {
            continue;
        }
        
        cJSON *tone_detect = cJSON_GetObjectItem(channel, "tone_detect");
        if (!tone_detect || !cJSON_IsBool(tone_detect) || !cJSON_IsTrue(tone_detect)) {
            printf("[TONE_DETECT] Channel %s has tone_detect=false, skipping\n", channel_name);
            continue;
        }
        
        cJSON *channel_id = cJSON_GetObjectItem(channel, "channel_id");
        if (!channel_id || !cJSON_IsString(channel_id)) {
            printf("[TONE_DETECT] Channel %s has no channel_id, skipping\n", channel_name);
            continue;
        }
        
        cJSON *tone_config = cJSON_GetObjectItem(channel, "tone_detect_configuration");
        if (!tone_config) {
            printf("[TONE_DETECT] Channel %s has no tone_detect_configuration, skipping\n", channel_name);
            continue;
        }
        
        // Initialize tone detection config
        tone_detect_config_t *td_config = &tone_configs[channel_idx];
        memset(td_config, 0, sizeof(tone_detect_config_t));
        
        strncpy(td_config->passthrough_channel, channel_id->valuestring, sizeof(td_config->passthrough_channel) - 1);
        
        // Load tone_passthrough setting
        cJSON *tone_passthrough = cJSON_GetObjectItem(tone_config, "tone_passthrough");
        if (tone_passthrough && cJSON_IsBool(tone_passthrough)) {
            td_config->tone_passthrough = cJSON_IsTrue(tone_passthrough);
        }
        
        // Load passthrough_channel
        cJSON *passthrough_channel = cJSON_GetObjectItem(tone_config, "passthrough_channel");
        if (passthrough_channel && cJSON_IsString(passthrough_channel)) {
            strncpy(td_config->passthrough_channel, passthrough_channel->valuestring, 
                   sizeof(td_config->passthrough_channel) - 1);
        }
        
        // Load alert_tones
        cJSON *alert_tones = cJSON_GetObjectItem(tone_config, "alert_tones");
        if (alert_tones && cJSON_IsArray(alert_tones)) {
            int tone_count = cJSON_GetArraySize(alert_tones);
            td_config->alert_tones_count = (tone_count > MAX_TONE_DEFINITIONS) ? MAX_TONE_DEFINITIONS : tone_count;
            
            for (int i = 0; i < td_config->alert_tones_count; i++) {
                cJSON *tone_item = cJSON_GetArrayItem(alert_tones, i);
                if (!tone_item) continue;
                
                tone_definition_t *tone_def = &td_config->alert_tones[i];
                memset(tone_def, 0, sizeof(tone_definition_t));
                
                cJSON *tone_id = cJSON_GetObjectItem(tone_item, "tone_id");
                if (tone_id && cJSON_IsString(tone_id)) {
                    strncpy(tone_def->tone_id, tone_id->valuestring, sizeof(tone_def->tone_id) - 1);
                }
                
                cJSON *tone_a = cJSON_GetObjectItem(tone_item, "tone_a");
                if (tone_a && cJSON_IsString(tone_a)) {
                    tone_def->tone_a = atof(tone_a->valuestring);
                }
                
                cJSON *tone_b = cJSON_GetObjectItem(tone_item, "tone_b");
                if (tone_b && cJSON_IsString(tone_b)) {
                    tone_def->tone_b = atof(tone_b->valuestring);
                }
                
                cJSON *tone_a_length = cJSON_GetObjectItem(tone_item, "tone_a_length");
                if (tone_a_length && cJSON_IsNumber(tone_a_length)) {
                    tone_def->tone_a_length = tone_a_length->valuedouble;
                }
                
                cJSON *tone_b_length = cJSON_GetObjectItem(tone_item, "tone_b_length");
                if (tone_b_length && cJSON_IsNumber(tone_b_length)) {
                    tone_def->tone_b_length = tone_b_length->valuedouble;
                }
                
                cJSON *tone_a_range = cJSON_GetObjectItem(tone_item, "tone_a_range");
                if (tone_a_range && cJSON_IsNumber(tone_a_range)) {
                    tone_def->tone_a_range = tone_a_range->valueint;
                }
                
                cJSON *tone_b_range = cJSON_GetObjectItem(tone_item, "tone_b_range");
                if (tone_b_range && cJSON_IsNumber(tone_b_range)) {
                    tone_def->tone_b_range = tone_b_range->valueint;
                }
                
                cJSON *record_length = cJSON_GetObjectItem(tone_item, "record_length");
                if (record_length && cJSON_IsNumber(record_length)) {
                    tone_def->record_length = record_length->valueint;
                }
                
                tone_def->valid = 1;
                
                printf("[TONE_DETECT] Loaded tone definition: %s (%.1f Hz -> %.1f Hz)\n", 
                       tone_def->tone_id, tone_def->tone_a, tone_def->tone_b);
            }
        }
        
        // Load alert_details
        cJSON *alert_details = cJSON_GetObjectItem(tone_config, "alert_details");
        if (alert_details) {
            cJSON *threshold = cJSON_GetObjectItem(alert_details, "threshold");
            if (threshold && cJSON_IsString(threshold)) {
                td_config->alert_details.threshold = atof(threshold->valuestring);
            }
            
            cJSON *gain = cJSON_GetObjectItem(alert_details, "gain");
            if (gain && cJSON_IsString(gain)) {
                td_config->alert_details.gain = atof(gain->valuestring);
            }
            
            cJSON *db = cJSON_GetObjectItem(alert_details, "db");
            if (db && cJSON_IsNumber(db)) {
                td_config->alert_details.db = db->valueint;
            }
            
            cJSON *detect_new_tones = cJSON_GetObjectItem(alert_details, "detect_new_tones");
            if (detect_new_tones && cJSON_IsBool(detect_new_tones)) {
                td_config->alert_details.detect_new_tones = cJSON_IsTrue(detect_new_tones);
            }
            
            cJSON *new_tone_length = cJSON_GetObjectItem(alert_details, "new_tone_length");
            if (new_tone_length && cJSON_IsNumber(new_tone_length)) {
                td_config->alert_details.new_tone_length = new_tone_length->valuedouble;
            }
            
            cJSON *new_tone_range = cJSON_GetObjectItem(alert_details, "new_tone_range");
            if (new_tone_range && cJSON_IsNumber(new_tone_range)) {
                td_config->alert_details.new_tone_range = new_tone_range->valueint;
            }
            
            printf("[TONE_DETECT] Loaded alert details: threshold=%.2f, gain=%.2f, db=%d\n",
                   td_config->alert_details.threshold, td_config->alert_details.gain, td_config->alert_details.db);
        }
        
        // Load filter_frequencies
        cJSON *filter_frequencies = cJSON_GetObjectItem(tone_config, "filter_frequencies");
        if (filter_frequencies && cJSON_IsArray(filter_frequencies)) {
            int filter_count = cJSON_GetArraySize(filter_frequencies);
            td_config->filter_frequencies_count = (filter_count > MAX_FILTERS) ? MAX_FILTERS : filter_count;
            
            for (int i = 0; i < td_config->filter_frequencies_count; i++) {
                cJSON *filter_item = cJSON_GetArrayItem(filter_frequencies, i);
                if (!filter_item) continue;
                
                frequency_filter_t *filter = &td_config->filter_frequencies[i];
                memset(filter, 0, sizeof(frequency_filter_t));
                
                cJSON *filter_id = cJSON_GetObjectItem(filter_item, "filter_id");
                if (filter_id && cJSON_IsString(filter_id)) {
                    strncpy(filter->filter_id, filter_id->valuestring, sizeof(filter->filter_id) - 1);
                }
                
                cJSON *frequency = cJSON_GetObjectItem(filter_item, "frequency");
                if (frequency && cJSON_IsNumber(frequency)) {
                    filter->frequency = frequency->valuedouble;
                }
                
                cJSON *filter_range = cJSON_GetObjectItem(filter_item, "filter_range");
                if (filter_range && cJSON_IsNumber(filter_range)) {
                    filter->filter_range = filter_range->valueint;
                }
                
                cJSON *type = cJSON_GetObjectItem(filter_item, "type");
                if (type && cJSON_IsString(type)) {
                    strncpy(filter->type, type->valuestring, sizeof(filter->type) - 1);
                }
                
                filter->valid = 1;
                
                printf("[TONE_DETECT] Loaded frequency filter: %s (%.1f Hz, %s)\n",
                       filter->filter_id, filter->frequency, filter->type);
            }
        }
        
        td_config->valid = 1;
        printf("[TONE_DETECT] Loaded tone detection config for channel %d (%s)\n", 
               channel_idx, channel_id->valuestring);
    }
    
    cJSON_Delete(json);
    printf("[TONE_DETECT] Successfully loaded tone detection configuration\n");
    return 1;
}

// Get tone detection configuration for a channel
tone_detect_config_t* get_tone_detect_config(int channel_index) {
    if (channel_index < 0 || channel_index >= MAX_CHANNELS) {
        return NULL;
    }
    
    return &tone_configs[channel_index];
}

// Initialize shared audio buffer
int init_shared_audio_buffer(void) {
    pthread_mutex_init(&global_shared_buffer.mutex, NULL);
    pthread_cond_init(&global_shared_buffer.data_ready, NULL);
    printf("[INFO] Shared audio buffer initialized\n");
    return 1;
}

// Update shared audio buffer
int update_shared_audio_buffer(const float *samples, int sample_count) {
    if (!samples || sample_count <= 0 || sample_count > SAMPLES_PER_FRAME) {
        return 0;
    }
    
    pthread_mutex_lock(&global_shared_buffer.mutex);
    
    memcpy(global_shared_buffer.samples, samples, sample_count * sizeof(float));
    global_shared_buffer.sample_count = sample_count;
    global_shared_buffer.valid = 1;
    
    pthread_cond_signal(&global_shared_buffer.data_ready);
    pthread_mutex_unlock(&global_shared_buffer.mutex);
    
    return 1;
}

// Tone detection thread function
static void* tone_detection_thread_func(void* arg) {
    (void)arg;
    
    printf("[TONE_DETECT] Tone detection thread started\n");
    
    while (thread_running && !global_interrupted) {
        pthread_mutex_lock(&global_shared_buffer.mutex);
        
        // Wait for audio data
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 1; // 1 second timeout
        
        int result = pthread_cond_timedwait(&global_shared_buffer.data_ready, 
                                          &global_shared_buffer.mutex, &timeout);
        
        if (result == ETIMEDOUT) {
            pthread_mutex_unlock(&global_shared_buffer.mutex);
            continue;
        }
        
        if (!global_shared_buffer.valid) {
            pthread_mutex_unlock(&global_shared_buffer.mutex);
            continue;
        }
        
        // Copy audio data
        float samples[SAMPLES_PER_FRAME];
        int sample_count = global_shared_buffer.sample_count;
        memcpy(samples, global_shared_buffer.samples, sample_count * sizeof(float));
        global_shared_buffer.valid = 0;
        
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Add samples to circular buffer
        for (int i = 0; i < sample_count; i++) {
            audio_buffer[buffer_pos] = samples[i];
            buffer_pos = (buffer_pos + 1) % buffer_size;
        }
        
        // Process tone detection for each configured channel
        for (int channel_idx = 0; channel_idx < MAX_CHANNELS; channel_idx++) {
            tone_detect_config_t *config = get_tone_detect_config(channel_idx);
            if (!config || !config->valid) {
                continue;
            }
            
            // Apply frequency filters
            float filtered_samples[SAMPLES_PER_FRAME];
            memcpy(filtered_samples, samples, sample_count * sizeof(float));
            
            if (config->filter_frequencies_count > 0) {
                apply_frequency_filters(filtered_samples, sample_count, SAMPLE_RATE,
                                      config->filter_frequencies, config->filter_frequencies_count);
            }
            
            // Check volume threshold
            float rms = 0.0;
            for (int i = 0; i < sample_count; i++) {
                rms += filtered_samples[i] * filtered_samples[i];
            }
            rms = sqrt(rms / sample_count);
            float db = 20.0 * log10(rms + 1e-10);
            
            if (db < config->alert_details.db) {
                continue; // Below threshold
            }
            
            // Detect known tone sequences
            for (int tone_idx = 0; tone_idx < config->alert_tones_count; tone_idx++) {
                tone_definition_t *tone_def = &config->alert_tones[tone_idx];
                if (!tone_def->valid) continue;
                
                // Check if we have enough samples for this tone sequence
                int required_samples = (int)((tone_def->tone_a_length + tone_def->tone_b_length) * SAMPLE_RATE);
                if (buffer_size < required_samples) {
                    continue;
                }
                
                // Extract samples for tone detection
                float detection_samples[required_samples];
                int start_pos = (buffer_pos - required_samples + buffer_size) % buffer_size;
                
                for (int i = 0; i < required_samples; i++) {
                    detection_samples[i] = audio_buffer[(start_pos + i) % buffer_size];
                }
                
                // Detect tone sequence
                if (detect_tone_sequence(detection_samples, required_samples, SAMPLE_RATE, 
                                       tone_def, tone_def->tone_a_range)) {
                    printf("[TONE_DETECT] Tone sequence detected on channel %d: %s\n", 
                           channel_idx, tone_def->tone_id);
                    
                    // Trigger passthrough if enabled
                    if (config->tone_passthrough) {
                        int target_channel = get_passthrough_target_channel_index();
                        if (target_channel >= 0) {
                            start_tone_passthrough(target_channel);
                        }
                    }
                    
                    last_detect_time = time(NULL);
                }
            }
            
            // Detect new tones if enabled
            if (config->alert_details.detect_new_tones) {
                if (detect_new_tones(filtered_samples, sample_count, SAMPLE_RATE, 
                                   &config->alert_details)) {
                    printf("[TONE_DETECT] New tone detected on channel %d\n", channel_idx);
                }
            }
        }
        
        usleep(10000); // 10ms sleep
    }
    
    printf("[TONE_DETECT] Tone detection thread exiting\n");
    return NULL;
}

// Initialize tone detection control
int init_tone_detect_control(void) {
    memset(&global_tone_detect, 0, sizeof(tone_detect_control_t));
    global_tone_detect.enabled = 1;
    global_tone_detect.card1_input_enabled = 1;
    global_tone_detect.passthrough_mode = 0;
    pthread_mutex_init(&global_tone_detect.mutex, NULL);
    printf("[INFO] Tone detection control initialized\n");
    return 1;
}

// Enable tone detection
int enable_tone_detection(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.enabled = 1;
    global_tone_detect.card1_input_enabled = 1;
    global_tone_detect.passthrough_mode = 1;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Tone detection ENABLED\n");
    return 1;
}

// Disable tone detection
int disable_tone_detection(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.enabled = 0;
    global_tone_detect.card1_input_enabled = 0;
    global_tone_detect.passthrough_mode = 0;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Tone detection DISABLED\n");
    return 1;
}

// Set passthrough output mode
int set_passthrough_output_mode(int passthrough_mode) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.passthrough_mode = passthrough_mode;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Passthrough output mode set to %s\n", passthrough_mode ? "PASSTHROUGH" : "ECHOSTREAM");
    return 1;
}

// Check if tone detection is enabled
int is_tone_detect_enabled(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    int enabled = global_tone_detect.enabled;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    return enabled;
}

// Check if Card 1 input is enabled
int is_card1_input_enabled(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    int enabled = global_tone_detect.card1_input_enabled;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    return enabled;
}

// Check if passthrough mode is enabled
int is_passthrough_mode(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    int passthrough = global_tone_detect.passthrough_mode;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    return passthrough;
}

// Get passthrough target channel index
int get_passthrough_target_channel_index(void) {
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    extern int global_channel_count;
    
    // Find the channel with tone_passthrough enabled
    for (int config_idx = 0; config_idx < MAX_CHANNELS; config_idx++) {
        tone_detect_config_t *config = get_tone_detect_config(config_idx);
        if (!config || !config->valid || !config->tone_passthrough) {
            continue;
        }
        
        // Find the target channel by passthrough_channel
        for (int channel_idx = 0; channel_idx < global_channel_count; channel_idx++) {
            if (strcmp(global_channel_ids[channel_idx], config->passthrough_channel) == 0) {
                return channel_idx;
            }
        }
    }
    
    return -1;
}

// Check if channel has output stream
int channel_has_output_stream(int channel_index) {
    extern struct channel_context channels[MAX_CHANNELS];
    
    if (channel_index < 0 || channel_index >= MAX_CHANNELS) {
        return 0;
    }
    
    PaStream *stream = channels[channel_index].audio.output_stream;
    if (!stream) {
        return 0;
    }
    
    return Pa_IsStreamActive(stream) ? 1 : 0;
}

// Start tone passthrough
int start_tone_passthrough(int target_channel) {
    pthread_mutex_lock(&global_tone_passthrough.mutex);
    
    if (global_tone_passthrough.active) {
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        return 1;
    }
    
    global_tone_passthrough.enabled = 1;
    global_tone_passthrough.target_channel = target_channel;
    global_tone_passthrough.active = 1;
    
    pthread_mutex_unlock(&global_tone_passthrough.mutex);
    
    printf("[INFO] Tone passthrough started for channel %d\n", target_channel);
    return 1;
}

// Stop tone passthrough
int stop_tone_passthrough(void) {
    pthread_mutex_lock(&global_tone_passthrough.mutex);
    
    if (!global_tone_passthrough.active) {
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        return 1;
    }
    
    if (global_tone_passthrough.passthrough_stream) {
        Pa_AbortStream(global_tone_passthrough.passthrough_stream);
        Pa_CloseStream(global_tone_passthrough.passthrough_stream);
        global_tone_passthrough.passthrough_stream = NULL;
    }
    
    global_tone_passthrough.active = 0;
    pthread_mutex_unlock(&global_tone_passthrough.mutex);
    
    printf("[INFO] Tone passthrough stopped\n");
    return 1;
}

// Check if tone passthrough is active
int is_tone_passthrough_active(void) {
    pthread_mutex_lock(&global_tone_passthrough.mutex);
    int active = global_tone_passthrough.active;
    pthread_mutex_unlock(&global_tone_passthrough.mutex);
    return active;
}

// Tone passthrough callback
int tone_passthrough_callback(const void *input, void *output, unsigned long frames,
                              const PaStreamCallbackTimeInfo *time_info,
                              PaStreamCallbackFlags flags, void *user_data) {
    (void)time_info;
    (void)flags;
    (void)user_data;
    
    if (!input || !output) {
        return paContinue;
    }
    
    // Direct audio passthrough - copy input to output
    const float *in = (const float *)input;
    float *out = (float *)output;
    
    for (unsigned long i = 0; i < frames; i++) {
        out[i] = in[i];
    }
    
    return paContinue;
}

// Repair passthrough output stream (placeholder)
int repair_passthrough_output_stream(int channel_index) {
    (void)channel_index;
    printf("[AUDIO] Repairing passthrough output stream for channel %d (placeholder)\n", channel_index);
    return 1; // Placeholder - always return success
}

// Initialize tone detection system
int init_tone_detection(void) {
    printf("[TONE_DETECT] Initializing tone detection system...\n");
    
    // Initialize FFT system
    if (!init_fft_system()) {
        printf("[ERROR] Failed to initialize FFT system\n");
        return 0;
    }
    
    // Initialize shared audio buffer
    if (!init_shared_audio_buffer()) {
        printf("[ERROR] Failed to initialize shared audio buffer\n");
        return 0;
    }
    
    // Initialize tone detection control
    if (!init_tone_detect_control()) {
        printf("[ERROR] Failed to initialize tone detection control\n");
        return 0;
    }
    
    printf("[TONE_DETECT] Tone detection system initialized successfully\n");
    return 1;
}

// Start tone detection thread
int start_tone_detection(void) {
    printf("[TONE_DETECT] Starting tone detection thread...\n");
    
    thread_running = 1;
    global_interrupted = 0;
    
    if (pthread_create(&tone_detection_thread, NULL, tone_detection_thread_func, NULL) != 0) {
        printf("[ERROR] Failed to create tone detection thread\n");
        return 0;
    }
    
    printf("[TONE_DETECT] Tone detection thread started successfully\n");
    return 1;
}

// Cleanup tone detection system
int cleanup_tone_detection(void) {
    printf("[TONE_DETECT] Cleaning up tone detection system...\n");
    
    // Stop tone detection thread
    thread_running = 0;
    global_interrupted = 1;
    
    if (tone_detection_thread) {
        pthread_join(tone_detection_thread, NULL);
    }
    
    // Stop passthrough
    stop_tone_passthrough();
    
    // Cleanup FFT system
    cleanup_fft_system();
    
    // Cleanup mutexes
    pthread_mutex_destroy(&global_tone_detect.mutex);
    pthread_mutex_destroy(&global_shared_buffer.mutex);
    pthread_mutex_destroy(&global_tone_passthrough.mutex);
    
    printf("[TONE_DETECT] Tone detection system cleaned up\n");
    return 1;
}
