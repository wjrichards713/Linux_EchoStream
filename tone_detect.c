#include "tone_detect.h"
#include <math.h>
#include <string.h>
#include <unistd.h>

// Global tone detection state
struct tone_detect_channel tone_channels[TONE_DETECT_THREADS] = {0};
struct shared_audio_buffer shared_buffer = {0};
int tone_detect_enabled = 0;

// Initialize shared audio buffer
int shared_buffer_init(void) {
    memset(&shared_buffer, 0, sizeof(shared_buffer));
    shared_buffer.buffer_size = TONE_DETECT_BUFFER_SIZE;
    
    if (pthread_mutex_init(&shared_buffer.mutex, NULL) != 0) {
        fprintf(stderr, "Failed to initialize shared buffer mutex\n");
        return 0;
    }
    
    if (pthread_cond_init(&shared_buffer.data_available, NULL) != 0) {
        fprintf(stderr, "Failed to initialize shared buffer condition\n");
        pthread_mutex_destroy(&shared_buffer.mutex);
        return 0;
    }
    
    return 1;
}

void shared_buffer_cleanup(void) {
    pthread_mutex_destroy(&shared_buffer.mutex);
    pthread_cond_destroy(&shared_buffer.data_available);
}

// Write audio samples to shared buffer
void shared_buffer_write(const float* samples, int sample_count) {
    pthread_mutex_lock(&shared_buffer.mutex);
    
    for (int i = 0; i < sample_count; i++) {
        shared_buffer.samples[shared_buffer.write_pos] = samples[i];
        shared_buffer.write_pos = (shared_buffer.write_pos + 1) % TONE_DETECT_BUFFER_SIZE;
        
        if (shared_buffer.available_samples < TONE_DETECT_BUFFER_SIZE) {
            shared_buffer.available_samples++;
        }
    }
    
    pthread_cond_signal(&shared_buffer.data_available);
    pthread_mutex_unlock(&shared_buffer.mutex);
}

// Read audio samples from shared buffer
int shared_buffer_read(float* samples, int max_samples) {
    pthread_mutex_lock(&shared_buffer.mutex);
    
    int samples_read = 0;
    while (samples_read < max_samples && shared_buffer.available_samples > 0) {
        samples[samples_read] = shared_buffer.samples[shared_buffer.read_pos];
        shared_buffer.read_pos = (shared_buffer.read_pos + 1) % TONE_DETECT_BUFFER_SIZE;
        shared_buffer.available_samples--;
        samples_read++;
    }
    
    pthread_mutex_unlock(&shared_buffer.mutex);
    return samples_read;
}

// Initialize tone detection system
int tone_detect_init(void) {
    printf("Initializing tone detection system...\n");
    
    // Initialize shared buffer
    if (!shared_buffer_init()) {
        fprintf(stderr, "Failed to initialize shared audio buffer\n");
        return 0;
    }
    
    // Initialize tone detection channels
    for (int i = 0; i < TONE_DETECT_THREADS; i++) {
        struct tone_detect_channel *channel = &tone_channels[i];
        memset(channel, 0, sizeof(struct tone_detect_channel));
        
        // Allocate FFT buffers
        channel->fft_input = fftwf_malloc(sizeof(fftwf_complex) * FFT_SIZE);
        channel->fft_output = fftwf_malloc(sizeof(fftwf_complex) * FFT_SIZE);
        
        if (!channel->fft_input || !channel->fft_output) {
            fprintf(stderr, "Failed to allocate FFT buffers for channel %d\n", i);
            return 0;
        }
        
        // Create FFT plan
        channel->fft_plan = fftwf_plan_dft_1d(FFT_SIZE, channel->fft_input, channel->fft_output, FFTW_FORWARD, FFTW_ESTIMATE);
        if (!channel->fft_plan) {
            fprintf(stderr, "Failed to create FFT plan for channel %d\n", i);
            return 0;
        }
        
        // Allocate audio buffers
        channel->buffer_size = TONE_DETECT_BUFFER_SIZE;
        channel->audio_buffer = malloc(channel->buffer_size * sizeof(float));
        channel->new_tone_buffer = malloc(channel->buffer_size * sizeof(float));
        
        if (!channel->audio_buffer || !channel->new_tone_buffer) {
            fprintf(stderr, "Failed to allocate audio buffers for channel %d\n", i);
            return 0;
        }
        
        // Initialize mutex
        if (pthread_mutex_init(&channel->mutex, NULL) != 0) {
            fprintf(stderr, "Failed to initialize mutex for channel %d\n", i);
            return 0;
        }
        
        channel->channel_index = i;
    }
    
    tone_detect_enabled = 1;
    printf("Tone detection system initialized successfully\n");
    return 1;
}

void tone_detect_cleanup(void) {
    printf("Cleaning up tone detection system...\n");
    
    tone_detect_enabled = 0;
    
    // Cleanup channels
    for (int i = 0; i < TONE_DETECT_THREADS; i++) {
        struct tone_detect_channel *channel = &tone_channels[i];
        
        if (channel->fft_plan) {
            fftwf_destroy_plan(channel->fft_plan);
        }
        
        if (channel->fft_input) {
            fftwf_free(channel->fft_input);
        }
        
        if (channel->fft_output) {
            fftwf_free(channel->fft_output);
        }
        
        if (channel->audio_buffer) {
            free(channel->audio_buffer);
        }
        
        if (channel->new_tone_buffer) {
            free(channel->new_tone_buffer);
        }
        
        pthread_mutex_destroy(&channel->mutex);
    }
    
    shared_buffer_cleanup();
    printf("Tone detection system cleaned up\n");
}

// Setup tone detection for a specific channel
int tone_detect_setup_channel(int channel_index, const char* config_json) {
    if (channel_index >= TONE_DETECT_THREADS) {
        fprintf(stderr, "Invalid channel index for tone detection: %d\n", channel_index);
        return 0;
    }
    
    struct tone_detect_channel *channel = &tone_channels[channel_index];
    
    // Parse JSON configuration
    struct json_object *json = json_tokener_parse(config_json);
    if (!json) {
        fprintf(stderr, "Failed to parse tone detection config JSON\n");
        return 0;
    }
    
    // Parse tone details
    struct json_object *tone_details_array;
    if (json_object_object_get_ex(json, "tone_details", &tone_details_array)) {
        int array_len = json_object_array_length(tone_details_array);
        channel->tone_detail_count = (array_len > MAX_TONE_DETAILS) ? MAX_TONE_DETAILS : array_len;
        
        for (int i = 0; i < channel->tone_detail_count; i++) {
            struct json_object *tone_obj = json_object_array_get_idx(tone_details_array, i);
            struct tone_detail *detail = &channel->tone_details[i];
            
            // Parse tone details (simplified for now)
            const char *tone_id = json_object_get_string(json_object_object_get(tone_obj, "tone_id"));
            if (tone_id) {
                strncpy(detail->tone_id, tone_id, sizeof(detail->tone_id) - 1);
                detail->tone_id[sizeof(detail->tone_id) - 1] = '\0';
            }
            
            detail->tone_a = json_object_get_double(json_object_object_get(tone_obj, "tone_a"));
            detail->tone_b = json_object_get_double(json_object_object_get(tone_obj, "tone_b"));
            detail->tone_a_length = json_object_get_int(json_object_object_get(tone_obj, "tone_a_length"));
            detail->tone_b_length = json_object_get_int(json_object_object_get(tone_obj, "tone_b_length"));
            detail->tone_a_range = json_object_get_int(json_object_object_get(tone_obj, "tone_a_range"));
            detail->tone_b_length = json_object_get_int(json_object_object_get(tone_obj, "tone_b_range"));
            detail->record_length = json_object_get_int(json_object_object_get(tone_obj, "record_length"));
        }
    }
    
    // Parse tone config
    struct json_object *tone_config_obj;
    if (json_object_object_get_ex(json, "tone_config", &tone_config_obj)) {
        channel->config.threshold = json_object_get_double(json_object_object_get(tone_config_obj, "threshold"));
        channel->config.gain = json_object_get_double(json_object_object_get(tone_config_obj, "gain"));
        channel->config.db = json_object_get_int(json_object_object_get(tone_config_obj, "db"));
        channel->config.detect_new_tones = json_object_get_boolean(json_object_object_get(tone_config_obj, "detect_new_tones"));
        channel->config.new_tone_length = json_object_get_int(json_object_object_get(tone_config_obj, "new_tone_length"));
        channel->config.new_tone_range = json_object_get_int(json_object_object_get(tone_config_obj, "new_tone_range"));
    }
    
    // Parse filter frequencies
    struct json_object *filters_array;
    if (json_object_object_get_ex(json, "filter_frequencies", &filters_array)) {
        int array_len = json_object_array_length(filters_array);
        channel->filter_count = (array_len > MAX_FILTER_FREQUENCIES) ? MAX_FILTER_FREQUENCIES : array_len;
        
        for (int i = 0; i < channel->filter_count; i++) {
            struct json_object *filter_obj = json_object_array_get_idx(filters_array, i);
            struct filter_frequency *filter = &channel->filters[i];
            
            const char *filter_id = json_object_get_string(json_object_object_get(filter_obj, "filter_id"));
            if (filter_id) {
                strncpy(filter->filter_id, filter_id, sizeof(filter->filter_id) - 1);
                filter->filter_id[sizeof(filter->filter_id) - 1] = '\0';
            }
            
            filter->frequency = json_object_get_double(json_object_object_get(filter_obj, "frequency"));
            filter->filter_range = json_object_get_int(json_object_object_get(filter_obj, "filter_range"));
            
            const char *type = json_object_get_string(json_object_object_get(filter_obj, "type"));
            if (type) {
                strncpy(filter->type, type, sizeof(filter->type) - 1);
                filter->type[sizeof(filter->type) - 1] = '\0';
            }
        }
    }
    
    channel->active = 1;
    json_object_put(json);
    
    printf("Tone detection configured for channel %d\n", channel_index);
    return 1;
}

// Process audio samples for tone detection
void tone_detect_process_audio(int channel_index, const float* samples, int sample_count) {
    if (channel_index >= TONE_DETECT_THREADS || !tone_channels[channel_index].active) {
        return;
    }
    
    struct tone_detect_channel *channel = &tone_channels[channel_index];
    
    pthread_mutex_lock(&channel->mutex);
    
    // Add samples to buffer
    for (int i = 0; i < sample_count; i++) {
        channel->audio_buffer[channel->buffer_pos] = samples[i];
        channel->buffer_pos = (channel->buffer_pos + 1) % channel->buffer_size;
    }
    
    // Process when we have enough samples for FFT
    if (channel->buffer_pos >= FFT_SIZE) {
        // Copy samples for FFT processing
        for (int i = 0; i < FFT_SIZE; i++) {
            int buffer_idx = (channel->buffer_pos - FFT_SIZE + i + channel->buffer_size) % channel->buffer_size;
            channel->fft_input[i][0] = channel->audio_buffer[buffer_idx];
            channel->fft_input[i][1] = 0.0f;
        }
        
        // Perform FFT
        fftwf_execute(channel->fft_plan);
        
        // Analyze frequencies
        float max_magnitude = 0.0f;
        int max_freq_bin = 0;
        
        for (int i = 0; i < FFT_SIZE / 2; i++) {
            float real = channel->fft_output[i][0];
            float imag = channel->fft_output[i][1];
            float magnitude = sqrtf(real * real + imag * imag);
            
            if (magnitude > max_magnitude) {
                max_magnitude = magnitude;
                max_freq_bin = i;
            }
        }
        
        // Convert bin to frequency (assuming 48kHz sample rate)
        float detected_frequency = (float)max_freq_bin * 48000.0f / FFT_SIZE;
        channel->current_tone_frequency = detected_frequency;
        
        // Check for known tones
        for (int i = 0; i < channel->tone_detail_count; i++) {
            struct tone_detail *detail = &channel->tone_details[i];
            
            // Check tone A
            if (fabsf(detected_frequency - detail->tone_a) <= detail->tone_a_range) {
                if (!channel->tone_a_detected) {
                    channel->tone_a_detected = 1;
                    channel->tone_a_count = 0;
                    printf("Tone A detected: %.1f Hz (expected: %.1f Hz)\n", detected_frequency, detail->tone_a);
                }
                channel->tone_a_count++;
            } else {
                if (channel->tone_a_detected && channel->tone_a_count < detail->tone_a_length) {
                    // Tone A not sustained long enough
                    channel->tone_a_detected = 0;
                    channel->tone_a_count = 0;
                }
            }
            
            // Check tone B (only if tone A was detected)
            if (channel->tone_a_detected && channel->tone_a_count >= detail->tone_a_length) {
                if (fabsf(detected_frequency - detail->tone_b) <= detail->tone_b_range) {
                    if (!channel->tone_b_detected) {
                        channel->tone_b_detected = 1;
                        channel->tone_b_count = 0;
                        printf("Tone B detected: %.1f Hz (expected: %.1f Hz)\n", detected_frequency, detail->tone_b);
                    }
                    channel->tone_b_count++;
                } else {
                    if (channel->tone_b_detected && channel->tone_b_count < detail->tone_b_length) {
                        // Tone B not sustained long enough
                        channel->tone_b_detected = 0;
                        channel->tone_b_count = 0;
                    }
                }
            }
            
            // Check if both tones detected
            if (channel->tone_a_detected && channel->tone_b_detected && 
                channel->tone_a_count >= detail->tone_a_length && 
                channel->tone_b_count >= detail->tone_b_length) {
                
                printf("Tone sequence detected! Starting recording for %d samples\n", detail->record_length);
                tone_detect_start_recording(channel_index);
                
                // Reset detection state
                channel->tone_a_detected = 0;
                channel->tone_b_detected = 0;
                channel->tone_a_count = 0;
                channel->tone_b_count = 0;
            }
        }
        
        // Check for new tone detection
        if (channel->config.detect_new_tones && !channel->recording) {
            // Simple new tone detection based on sustained frequency
            if (fabsf(detected_frequency - channel->new_tone_frequency) <= channel->config.new_tone_range) {
                channel->new_tone_count++;
                if (channel->new_tone_count >= channel->config.new_tone_length) {
                    printf("New tone detected: %.1f Hz\n", detected_frequency);
                    channel->new_tone_detected = 1;
                    channel->new_tone_frequency = detected_frequency;
                }
            } else {
                channel->new_tone_count = 0;
                channel->new_tone_frequency = detected_frequency;
            }
        }
    }
    
    pthread_mutex_unlock(&channel->mutex);
}

// Start recording after tone detection
int tone_detect_start_recording(int channel_index) {
    if (channel_index >= TONE_DETECT_THREADS) {
        return 0;
    }
    
    struct tone_detect_channel *channel = &tone_channels[channel_index];
    
    pthread_mutex_lock(&channel->mutex);
    channel->recording = 1;
    channel->record_count = 0;
    pthread_mutex_unlock(&channel->mutex);
    
    return 1;
}

void tone_detect_stop_recording(int channel_index) {
    if (channel_index >= TONE_DETECT_THREADS) {
        return;
    }
    
    struct tone_detect_channel *channel = &tone_channels[channel_index];
    
    pthread_mutex_lock(&channel->mutex);
    channel->recording = 0;
    channel->record_count = 0;
    pthread_mutex_unlock(&channel->mutex);
}

// Tone detection thread
void* tone_detect_thread(void* arg) {
    int channel_index = *(int*)arg;
    struct tone_detect_channel *channel = &tone_channels[channel_index];
    float samples[TONE_DETECT_BUFFER_SIZE];
    
    printf("Tone detection thread started for channel %d\n", channel_index);
    
    while (tone_detect_enabled && channel->active) {
        // Read from shared buffer
        int samples_read = shared_buffer_read(samples, TONE_DETECT_BUFFER_SIZE);
        
        if (samples_read > 0) {
            tone_detect_process_audio(channel_index, samples, samples_read);
        } else {
            // Wait for data
            usleep(1000); // 1ms
        }
    }
    
    printf("Tone detection thread stopped for channel %d\n", channel_index);
    return NULL;
}
