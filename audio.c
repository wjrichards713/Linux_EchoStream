#define _POSIX_C_SOURCE 200809L
#include "audio.h"
#include "crypto.h"
#include "config.h"
#include "udp.h"
#include "tone_detect.h"
#include <math.h>
#include <unistd.h>

// Global audio state
struct channel_context channels[MAX_CHANNELS] = {0};
PaDeviceIndex usb_devices[MAX_CHANNELS] = {paNoDevice, paNoDevice, paNoDevice, paNoDevice};
int device_assigned = 0;

// Global shared audio buffer and passthrough
struct shared_audio_buffer global_shared_buffer = {0};
struct audio_passthrough global_passthrough = {0};

// Global tone detection control
struct tone_detect_control global_tone_detect = {0};

// Global tone passthrough control
struct tone_passthrough_control global_tone_passthrough = {0};

// Get the index of the passthrough target channel
int get_passthrough_target_channel_index(void) {
    struct tone_detect_config* tone_cfg = get_tone_detect_config(0);
    if (!tone_cfg || !tone_cfg->tone_passthrough) {
        return -1;
    }
    if (strcmp(tone_cfg->passthrough_channel, "channel_four") == 0) return 3;
    else if (strcmp(tone_cfg->passthrough_channel, "channel_three") == 0) return 2;
    else if (strcmp(tone_cfg->passthrough_channel, "channel_two") == 0) return 1;
    else if (strcmp(tone_cfg->passthrough_channel, "channel_one") == 0) return 0;
    return -1;
}

// Check if a channel has a working output stream
int channel_has_output_stream(int channel_index) {
    if (channel_index < 0 || channel_index >= MAX_CHANNELS) {
        printf("[DEBUG] channel_has_output_stream: invalid channel_index %d\n", channel_index);
        return 0;
    }
    
    PaStream* stream = channels[channel_index].audio.output_stream;
    if (stream == NULL) {
        printf("[DEBUG] channel_has_output_stream: channel_index=%d, has_stream=0, stream_ptr=NULL\n", channel_index);
        return 0;
    }
    
    // Check if the stream is actually active
    PaError err = Pa_IsStreamActive(stream);
    int is_active = (err == 1) ? 1 : 0;
    
    printf("[DEBUG] channel_has_output_stream: channel_index=%d, has_stream=1, stream_ptr=%p, is_active=%d, pa_error=%d\n", 
           channel_index, stream, is_active, err);
    
    return is_active;
}

// Helper: check if a channel_id matches the configured passthrough_channel from JSON
static int is_configured_passthrough_channel_id(const char* channel_id) {
    struct tone_detect_config* tone_cfg = get_tone_detect_config(0);
    if (!tone_cfg || !tone_cfg->tone_passthrough) {
        static int debug_count = 0;
        if (debug_count++ % 10000 == 0) {
            printf("[DEBUG] is_configured_passthrough_channel_id: tone_cfg=%p, tone_passthrough=%d\n", 
                   tone_cfg, tone_cfg ? tone_cfg->tone_passthrough : -1);
        }
        return 0;
    }
    int idx = -1;
    if (strcmp(tone_cfg->passthrough_channel, "channel_four") == 0) idx = 3;
    else if (strcmp(tone_cfg->passthrough_channel, "channel_three") == 0) idx = 2;
    else if (strcmp(tone_cfg->passthrough_channel, "channel_two") == 0) idx = 1;
    else if (strcmp(tone_cfg->passthrough_channel, "channel_one") == 0) idx = 0;
    
    static int debug_count = 0;
    if (debug_count++ % 10000 == 0) {
        printf("[DEBUG] is_configured_passthrough_channel_id: channel_id=%s, passthrough_channel=%s, idx=%d\n", 
               channel_id, tone_cfg->passthrough_channel, idx);
    }
    
    if (idx < 0) return 0;
    return (strcmp(channel_id, global_channel_ids[idx]) == 0) ? 1 : 0;
}

// Initialize tone detection control
int init_tone_detect_control(void) {
    memset(&global_tone_detect, 0, sizeof(struct tone_detect_control));
    // Initialize based on shadow config
    struct tone_detect_config* tone_cfg = get_tone_detect_config(0);
    global_tone_detect.enabled = 1;  // Start enabled by default
    global_tone_detect.card1_input_enabled = 1;  // Channel 1 input enabled by default
    global_tone_detect.passthrough_mode = (tone_cfg && tone_cfg->tone_passthrough) ? 1 : 0;
    pthread_mutex_init(&global_tone_detect.mutex, NULL);
    printf("[INFO] Tone detection control initialized (enabled by default)\n");
    return 1;
}

// Enable tone detection
int enable_tone_detection(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.enabled = 1;
    global_tone_detect.card1_input_enabled = 1;  // Enable Card 1 input for tone detection
    global_tone_detect.passthrough_mode = 1;  // Enable passthrough mode
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Tone detection ENABLED - source input active for tone detection, passthrough mode enabled\n");
    printf("[INFO] Primary output continues to play EchoStream audio\n");
    return 1;
}

// Disable tone detection
int disable_tone_detection(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.enabled = 0;
    global_tone_detect.card1_input_enabled = 0;  // Disable Card 1 input for tone detection
    global_tone_detect.passthrough_mode = 0;  // Switch output to EchoStream mode
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Tone detection DISABLED - source input disabled for tone detection, EchoStream mode\n");
    printf("[INFO] Primary output continues to play EchoStream audio\n");
    return 1;
}

// Set passthrough output mode (for configured target channel)
int set_passthrough_output_mode(int passthrough_mode) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.passthrough_mode = passthrough_mode;
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Passthrough output mode set to %s for configured target\n", passthrough_mode ? "PASSTHROUGH" : "ECHOSTREAM");
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

// Modified audio input callback with tone detection control
static int audio_input_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    (void)output; // Suppress unused parameter warning
    (void)time_info; // Suppress unused parameter warning
    (void)flags; // Suppress unused parameter warning
    
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    static int callback_count = 0;
    if (callback_count++ % 100000 == 0) {  // Even less frequent logging - about every 30 seconds
        printf("Audio input callback called (frames=%lu, transmitting=%d, gpio_active=%d)\n", 
               frames, audio_stream->transmitting, audio_stream->gpio_active);
    }
    
    // Check if this is Card 1 (channel 555) and if input should be enabled
    int is_card1 = (strcmp(audio_stream->channel_id, "555") == 0);
    int input_enabled = is_card1 ? is_card1_input_enabled() : 1;
    
    if (!audio_stream->transmitting || !input || !audio_stream->gpio_active) {
        return paContinue;
    }
    
    static int audio_processing_count = 0;
    if (audio_processing_count++ % 100000 == 0) {  // Even less frequent logging - about every 30 seconds
        printf("Audio processing for channel %s (frames=%lu, input_enabled=%d)\n", 
               audio_stream->channel_id, frames, input_enabled);
    }
    
    const float *samples = (const float*)input;
    
    // Update shared buffer for passthrough (only for Card 1 when tone detect enabled)
    if (is_card1 && is_tone_detect_enabled()) {
        pthread_mutex_lock(&global_shared_buffer.mutex);
        for (unsigned long i = 0; i < frames && i < SAMPLES_PER_FRAME; i++) {
            global_shared_buffer.samples[i] = samples[i];
        }
        global_shared_buffer.sample_count = frames;
        global_shared_buffer.valid = 1;
        pthread_cond_signal(&global_shared_buffer.data_ready);
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Debug logging for shared buffer
        static int shared_buffer_count = 0;
        if (shared_buffer_count++ % 10000 == 0) {
            printf("[DEBUG] Shared buffer updated: frames=%lu, valid=%d\n", frames, global_shared_buffer.valid);
        }
        
        // Tone detection reads directly from shared buffer
    }
    
    // Process audio for EchoStream (only if input is enabled for this channel)
    if (input_enabled) {
        for (unsigned long i = 0; i < frames; i++) {
            audio_stream->input_buffer[audio_stream->input_buffer_pos++] = samples[i];
            
            if (audio_stream->input_buffer_pos >= 1920) {
                short pcm[1920];
                for (int j = 0; j < 1920; j++) {
                    float sample = audio_stream->input_buffer[j];
                    if (sample > 1.0f) sample = 1.0f;
                    if (sample < -1.0f) sample = -1.0f;
                    pcm[j] = (short)(sample * 32767.0f);
                }
                
                unsigned char opus_data[4000];
                int opus_len = opus_encode(audio_stream->encoder, pcm, 1920, opus_data, sizeof(opus_data));
                
                if (opus_len > 0) {
                    size_t encrypted_len;
                    unsigned char* encrypted = encrypt_data(opus_data, opus_len, audio_stream->key, &encrypted_len);
                    
                    if (encrypted) {
                        char* b64_data = encode_base64(encrypted, encrypted_len);
                        
                        if (b64_data) {
                            char msg[8192];
                            snprintf(msg, sizeof(msg),
                                    "{\"channel_id\":\"%s\",\"type\":\"audio\",\"data\":\"%s\"}", audio_stream->channel_id, b64_data);
                            
                            int sent = sendto(global_udp_socket, msg, strlen(msg), 0,
                                   (struct sockaddr*)&global_server_addr, sizeof(global_server_addr));
                            
                            static int audio_send_count = 0;
                            if (audio_send_count++ % 10000 == 0) {  // Even less frequent logging
                                printf("Audio sent for channel %s (%d bytes, UDP result: %d)\n", 
                                       audio_stream->channel_id, (int)strlen(msg), sent);
                            }
                            
                            free(b64_data);
                        }
                        free(encrypted);
                    }
                }
                
                audio_stream->input_buffer_pos = 0;
            }
        }
    }
    
    return paContinue;
}

// Modified audio output callback
static int audio_output_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    (void)input; // Suppress unused parameter warning
    (void)time_info; // Suppress unused parameter warning
    (void)flags; // Suppress unused parameter warning
    
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    float *out = (float*)output;
    struct jitter_buffer *jitter = &audio_stream->output_jitter;
    
    static int callback_count = 0;
    if (callback_count++ % 100000 == 0) {  // Even less frequent logging - about every 30 seconds
        printf("Audio output callback called (frames=%lu, buffer_count=%d)\n", frames, jitter->frame_count);
    }
    
    // Check if this channel is the configured passthrough target
    int is_configured_target = is_configured_passthrough_channel_id(audio_stream->channel_id);
    int passthrough_mode = is_configured_target ? is_passthrough_mode() : 0;
    
    // Debug logging for passthrough
    static int debug_count = 0;
    if (debug_count++ % 10000 == 0) {
        printf("[DEBUG] Channel %s: is_configured_target=%d, passthrough_mode=%d\n", 
               audio_stream->channel_id, is_configured_target, passthrough_mode);
    }
    
    if (passthrough_mode) {
        // Configured passthrough target in passthrough mode - play audio from shared buffer (Channel 1 input)
        unsigned long frames_filled = 0;
        pthread_mutex_lock(&global_shared_buffer.mutex);
        if (global_shared_buffer.valid && global_shared_buffer.sample_count > 0) {
            unsigned long to_copy = global_shared_buffer.sample_count;
            if (to_copy > frames) to_copy = frames;
            for (unsigned long i = 0; i < to_copy; i++) {
                out[i] = global_shared_buffer.samples[i];
            }
            frames_filled = to_copy;
            // do not invalidate; tone detection thread also reads; this is a tap
        }
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Debug logging for passthrough audio
        static int passthrough_audio_count = 0;
        if (passthrough_audio_count++ % 1000 == 0) {
            printf("[DEBUG] Passthrough audio: frames_filled=%lu, shared_valid=%d, shared_count=%d\n", 
                   frames_filled, global_shared_buffer.valid, global_shared_buffer.sample_count);
        }
        
        // Fill any remainder with silence
        for (unsigned long i = frames_filled; i < frames; i++) {
            out[i] = 0.0f;
        }
        return paContinue;
    }
    
    // Normal EchoStream output processing
    pthread_mutex_lock(&jitter->mutex);
    
    unsigned long frames_filled = 0;
    
    while (frames_filled < frames) {
        // Check if we have a current frame to read from
        if (jitter->frame_count > 0) {
            struct audio_frame *current_frame = &jitter->frames[jitter->read_index];
            
            if (current_frame->valid) {
                // Calculate how many samples we can copy from current frame
                int remaining_in_frame = current_frame->sample_count - audio_stream->current_output_frame_pos;
                unsigned long frames_to_copy = frames - frames_filled;
                
                if (frames_to_copy > (unsigned long)remaining_in_frame) {
                    frames_to_copy = (unsigned long)remaining_in_frame;
                }
                
                // Copy samples from current frame
                for (unsigned long i = 0; i < frames_to_copy; i++) {
                    out[frames_filled + i] = current_frame->samples[audio_stream->current_output_frame_pos + i];
                }
                
                frames_filled += frames_to_copy;
                audio_stream->current_output_frame_pos += frames_to_copy;
                
                // Check if we finished this frame
                if (audio_stream->current_output_frame_pos >= current_frame->sample_count) {
                    // Mark frame as consumed
                    current_frame->valid = 0;
                    jitter->read_index = (jitter->read_index + 1) % JITTER_BUFFER_SIZE;
                    jitter->frame_count--;
                    audio_stream->current_output_frame_pos = 0;
                }
            } else {
                // Frame is invalid, skip it
                jitter->read_index = (jitter->read_index + 1) % JITTER_BUFFER_SIZE;
                jitter->frame_count--;
                audio_stream->current_output_frame_pos = 0;
            }
        } else {
            // No frames available, fill with silence
            for (unsigned long i = frames_filled; i < frames; i++) {
                out[i] = 0.0f;
            }
            frames_filled = frames;
        }
    }
    
    pthread_mutex_unlock(&jitter->mutex);
    return paContinue;
}

// Passthrough thread outputs the shared input when in passthrough mode
void* audio_passthrough_thread(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    printf("[INFO] Audio passthrough thread started\n");
    
    // Buffer for smoothing audio output
    float output_buffer[SAMPLES_PER_FRAME];
    int underflow_count = 0;
    
    while (global_passthrough.active && !global_interrupted) {
        int samples_to_copy = 0;
        
        // Only process if passthrough mode is enabled
        if (!is_passthrough_mode()) {
            usleep(10000); // 10ms delay when not in passthrough mode
            continue;
        }
        
        pthread_mutex_lock(&global_shared_buffer.mutex);
        
        // Wait for new audio data
        while (!global_shared_buffer.valid && global_passthrough.active && !global_interrupted) {
            pthread_cond_wait(&global_shared_buffer.data_ready, &global_shared_buffer.mutex);
        }
        
        if (global_shared_buffer.valid && global_passthrough.active && !global_interrupted) {
            // Copy audio data to output buffer
            samples_to_copy = global_shared_buffer.sample_count;
            if (samples_to_copy > SAMPLES_PER_FRAME) {
                samples_to_copy = SAMPLES_PER_FRAME;
            }
            
            for (int i = 0; i < samples_to_copy; i++) {
                output_buffer[i] = global_shared_buffer.samples[i];
            }
            
            global_shared_buffer.valid = 0; // Mark as consumed
        }
        
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Write audio data to output stream (only if in passthrough mode)
        if (samples_to_copy > 0 && is_passthrough_mode()) {
            static int write_count = 0;
            write_count++;
            
            PaError err = Pa_WriteStream(global_passthrough.output_stream, 
                                       output_buffer, 
                                       samples_to_copy);
            
            if (err != paNoError) {
                if (err == paOutputUnderflowed) {
                    underflow_count++;
                    if (underflow_count % 50 == 0) {
                        printf("[DEBUG] Passthrough underflow count: %d (writes: %d)\n", underflow_count, write_count);
                    }
                } else {
                    fprintf(stderr, "PortAudio write error in passthrough: %s\n", Pa_GetErrorText(err));
                }
                } else {
                    underflow_count = 0; // Reset counter on successful write
                    if (write_count % 5000 == 0) {  // Much less frequent logging
                        printf("[DEBUG] Passthrough successful writes: %d\n", write_count);
                    }
                }
        }
        
        // Small delay to prevent overwhelming the output device
        usleep(5000); // 5ms delay to reduce underflow
    }
    
    printf("[INFO] Audio passthrough thread stopped\n");
    return NULL;
}

// Initialize shared audio buffer
int init_shared_audio_buffer(void) {
    memset(&global_shared_buffer, 0, sizeof(struct shared_audio_buffer));
    pthread_mutex_init(&global_shared_buffer.mutex, NULL);
    pthread_cond_init(&global_shared_buffer.data_ready, NULL);
    printf("[INFO] Shared audio buffer initialized\n");
    return 1;
}

// Initialize audio passthrough
int init_audio_passthrough(void) {
    memset(&global_passthrough, 0, sizeof(struct audio_passthrough));
    global_passthrough.shared_buffer = &global_shared_buffer;
    
    // Debug: Print all available devices
    int num_devices = Pa_GetDeviceCount();
    printf("[DEBUG] Available audio devices:\n");
    for (int i = 0; i < num_devices; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info) {
            printf("  Device %d: %s (Input: %d, Output: %d)\n", 
                   i, device_info->name, device_info->maxInputChannels, device_info->maxOutputChannels);
        }
    }
    
    // Debug: Print USB device assignments
    printf("[DEBUG] USB device assignments:\n");
    for (int i = 0; i < 4; i++) {
        printf("  USB device %d: %d\n", i, usb_devices[i]);
    }
    
    global_passthrough.active = 0;
    printf("[INFO] Audio passthrough initialized (callback-based, no extra streams)\n");
    return 1;
}

// Start audio passthrough
int start_audio_passthrough(void) {
    // Callback-based passthrough: nothing to start, output callback will handle routing
    printf("[INFO] Audio passthrough enabled (callback-based)\n");
    return 1;
}

// Stop audio passthrough
void stop_audio_passthrough(void) {
    if (!global_passthrough.active) {
        return;
    }
    
    global_passthrough.active = 0;
    
    // Signal the thread to wake up
    pthread_mutex_lock(&global_shared_buffer.mutex);
    pthread_cond_signal(&global_shared_buffer.data_ready);
    pthread_mutex_unlock(&global_shared_buffer.mutex);
    
    // Wait for thread to finish
    pthread_join(global_passthrough.thread, NULL);
    
    // Stop and close stream
    if (global_passthrough.output_stream) {
        Pa_StopStream(global_passthrough.output_stream);
        Pa_CloseStream(global_passthrough.output_stream);
        global_passthrough.output_stream = NULL;
    }
    
    printf("[INFO] Audio passthrough stopped\n");
}

int setup_audio_for_channel(struct audio_stream* audio_stream) {
    int error;
    
    // Setup encoder
    audio_stream->encoder = opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK) {
        fprintf(stderr, "Opus encoder error: %s\n", opus_strerror(error));
        return 0;
    }
    
    opus_encoder_ctl(audio_stream->encoder, OPUS_SET_BITRATE(64000));
    opus_encoder_ctl(audio_stream->encoder, OPUS_SET_VBR(1));
    
    // Setup decoder
    audio_stream->decoder = opus_decoder_create(48000, 1, &error);
    if (error != OPUS_OK) {
        fprintf(stderr, "Opus decoder error: %s\n", opus_strerror(error));
        opus_encoder_destroy(audio_stream->encoder);
        return 0;
    }
    
    // Setup buffers
    audio_stream->buffer_size = 4800;
    audio_stream->input_buffer = malloc(audio_stream->buffer_size * sizeof(float));
    audio_stream->input_buffer_pos = 0;
    audio_stream->current_output_frame_pos = 0;
    audio_stream->gpio_active = 0;
    
    // Initialize jitter buffer
    memset(&audio_stream->output_jitter, 0, sizeof(struct jitter_buffer));
    pthread_mutex_init(&audio_stream->output_jitter.mutex, NULL);
    
    for (int i = 0; i < JITTER_BUFFER_SIZE; i++) {
        audio_stream->output_jitter.frames[i].valid = 0;
        audio_stream->output_jitter.frames[i].sample_count = 0;
    }
    
    return 1;
}

int initialize_portaudio() {
    static int initialized = 0;
    if (initialized) return 1;
    
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "PortAudio error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    initialized = 1;
    return 1;
}

int start_transmission_for_channel(struct audio_stream* audio_stream) {
    PaStreamParameters input_params, output_params;
    
    audio_stream->device_index = get_device_for_channel(audio_stream->channel_id);
    
    // No channel is hard-reserved for passthrough; selection is driven by JSON.
    
    // Setup input stream for other channels
    input_params.device = audio_stream->device_index;
    if (input_params.device == paNoDevice) {
        fprintf(stderr, "No input device for channel %s\n", audio_stream->channel_id);
        return 0;
    }
    
    input_params.channelCount = 1;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    PaError err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, 48000, 1024, 
                                paClipOff, audio_input_callback, audio_stream);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input stream error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    // Setup output stream for other channels
    output_params.device = audio_stream->device_index;
    output_params.channelCount = 1;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    printf("[DEBUG] Attempting to open output stream for channel %s on device %d\n", 
           audio_stream->channel_id, audio_stream->device_index);
    
    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                        paClipOff, audio_output_callback, audio_stream);

    if (err != paNoError) {
        fprintf(stderr, "PortAudio output stream error: %s\n", Pa_GetErrorText(err));
        // Retry with default output device
        PaDeviceIndex defOut = Pa_GetDefaultOutputDevice();
        if (defOut != paNoDevice && defOut != output_params.device) {
            output_params.device = defOut;
            output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
            printf("[DEBUG] Retrying output open for channel %s using default output device %d\n", audio_stream->channel_id, (int)defOut);
            err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                                paClipOff, audio_output_callback, audio_stream);
        }
        if (err != paNoError) {
            printf("WARNING: Output stream failed for channel %s (device %d), trying alternative output devices\n",
                   audio_stream->channel_id, audio_stream->device_index);

            // Try other USB devices as output fallback
            for (int i = 0; i < 4; i++) {
                if (usb_devices[i] != audio_stream->device_index && usb_devices[i] != paNoDevice) {
                    output_params.device = usb_devices[i];
                    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
                    printf("[DEBUG] Trying alternative output device %d for channel %s\n", usb_devices[i], audio_stream->channel_id);
                    
                    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                                        paClipOff, audio_output_callback, audio_stream);
                    if (err == paNoError) {
                        printf("[INFO] Successfully opened output stream for channel %s on alternative device %d\n", 
                               audio_stream->channel_id, usb_devices[i]);
                        break;
                    } else {
                        printf("[DEBUG] Alternative device %d also failed: %s\n", usb_devices[i], Pa_GetErrorText(err));
                    }
                }
            }
            
            // If USB devices failed, try any available output device
            if (err != paNoError) {
                printf("[DEBUG] All USB devices failed, trying any available output device for channel %s\n", audio_stream->channel_id);
                int device_count = Pa_GetDeviceCount();
                for (int i = 0; i < device_count; i++) {
                    const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
                    if (device_info && device_info->maxOutputChannels > 0) {
                        output_params.device = i;
                        output_params.suggestedLatency = device_info->defaultLowOutputLatency;
                        printf("[DEBUG] Trying output device %d (%s) for channel %s\n", i, device_info->name, audio_stream->channel_id);
                        
                        err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                                            paClipOff, audio_output_callback, audio_stream);
                        if (err == paNoError) {
                            printf("[INFO] Successfully opened output stream for channel %s on device %d (%s)\n", 
                                   audio_stream->channel_id, i, device_info->name);
                            break;
                        } else {
                            printf("[DEBUG] Device %d (%s) also failed: %s\n", i, device_info->name, Pa_GetErrorText(err));
                        }
                    }
                }
            }
            
            // If all USB devices failed, try input-only mode as last resort
            if (err != paNoError) {
                printf("WARNING: All output devices failed for channel %s, trying input-only mode\n",
                       audio_stream->channel_id);

                // Try input-only mode as fallback
                Pa_CloseStream(audio_stream->input_stream);
                audio_stream->input_stream = NULL;

                // Reopen input stream
                err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, 48000, 1024,
                                    paClipOff, audio_input_callback, audio_stream);

                if (err != paNoError) {
                    fprintf(stderr, "PortAudio input-only mode also failed: %s\n", Pa_GetErrorText(err));
                    return 0;
                }

                // Start input stream only
                err = Pa_StartStream(audio_stream->input_stream);
                if (err != paNoError) {
                    fprintf(stderr, "PortAudio input start error: %s\n", Pa_GetErrorText(err));
                    Pa_CloseStream(audio_stream->input_stream);
                    return 0;
                }

                printf("Channel %s running in input-only mode (no audio output)\n", audio_stream->channel_id);
                
                // Check if this channel is configured as a passthrough target
                if (is_configured_passthrough_channel_id(audio_stream->channel_id)) {
                    printf("[WARNING] Channel %s is configured as passthrough target but has no output stream!\n", audio_stream->channel_id);
                    printf("[WARNING] Passthrough audio will not work for this channel.\n");
                }
                
                audio_stream->transmitting = 1;
                return 1;
            }
        }
    }
    
    // Start both streams
    err = Pa_StartStream(audio_stream->input_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
    }
    
    err = Pa_StartStream(audio_stream->output_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio output start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
    }
    
    // Check if streams are actually running
    if (Pa_IsStreamActive(audio_stream->input_stream)) {
        printf("Input stream is active for channel %s\n", audio_stream->channel_id);
    } else {
        printf("WARNING: Input stream is NOT active for channel %s\n", audio_stream->channel_id);
    }
    
    if (Pa_IsStreamActive(audio_stream->output_stream)) {
        printf("Output stream is active for channel %s\n", audio_stream->channel_id);
    } else {
        printf("WARNING: Output stream is NOT active for channel %s\n", audio_stream->channel_id);
    }
    
    audio_stream->transmitting = 1;
    printf("Audio transmission started for channel %s (input + output)\n", audio_stream->channel_id);
    return 1;
}

void auto_assign_usb_devices() {
    if (device_assigned) return;
    
    int num_devices = Pa_GetDeviceCount();
    int usb_count = 0;
    
    printf("Scanning for USB audio devices...\n");
    
    for (int i = 0; i < num_devices && usb_count < 4; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info && device_info->maxInputChannels > 0) {
            const PaHostApiInfo* host_info = Pa_GetHostApiInfo(device_info->hostApi);
            if (host_info && host_info->type == paALSA) {
                const char* name = device_info->name;
                if (strstr(name, "USB") || strstr(name, "usb") || 
                    strstr(name, "Audio Device") || strstr(name, "Headset")) {
                    usb_devices[usb_count] = i;
                    printf("USB Device %d assigned to slot %d: %s\n", i, usb_count, name);
                    usb_count++;
                }
            }
        }
    }
    
    if (usb_count == 0) {
        printf("No USB audio devices found, using default input device for all channels\n");
        for (int i = 0; i < 4; i++) {
            usb_devices[i] = Pa_GetDefaultInputDevice();
        }
    } else if (usb_count < 4) {
        printf("Only %d USB device(s) found, some channels will share devices\n", usb_count);
        // Fill remaining slots with available devices
        for (int i = usb_count; i < 4; i++) {
            usb_devices[i] = usb_devices[i % usb_count];
        }
    }
    
    printf("Channel assignments:\n");
    for (int i = 0; i < 4; i++) {
        printf("Channel %s -> Device %d\n", global_channel_ids[i], usb_devices[i]);
    }
    
    device_assigned = 1;
}

PaDeviceIndex get_device_for_channel(const char* channel) {
    auto_assign_usb_devices();
    
    // Direct channel mapping like the original
    if (strcmp(channel, "555") == 0) {
        printf("[DEBUG] Channel %s assigned to USB device 0 (device %d)\n", channel, usb_devices[0]);
        return usb_devices[0];
    } else if (strcmp(channel, "666") == 0) {
        printf("[DEBUG] Channel %s assigned to USB device 1 (device %d)\n", channel, usb_devices[1]);
        return usb_devices[1];
    } else if (strcmp(channel, "308e2478-072c-4d8b-ffff24d-51854e06711a") == 0) {
        printf("[DEBUG] Channel %s assigned to USB device 2 (device %d)\n", channel, usb_devices[2]);
        return usb_devices[2];
    } else if (strcmp(channel, "94415b61-8007-430d-ffffea0-10fc9fee2d8e") == 0) {
        printf("[DEBUG] Channel %s assigned to USB device 3 (device %d)\n", channel, usb_devices[3]);
        return usb_devices[3];
    }
    
    printf("[DEBUG] Channel %s using default fallback (device %d)\n", channel, usb_devices[0]);
    return usb_devices[0];  // Default fallback
}

int setup_channel(struct channel_context *ctx, const char *channel_id) {
    strcpy(ctx->audio.channel_id, channel_id);
    
    if (!setup_audio_for_channel(&ctx->audio)) {
        fprintf(stderr, "[ERROR] Audio setup failed for channel %s\n", channel_id);
        return 0;
    }
    
    ctx->active = 1;
    printf("[INFO] Channel %s setup completed successfully\n", channel_id);
    return 1;
}

// Initialize tone passthrough control
int init_tone_passthrough_control(void) {
    memset(&global_tone_passthrough, 0, sizeof(struct tone_passthrough_control));
    global_tone_passthrough.active = 0;
    global_tone_passthrough.source_channel = -1;
    global_tone_passthrough.target_channel = -1;
    global_tone_passthrough.passthrough_stream = NULL;
    pthread_mutex_init(&global_tone_passthrough.mutex, NULL);
    printf("[INFO] Tone passthrough control initialized\n");
    return 1;
}

// Setup tone passthrough routing
int setup_tone_passthrough(int source_channel, int target_channel) {
    if (source_channel < 0 || source_channel >= MAX_CHANNELS || 
        target_channel < 0 || target_channel >= MAX_CHANNELS) {
        printf("[ERROR] Invalid channel indices for tone passthrough\n");
        return 0;
    }
    
    pthread_mutex_lock(&global_tone_passthrough.mutex);
    global_tone_passthrough.source_channel = source_channel;
    global_tone_passthrough.target_channel = target_channel;
    pthread_mutex_unlock(&global_tone_passthrough.mutex);
    
    printf("[INFO] Tone passthrough configured: Channel %d -> Channel %d\n", 
           source_channel + 1, target_channel + 1);
    return 1;
}

// Start tone passthrough
int start_tone_passthrough(void) {
    pthread_mutex_lock(&global_tone_passthrough.mutex);
    
    if (global_tone_passthrough.active) {
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        printf("[WARNING] Tone passthrough already active\n");
        return 1;
    }
    
    if (global_tone_passthrough.source_channel < 0 || global_tone_passthrough.target_channel < 0) {
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        printf("[ERROR] Tone passthrough not configured\n");
        return 0;
    }
    
    // Get source and target audio devices
    PaDeviceIndex source_device = channels[global_tone_passthrough.source_channel].audio.device_index;
    PaDeviceIndex target_device = channels[global_tone_passthrough.target_channel].audio.device_index;
    
    if (source_device == paNoDevice || target_device == paNoDevice) {
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        printf("[ERROR] Invalid audio devices for tone passthrough\n");
        return 0;
    }
    
    // Setup passthrough stream parameters
    PaStreamParameters input_params, output_params;
    
    input_params.device = source_device;
    input_params.channelCount = 1;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(source_device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    output_params.device = target_device;
    output_params.channelCount = 1;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(target_device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    // Open passthrough stream
    PaError err = Pa_OpenStream(&global_tone_passthrough.passthrough_stream,
                               &input_params, &output_params, 48000, 1024,
                               paClipOff, tone_passthrough_callback, NULL);
    
    if (err != paNoError) {
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        printf("[ERROR] Failed to open tone passthrough stream: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    // Start the stream
    err = Pa_StartStream(global_tone_passthrough.passthrough_stream);
    if (err != paNoError) {
        Pa_CloseStream(global_tone_passthrough.passthrough_stream);
        global_tone_passthrough.passthrough_stream = NULL;
        pthread_mutex_unlock(&global_tone_passthrough.mutex);
        printf("[ERROR] Failed to start tone passthrough stream: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    global_tone_passthrough.active = 1;
    pthread_mutex_unlock(&global_tone_passthrough.mutex);
    
    printf("[INFO] Tone passthrough started: Channel %d -> Channel %d\n", 
           global_tone_passthrough.source_channel + 1, global_tone_passthrough.target_channel + 1);
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
                              const PaStreamCallbackTimeInfo* time_info,
                              PaStreamCallbackFlags flags, void *user_data) {
    (void)time_info; // Suppress unused parameter warning
    (void)flags;     // Suppress unused parameter warning
    (void)user_data; // Suppress unused parameter warning
    
    if (!input || !output) {
        return paContinue;
    }
    
    // Direct audio passthrough - copy input to output
    const float *in = (const float*)input;
    float *out = (float*)output;
    
    for (unsigned long i = 0; i < frames; i++) {
        out[i] = in[i];
    }
    
    return paContinue;
}