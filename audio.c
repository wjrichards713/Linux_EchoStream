#include "audio.h"
#include "crypto.h"
#include "udp.h"
#include <math.h>

// Global audio state
struct channel_context channels[MAX_CHANNELS] = {0};
PaDeviceIndex usb_devices[MAX_CHANNELS] = {paNoDevice, paNoDevice, paNoDevice, paNoDevice};
int device_assigned = 0;

// Global shared audio buffer and passthrough
struct shared_audio_buffer global_shared_buffer = {0};
struct audio_passthrough global_passthrough = {0};

static int audio_input_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    (void)output; // Suppress unused parameter warning
    (void)time_info; // Suppress unused parameter warning
    (void)flags; // Suppress unused parameter warning
    
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    static int callback_count = 0;
    if (callback_count++ % 100 == 0) {
        printf("Audio input callback called (frames=%lu, transmitting=%d, gpio_active=%d)\n", 
               frames, audio_stream->transmitting, audio_stream->gpio_active);
    }
    
    if (!audio_stream->transmitting || !input || !audio_stream->gpio_active) {
        return paContinue;
    }
    
    static int audio_processing_count = 0;
    if (audio_processing_count++ % 100 == 0) {
        printf("Audio processing for channel %s (frames=%lu)\n", audio_stream->channel_id, frames);
    }
    
    const float *samples = (const float*)input;
    
    // Update shared buffer for passthrough (only for channel 1 - "555")
    if (strcmp(audio_stream->channel_id, "555") == 0) {
        pthread_mutex_lock(&global_shared_buffer.mutex);
        for (unsigned long i = 0; i < frames && i < SAMPLES_PER_FRAME; i++) {
            global_shared_buffer.samples[i] = samples[i];
        }
        global_shared_buffer.sample_count = frames;
        global_shared_buffer.valid = 1;
        pthread_cond_signal(&global_shared_buffer.data_ready);
        pthread_mutex_unlock(&global_shared_buffer.mutex);
    }
    
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
                        if (audio_send_count++ % 10 == 0) {
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
    
    return paContinue;
}

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
    if (callback_count++ % 100 == 0) {
        printf("Audio output callback called (frames=%lu, buffer_count=%d)\n", frames, jitter->frame_count);
    }
    
    // Debug: Check if we have audio data
    if (jitter->frame_count > 0) {
        struct audio_frame *current_frame = &jitter->frames[jitter->read_index];
        if (current_frame->valid) {
            float max_sample = 0.0f;
            for (int i = 0; i < current_frame->sample_count; i++) {
                float abs_sample = fabsf(current_frame->samples[i]);
                if (abs_sample > max_sample) max_sample = abs_sample;
            }
            if (callback_count % 100 == 0) {
                printf("Audio frame has %d samples, max level: %.4f\n", 
                       current_frame->sample_count, max_sample);
            }
        }
    }
    
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
    
    // Setup input stream
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
    
    // Setup output stream
    output_params.device = audio_stream->device_index;
    output_params.channelCount = 1;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024, 
                        paClipOff, audio_output_callback, audio_stream);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio output stream error: %s\n", Pa_GetErrorText(err));
        printf("WARNING: Output stream failed for channel %s (device %d), trying input-only mode\n", 
               audio_stream->channel_id, audio_stream->device_index);
        
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
        audio_stream->transmitting = 1;
        return 1;
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
        return usb_devices[0];
    } else if (strcmp(channel, "666") == 0) {
        return usb_devices[1];
    } else if (strcmp(channel, "308e2478-072c-4d8b-ffff24d-51854e06711a") == 0) {
        return usb_devices[2];
    } else if (strcmp(channel, "94415b61-8007-430d-ffffea0-10fc9fee2d8e") == 0) {
        return usb_devices[3];
    }
    
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
    global_passthrough.output_device = usb_devices[2]; // Card 3 (index 2)
    global_passthrough.active = 0;
    printf("[INFO] Audio passthrough initialized for device %d\n", global_passthrough.output_device);
    return 1;
}

// Audio passthrough thread function
void* audio_passthrough_thread(void* arg) {
    (void)arg; // Suppress unused parameter warning
    
    printf("[INFO] Audio passthrough thread started\n");
    
    while (global_passthrough.active && !global_interrupted) {
        pthread_mutex_lock(&global_shared_buffer.mutex);
        
        // Wait for new audio data
        while (!global_shared_buffer.valid && global_passthrough.active && !global_interrupted) {
            pthread_cond_wait(&global_shared_buffer.data_ready, &global_shared_buffer.mutex);
        }
        
        if (global_shared_buffer.valid && global_passthrough.active && !global_interrupted) {
            // Play audio on output device
            PaError err = Pa_WriteStream(global_passthrough.output_stream, 
                                       global_shared_buffer.samples, 
                                       global_shared_buffer.sample_count);
            
            if (err != paNoError) {
                fprintf(stderr, "PortAudio write error in passthrough: %s\n", Pa_GetErrorText(err));
            }
            
            global_shared_buffer.valid = 0; // Mark as consumed
        }
        
        pthread_mutex_unlock(&global_shared_buffer.mutex);
    }
    
    printf("[INFO] Audio passthrough thread stopped\n");
    return NULL;
}

// Start audio passthrough
int start_audio_passthrough(void) {
    if (global_passthrough.active) {
        printf("[WARNING] Audio passthrough already active\n");
        return 1;
    }
    
    if (global_passthrough.output_device == paNoDevice) {
        fprintf(stderr, "[ERROR] No output device available for passthrough\n");
        return 0;
    }
    
    // Setup output stream for passthrough
    PaStreamParameters output_params;
    output_params.device = global_passthrough.output_device;
    output_params.channelCount = 1;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    PaError err = Pa_OpenStream(&global_passthrough.output_stream, NULL, &output_params, 
                               48000, 1024, paClipOff, NULL, NULL);
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio passthrough output stream error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    err = Pa_StartStream(global_passthrough.output_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio passthrough start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(global_passthrough.output_stream);
        return 0;
    }
    
    global_passthrough.active = 1;
    
    // Create passthrough thread
    if (pthread_create(&global_passthrough.thread, NULL, audio_passthrough_thread, NULL)) {
        fprintf(stderr, "Failed to create audio passthrough thread\n");
        Pa_StopStream(global_passthrough.output_stream);
        Pa_CloseStream(global_passthrough.output_stream);
        global_passthrough.active = 0;
        return 0;
    }
    
    printf("[INFO] Audio passthrough started successfully\n");
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
