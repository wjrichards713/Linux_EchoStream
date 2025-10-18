#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "audio.h"
#include "crypto.h"
#include "config.h"
#include "udp.h"
#include <math.h>
#include <unistd.h>

// Forward declarations
static int audio_input_callback(const void *input, void *output, unsigned long frames,
                               const PaStreamCallbackTimeInfo* time_info,
                               PaStreamCallbackFlags flags, void *user_data);
void kill_processes_using_audio_device(PaDeviceIndex device_index);

// Global audio state
struct channel_context channels[MAX_CHANNELS] = {0};
PaDeviceIndex usb_devices[MAX_CHANNELS] = {paNoDevice, paNoDevice, paNoDevice, paNoDevice};
int device_assigned = 0;

// Passthrough pipeline structures
struct passthrough_pipeline {
    int active;                     // Whether passthrough is active
    int source_channel_index;       // Index of source channel (tone detection)
    int target_channel_index;       // Index of target channel (passthrough output)
    char source_channel_id[64];     // Source channel ID
    char target_channel_id[64];     // Target channel ID
    float* audio_buffer;            // Audio buffer for passthrough
    int buffer_size;                // Buffer size in samples
    pthread_mutex_t mutex;          // Mutex for thread safety
    int samples_ready;              // Number of samples ready for output
};

// Global passthrough pipeline
static struct passthrough_pipeline global_passthrough = {0};

// Initialize passthrough pipeline
int init_passthrough_pipeline(void) {
    printf("[PASSTHROUGH] Initializing passthrough pipeline\n");
    
    // Find tone detection channel and passthrough target channel from config
    int tone_detect_channel_index = -1;
    int passthrough_target_index = -1;
    
    for (int i = 0; i < MAX_CHANNELS; i++) {
        struct channel_config* channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid) {
            if (channel_config->tone_detect && channel_config->tone_config.valid) {
                tone_detect_channel_index = i;
                printf("[PASSTHROUGH] Found tone detection channel: %s (index %d)\n", 
                       channel_config->channel_id, i);
                
                // Find the passthrough target channel
                // First try exact match
                for (int j = 0; j < MAX_CHANNELS; j++) {
                    struct channel_config* target_config = get_channel_config(j);
                    if (target_config && target_config->valid) {
                        if (strcmp(target_config->channel_id, channel_config->tone_config.passthrough_channel) == 0) {
                            passthrough_target_index = j;
                            printf("[PASSTHROUGH] Found passthrough target channel: %s (index %d)\n", 
                                   target_config->channel_id, j);
                            break;
                        }
                    }
                }
                
                // If not found, try mapping channel names to indices
                if (passthrough_target_index == -1) {
                    const char* target_name = channel_config->tone_config.passthrough_channel;
                    printf("[PASSTHROUGH] Exact match failed, trying channel name mapping: %s\n", target_name);
                    
                    if (strcmp(target_name, "channel_one") == 0) {
                        passthrough_target_index = 0;
                    } else if (strcmp(target_name, "channel_two") == 0) {
                        passthrough_target_index = 1;
                    } else if (strcmp(target_name, "channel_three") == 0) {
                        passthrough_target_index = 2;
                    } else if (strcmp(target_name, "channel_four") == 0) {
                        passthrough_target_index = 3;
                    }
                    
                    if (passthrough_target_index != -1) {
                        struct channel_config* target_config = get_channel_config(passthrough_target_index);
                        if (target_config && target_config->valid) {
                            printf("[PASSTHROUGH] Found passthrough target channel via mapping: %s -> %s (index %d)\n", 
                                   target_name, target_config->channel_id, passthrough_target_index);
                        } else {
                            printf("[PASSTHROUGH] Channel mapping found but channel %d is invalid\n", passthrough_target_index);
                            passthrough_target_index = -1;
                        }
                    }
                }
                break;
            }
        }
    }
    
    if (tone_detect_channel_index == -1) {
        printf("[PASSTHROUGH] No tone detection channel found in configuration\n");
        return 0;
    }
    
    if (passthrough_target_index == -1) {
        printf("[PASSTHROUGH] No passthrough target channel found in configuration\n");
        return 0;
    }
    
    // Initialize passthrough pipeline
    global_passthrough.active = 0;
    global_passthrough.source_channel_index = tone_detect_channel_index;
    global_passthrough.target_channel_index = passthrough_target_index;
    
    // Copy channel IDs
    struct channel_config* source_config = get_channel_config(tone_detect_channel_index);
    struct channel_config* target_config = get_channel_config(passthrough_target_index);
    
    if (source_config) {
        strncpy(global_passthrough.source_channel_id, source_config->channel_id, 63);
        global_passthrough.source_channel_id[63] = '\0';
    }
    
    if (target_config) {
        strncpy(global_passthrough.target_channel_id, target_config->channel_id, 63);
        global_passthrough.target_channel_id[63] = '\0';
    }
    
    // Initialize audio buffer
    global_passthrough.buffer_size = SAMPLES_PER_FRAME * 2; // Double buffer for safety
    global_passthrough.audio_buffer = malloc(global_passthrough.buffer_size * sizeof(float));
    if (!global_passthrough.audio_buffer) {
        printf("[PASSTHROUGH] Failed to allocate audio buffer\n");
        return 0;
    }
    
    // Initialize mutex
    if (pthread_mutex_init(&global_passthrough.mutex, NULL) != 0) {
        printf("[PASSTHROUGH] Failed to initialize mutex\n");
        free(global_passthrough.audio_buffer);
        return 0;
    }
    
    global_passthrough.samples_ready = 0;
    
    printf("[PASSTHROUGH] Pipeline initialized: %s -> %s\n", 
           global_passthrough.source_channel_id, global_passthrough.target_channel_id);
    
    return 1;
}

// Activate passthrough pipeline
int activate_passthrough_pipeline(void) {
    pthread_mutex_lock(&global_passthrough.mutex);
    global_passthrough.active = 1;
    global_passthrough.samples_ready = 0;
    pthread_mutex_unlock(&global_passthrough.mutex);
    
    printf("[PASSTHROUGH] Pipeline activated: %s -> %s\n", 
           global_passthrough.source_channel_id, global_passthrough.target_channel_id);
    
    return 1;
}

// Deactivate passthrough pipeline
int deactivate_passthrough_pipeline(void) {
    pthread_mutex_lock(&global_passthrough.mutex);
    global_passthrough.active = 0;
    global_passthrough.samples_ready = 0;
    pthread_mutex_unlock(&global_passthrough.mutex);
    
    printf("[PASSTHROUGH] Pipeline deactivated\n");
    
    return 1;
}

// Check if passthrough pipeline is active
int is_passthrough_pipeline_active(void) {
    pthread_mutex_lock(&global_passthrough.mutex);
    int active = global_passthrough.active;
    pthread_mutex_unlock(&global_passthrough.mutex);
    return active;
}

// Feed audio data to passthrough pipeline (called from source channel input callback)
int feed_passthrough_audio(const float* samples, int sample_count) {
    if (!global_passthrough.active || !samples || sample_count <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&global_passthrough.mutex);
    
    // Copy samples to buffer (with overflow protection)
    int samples_to_copy = (sample_count > global_passthrough.buffer_size) ? 
                         global_passthrough.buffer_size : sample_count;
    
    for (int i = 0; i < samples_to_copy; i++) {
        global_passthrough.audio_buffer[i] = samples[i];
    }
    
    global_passthrough.samples_ready = samples_to_copy;
    
    pthread_mutex_unlock(&global_passthrough.mutex);
    
    return 1;
}

// Get audio data from passthrough pipeline (called from target channel output callback)
int get_passthrough_audio(float* output_samples, int max_samples) {
    if (!global_passthrough.active || !output_samples || max_samples <= 0) {
        return 0;
    }
    
    pthread_mutex_lock(&global_passthrough.mutex);
    
    int samples_to_copy = (global_passthrough.samples_ready > max_samples) ? 
                         max_samples : global_passthrough.samples_ready;
    
    for (int i = 0; i < samples_to_copy; i++) {
        output_samples[i] = global_passthrough.audio_buffer[i];
    }
    
    // Clear remaining samples with silence
    for (int i = samples_to_copy; i < max_samples; i++) {
        output_samples[i] = 0.0f;
    }
    
    pthread_mutex_unlock(&global_passthrough.mutex);
    
    return samples_to_copy;
}

// Cleanup passthrough pipeline
void cleanup_passthrough_pipeline(void) {
    printf("[PASSTHROUGH] Cleaning up passthrough pipeline\n");
    
    pthread_mutex_lock(&global_passthrough.mutex);
    global_passthrough.active = 0;
    global_passthrough.samples_ready = 0;
    pthread_mutex_unlock(&global_passthrough.mutex);
    
    if (global_passthrough.audio_buffer) {
        free(global_passthrough.audio_buffer);
        global_passthrough.audio_buffer = NULL;
    }
    
    pthread_mutex_destroy(&global_passthrough.mutex);
}

// List all available PortAudio devices for debugging
void list_all_audio_devices(void) {
    printf("[DEBUG] === LISTING ALL AVAILABLE AUDIO DEVICES ===\n");
    int num_devices = Pa_GetDeviceCount();
    printf("[DEBUG] Total devices available: %d\n", num_devices);
    
    for (int i = 0; i < num_devices; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info) {
            const PaHostApiInfo* host_api = Pa_GetHostApiInfo(device_info->hostApi);
            printf("[DEBUG] Device %d: %s (API: %s, Input: %d, Output: %d)\n", 
                   i, device_info->name, host_api->name, 
                   device_info->maxInputChannels, device_info->maxOutputChannels);
        }
    }
}

// Kill processes using a specific audio device
void kill_processes_using_audio_device(PaDeviceIndex device_index) {
    // This is a placeholder - actual implementation would kill processes using the device
    printf("[DEBUG] Would kill processes using device %d\n", device_index);
}

// Audio input callback with passthrough pipeline integration
static int audio_input_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    (void)output;
    (void)time_info;
    (void)flags;
    
    if (flags & paInputUnderflow) {
        printf("[WARNING] Audio input underflow\n");
    }
    
    if (flags & paInputOverflow) {
        printf("[WARNING] Audio input overflow\n");
    }
    
    const float* samples = (const float*)input;
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    // Check if this is the tone detection channel (source for passthrough)
    int is_tone_detect_channel = 0;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        struct channel_config* channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid && 
            channel_config->tone_detect && 
            strcmp(channel_config->channel_id, audio_stream->channel_id) == 0) {
            is_tone_detect_channel = 1;
            break;
        }
    }
    
    // If this is the tone detection channel, feed audio to passthrough pipeline
    if (is_tone_detect_channel && is_passthrough_pipeline_active()) {
        feed_passthrough_audio(samples, frames);
        
        static int passthrough_feed_count = 0;
        if (passthrough_feed_count++ % 1000 == 0) {
            printf("[PASSTHROUGH] Feeding audio from tone detection channel: %s (frames=%lu)\n", 
                   audio_stream->channel_id, frames);
        }
    }
    
    // Process audio samples for EchoStream functionality
    for (unsigned long i = 0; i < frames; i++) {
        // Basic audio processing - can be extended for EchoStream features
        // float sample = samples[i];  // Unused for now
        // Add any necessary audio processing here
    }
    
    return paContinue;
}

// Audio output callback with passthrough pipeline integration
int audio_output_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo* time_info,
                                PaStreamCallbackFlags flags, void *user_data) {
    (void)input;
    (void)time_info;
    (void)flags;
    
    if (flags & paOutputUnderflow) {
        printf("[WARNING] Audio output underflow\n");
    }
    
    if (flags & paOutputOverflow) {
        printf("[WARNING] Audio output overflow\n");
    }
    
    float* out = (float*)output;
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    // Check if this is the passthrough target channel
    int is_passthrough_target = 0;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        struct channel_config* channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid && 
            channel_config->tone_detect && 
            channel_config->tone_config.valid &&
            strcmp(channel_config->tone_config.passthrough_channel, audio_stream->channel_id) == 0) {
            is_passthrough_target = 1;
            break;
        }
    }
    
    // If this is the passthrough target channel and pipeline is active, output passthrough audio
    if (is_passthrough_target && is_passthrough_pipeline_active()) {
        int samples_received = get_passthrough_audio(out, frames);
        
        static int passthrough_output_count = 0;
        if (passthrough_output_count++ % 1000 == 0) {
            printf("[PASSTHROUGH] Outputting audio to passthrough target: %s (frames=%lu, samples=%d)\n", 
                   audio_stream->channel_id, frames, samples_received);
        }
        
        // If we got passthrough audio, we're done
        if (samples_received > 0) {
            return paContinue;
        }
    }
    
    // Default: Fill output with silence or EchoStream audio
    for (unsigned long i = 0; i < frames; i++) {
        out[i] = 0.0f; // Silence for now
    }
    
    return paContinue;
}

// Setup audio for a channel
int setup_audio_for_channel(struct audio_stream* audio_stream) {
    if (!audio_stream) {
        printf("[ERROR] Invalid audio stream\n");
        return 0;
    }
    
    // Initialize audio stream parameters
    audio_stream->transmitting = 0;
    audio_stream->gpio_active = 0;
    audio_stream->buffer_size = SAMPLES_PER_FRAME;
    audio_stream->input_buffer_pos = 0;
    audio_stream->current_output_frame_pos = 0;
    
    // Initialize jitter buffer
    audio_stream->output_jitter.write_index = 0;
    audio_stream->output_jitter.read_index = 0;
    audio_stream->output_jitter.frame_count = 0;
    pthread_mutex_init(&audio_stream->output_jitter.mutex, NULL);
    
    return 1;
}

// Initialize PortAudio
int initialize_portaudio() {
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        printf("[ERROR] Failed to initialize PortAudio: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    printf("[INFO] PortAudio initialized successfully\n");
    return 1;
}

// Start transmission for a channel
int start_transmission_for_channel(struct audio_stream* audio_stream) {
    if (!audio_stream) {
        printf("[ERROR] Invalid audio stream\n");
        return 0;
    }
    
    // Set up input parameters
    PaStreamParameters input_params;
    input_params.device = audio_stream->device_index;
    input_params.channelCount = 1;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    // Set up output parameters
    PaStreamParameters output_params;
    output_params.device = audio_stream->device_index;
    output_params.channelCount = 2;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    // Open input stream
    PaError err = Pa_OpenStream(&audio_stream->input_stream,
                               &input_params,
                               NULL,
                               SAMPLE_RATE,
                               paFramesPerBufferUnspecified,
                               paClipOff,
                               audio_input_callback,
                               audio_stream);
        
        if (err != paNoError) {
        printf("[ERROR] Failed to open input stream: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    // Open output stream
    err = Pa_OpenStream(&audio_stream->output_stream,
                       NULL,
                       &output_params,
                       SAMPLE_RATE,
                       paFramesPerBufferUnspecified,
                       paClipOff,
                       audio_output_callback,
                       audio_stream);
    
    if (err != paNoError) {
        printf("[ERROR] Failed to open output stream: %s\n", Pa_GetErrorText(err));
                Pa_CloseStream(audio_stream->input_stream);
                audio_stream->input_stream = NULL;
                    return 0;
                }

    // Start streams
                err = Pa_StartStream(audio_stream->input_stream);
                if (err != paNoError) {
        printf("[ERROR] Failed to start input stream: %s\n", Pa_GetErrorText(err));
                    Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        audio_stream->input_stream = NULL;
        audio_stream->output_stream = NULL;
                    return 0;
                }
    
    err = Pa_StartStream(audio_stream->output_stream);
    if (err != paNoError) {
        printf("[ERROR] Failed to start output stream: %s\n", Pa_GetErrorText(err));
        Pa_StopStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        audio_stream->input_stream = NULL;
        audio_stream->output_stream = NULL;
        return 0;
    }
    
    printf("[INFO] Audio streams started successfully for device %d\n", audio_stream->device_index);
    return 1;
}

// Auto assign USB devices
void auto_assign_usb_devices() {
    printf("[INFO] Auto-assigning USB devices\n");
    
    int num_devices = Pa_GetDeviceCount();
    int usb_count = 0;
    
     for (int i = 0; i < num_devices && usb_count < MAX_CHANNELS; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info) {
            const PaHostApiInfo* host_api = Pa_GetHostApiInfo(device_info->hostApi);
            if (host_api && strcmp(host_api->name, "ALSA") == 0) {
                if (device_info->maxInputChannels > 0 && device_info->maxOutputChannels > 0) {
                    usb_devices[usb_count] = i;
                    printf("[INFO] Assigned USB device %d: %s\n", usb_count, device_info->name);
                    usb_count++;
                }
            }
        }
    }
    
    device_assigned = usb_count;
    printf("[INFO] Auto-assigned %d USB devices\n", device_assigned);
}

// Setup channel
int setup_channel(struct channel_context *ctx, const char *channel_id) {
    if (!ctx || !channel_id) {
        printf("[ERROR] Invalid parameters for setup_channel\n");
        return 0;
    }
    
    printf("[SETUP] Setting up channel: %s\n", channel_id);
    
    strncpy(ctx->audio.channel_id, channel_id, CHANNEL_ID_LEN - 1);
    ctx->audio.channel_id[CHANNEL_ID_LEN - 1] = '\0';
    
    // Get device for channel
    ctx->audio.device_index = get_device_for_channel(channel_id);
    if (ctx->audio.device_index == paNoDevice) {
        printf("[ERROR] No device found for channel %s\n", channel_id);
        printf("[ERROR] Available devices: ");
        for (int i = 0; i < device_assigned; i++) {
            printf("%d ", usb_devices[i]);
        }
        printf("\n");
        return 0;
    }
    
    printf("[SETUP] Channel %s assigned to device %d\n", channel_id, ctx->audio.device_index);
    
    // Setup audio for channel
    if (!setup_audio_for_channel(&ctx->audio)) {
        printf("[ERROR] Failed to setup audio for channel %s\n", channel_id);
        return 0;
    }
    
    // Start transmission for channel
    if (!start_transmission_for_channel(&ctx->audio)) {
        printf("[ERROR] Failed to start transmission for channel %s\n", channel_id);
        return 0;
    }
    
    ctx->active = 1;
    printf("[INFO] Channel %s setup successfully\n", channel_id);
    return 1;
}

// Get device for channel
PaDeviceIndex get_device_for_channel(const char* channel) {
    if (!channel) {
        return paNoDevice;
    }
    
    // First try to find the channel in the configuration to get its index
    for (int i = 0; i < MAX_CHANNELS; i++) {
        struct channel_config* channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid) {
            if (strcmp(channel_config->channel_id, channel) == 0) {
                // Check if we have a device available for this index
                if (i < device_assigned) {
                    printf("[DEVICE] Found channel %s at index %d, assigning device %d\n", 
                           channel, i, usb_devices[i]);
                    return usb_devices[i];
                } else {
                    printf("[DEVICE] Channel %s at index %d but no device available (only %d devices)\n", 
                           channel, i, device_assigned);
                    // Try to assign to the last available device instead
                    if (device_assigned > 0) {
                        printf("[DEVICE] Assigning to last available device %d instead\n", usb_devices[device_assigned-1]);
                        return usb_devices[device_assigned-1];
                    }
                    return paNoDevice;
                }
            }
        }
    }
    
    // Fallback to old hardcoded mapping for backward compatibility
    if (strcmp(channel, "channel_one") == 0) {
        return usb_devices[0];
    } else if (strcmp(channel, "channel_two") == 0) {
        return usb_devices[1];
    } else if (strcmp(channel, "channel_three") == 0) {
        return usb_devices[2];
    } else if (strcmp(channel, "channel_four") == 0) {
        // Use the last available device (device 4, which is index 3 in usb_devices array)
        if (device_assigned >= 4) {
            return usb_devices[3];  // This is actually device 4
        } else {
            printf("[DEVICE] Channel four requested but only %d devices available\n", device_assigned);
            return paNoDevice;
        }
    }
    
    // Handle empty or invalid channel IDs by assigning to available devices
    if (strlen(channel) == 0 || strcmp(channel, "channel_4") == 0) {
        // For channel_4 or empty channels, assign to device 4 (which is usb_devices[3])
        if (device_assigned >= 4) {
            printf("[DEVICE] Assigning empty/invalid channel %s to device 4 (usb_devices[3])\n", channel);
            return usb_devices[3];  // This is device 4
        } else {
            printf("[DEVICE] Channel %s requested but only %d devices available\n", channel, device_assigned);
            return paNoDevice;
        }
    }
    
    printf("[DEVICE] No device found for channel: %s\n", channel);
    return paNoDevice;
}

// Initialize audio devices
int initialize_audio_devices(void) {
    printf("[INFO] Initializing audio devices\n");
    
    if (!initialize_portaudio()) {
        return 0;
    }
    
    auto_assign_usb_devices();
    
    if (device_assigned == 0) {
        printf("[ERROR] No USB devices found\n");
        return 0;
    }
    
    // Initialize passthrough pipeline
    if (!init_passthrough_pipeline()) {
        printf("[WARNING] Failed to initialize passthrough pipeline\n");
        // Don't fail completely, just warn
    }
    
    printf("[INFO] Audio devices initialized successfully\n");
    return 1;
}

// Cleanup audio devices
int cleanup_audio_devices(void) {
    printf("[INFO] Cleaning up audio devices\n");
    
    // Cleanup passthrough pipeline first
    cleanup_passthrough_pipeline();
    
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (channels[i].active) {
            if (channels[i].audio.input_stream) {
                Pa_StopStream(channels[i].audio.input_stream);
                Pa_CloseStream(channels[i].audio.input_stream);
                channels[i].audio.input_stream = NULL;
            }
            if (channels[i].audio.output_stream) {
                Pa_StopStream(channels[i].audio.output_stream);
                Pa_CloseStream(channels[i].audio.output_stream);
                channels[i].audio.output_stream = NULL;
            }
            channels[i].active = 0;
        }
    }
    
    Pa_Terminate();
    printf("[INFO] Audio devices cleaned up\n");
    return 1;
}
