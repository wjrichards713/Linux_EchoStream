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

// Audio input callback - simplified without tone detection
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
    
    // Simple audio processing without tone detection
    const float* samples = (const float*)input;
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    // Process audio samples for EchoStream functionality
    for (unsigned long i = 0; i < frames; i++) {
        // Basic audio processing - can be extended for EchoStream features
        float sample = samples[i];
        // Add any necessary audio processing here
    }
    
    return paContinue;
}

// Audio output callback - simplified without passthrough
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
    
    // Simple output processing without passthrough
    float* out = (float*)output;
    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    
    // Fill output with silence or EchoStream audio
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
    
    strncpy(ctx->audio.channel_id, channel_id, CHANNEL_ID_LEN - 1);
    ctx->audio.channel_id[CHANNEL_ID_LEN - 1] = '\0';
    
    // Get device for channel
    ctx->audio.device_index = get_device_for_channel(channel_id);
    if (ctx->audio.device_index == paNoDevice) {
        printf("[ERROR] No device found for channel %s\n", channel_id);
        return 0;
    }
    
    // Setup audio for channel
    if (!setup_audio_for_channel(&ctx->audio)) {
        printf("[ERROR] Failed to setup audio for channel %s\n", channel_id);
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
    
    // Simple mapping - can be extended
    if (strcmp(channel, "channel_one") == 0) {
        return usb_devices[0];
    } else if (strcmp(channel, "channel_two") == 0) {
        return usb_devices[1];
    } else if (strcmp(channel, "channel_three") == 0) {
        return usb_devices[2];
    } else if (strcmp(channel, "channel_four") == 0) {
        return usb_devices[3];
    }
    
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
    
    printf("[INFO] Audio devices initialized successfully\n");
    return 1;
}

// Cleanup audio devices
int cleanup_audio_devices(void) {
    printf("[INFO] Cleaning up audio devices\n");
    
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
