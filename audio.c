#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "tone_detect.h"
#include "crypto.h"
#include "config.h"
#include "udp.h"
#include <math.h>
#include <unistd.h>

// Forward declarations
static int audio_input_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo *time_info,
                                PaStreamCallbackFlags flags, void *user_data);
static int audio_output_callback(const void *input, void *output, unsigned long frames,
                                 const PaStreamCallbackTimeInfo *time_info,
                                 PaStreamCallbackFlags flags, void *user_data);
void kill_processes_using_audio_device(PaDeviceIndex device_index);

// Global audio state
struct channel_context channels[MAX_CHANNELS] = {0};
PaDeviceIndex usb_devices[MAX_CHANNELS] = {paNoDevice, paNoDevice, paNoDevice, paNoDevice};
int device_assigned = 0;

// List all available PortAudio devices for debugging
void list_all_audio_devices(void)
{
    printf("[DEBUG] === LISTING ALL AVAILABLE AUDIO DEVICES ===\n");
    int num_devices = Pa_GetDeviceCount();
    printf("[DEBUG] Total devices available: %d\n", num_devices);

    for (int i = 0; i < num_devices; i++)
    {
        const PaDeviceInfo *device_info = Pa_GetDeviceInfo(i);
        if (device_info)
        {
            printf("[DEBUG] Device %d: %s\n", i, device_info->name);
            printf("[DEBUG]   - Max input channels: %d\n", device_info->maxInputChannels);
            printf("[DEBUG]   - Max output channels: %d\n", device_info->maxOutputChannels);
            printf("[DEBUG]   - Default sample rate: %f\n", device_info->defaultSampleRate);
            printf("[DEBUG]   - Host API: %s\n", Pa_GetHostApiInfo(device_info->hostApi)->name);
        }
        else
        {
            printf("[DEBUG] Device %d: <INVALID>\n", i);
        }
    }
    printf("[DEBUG] === END DEVICE LIST ===\n");
}

// Kill processes using a specific audio device
void kill_processes_using_audio_device(PaDeviceIndex device_index)
{
    if (device_index == paNoDevice) return;
    
    const PaDeviceInfo *device_info = Pa_GetDeviceInfo(device_index);
    if (!device_info) return;
    
    printf("[DEBUG] Killing processes using device %d: %s\n", device_index, device_info->name);
    
    // Kill common audio processes that might be using the device
    system("pkill -f pulseaudio 2>/dev/null || true");
    system("pkill -f jack 2>/dev/null || true");
    system("pkill -f arecord 2>/dev/null || true");
    system("pkill -f aplay 2>/dev/null || true");
    
    usleep(500000); // Wait 500ms for processes to terminate
}

// Initialize audio devices and kill interfering processes
int initialize_audio_devices(void)
{
    printf("[AUDIO INIT] Starting comprehensive audio device initialization...\n");

    // Kill any audio processes that might interfere
    printf("[AUDIO INIT] Killing interfering audio processes...\n");
    system("pkill -f pulseaudio 2>/dev/null || true");
    system("pkill -f jack 2>/dev/null || true");
    system("pkill -f alsa 2>/dev/null || true");
    system("pkill -f audio 2>/dev/null || true");
    system("pkill -f arecord 2>/dev/null || true");
    system("pkill -f aplay 2>/dev/null || true");

    // Wait a moment for processes to terminate
    usleep(500000); // 500ms

    // Restart PulseAudio to ensure it's working properly
    printf("[AUDIO INIT] Restarting PulseAudio...\n");
    system("pulseaudio --kill 2>/dev/null || true");
    usleep(200000); // 200ms
    system("pulseaudio --start 2>/dev/null || true");
    usleep(500000); // 500ms

    // Configure ALSA to ensure all USB audio devices are available
    printf("[AUDIO INIT] Configuring ALSA audio devices...\n");

    // Force reload ALSA modules
    system("sudo modprobe -r snd-usb-audio 2>/dev/null || true");
    usleep(200000); // 200ms
    system("sudo modprobe snd-usb-audio 2>/dev/null || true");
    usleep(500000); // 500ms

    // Set all USB audio cards to both input and output mode
    printf("[AUDIO INIT] Configuring USB audio cards for input/output mode...\n");
    
    // Test each USB audio card
    for (int card = 0; card < 10; card++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "test -e /proc/asound/card%d", card);
        if (system(cmd) == 0) {
            printf("[AUDIO INIT] Found USB audio card %d\n", card);
            printf("Card %d: EXISTS\n", card);
            
            // Configure for input/output
            printf("[AUDIO INIT] Configuring card %d for input/output...\n", card);
            
            // Test input
            snprintf(cmd, sizeof(cmd), "arecord -D hw:%d,0 -f S16_LE -r 48000 -c 1 -d 1 /dev/null 2>&1", card);
            printf("[AUDIO INIT] Card %d input test: %s\n", card, cmd);
            system(cmd);
            
            // Test output
            snprintf(cmd, sizeof(cmd), "aplay -D hw:%d,0 -f S16_LE -r 48000 -c 1 -d 1 /dev/zero 2>&1", card);
            printf("[AUDIO INIT] Card %d output test: %s\n", card, cmd);
            system(cmd);
        }
    }

    // Verify PortAudio device enumeration
    printf("[AUDIO INIT] Verifying PortAudio device enumeration...\n");
    list_all_audio_devices();
    
    printf("[AUDIO INIT] Audio device initialization completed\n");
    return 1;
}

// Initialize PortAudio
int initialize_portaudio(void)
{
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "PortAudio initialization failed: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    printf("[INFO] PortAudio initialized successfully\n");
    return 1;
}

// Get device for a specific channel
PaDeviceIndex get_device_for_channel(const char *channel)
{
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    extern int global_channel_count;
    
    // Find the channel index
    int channel_index = -1;
    for (int i = 0; i < global_channel_count; i++) {
        if (strcmp(global_channel_ids[i], channel) == 0) {
            channel_index = i;
            break;
        }
    }
    
    if (channel_index < 0 || channel_index >= MAX_CHANNELS) {
        printf("[ERROR] Channel %s not found in global channel list\n", channel);
        return paNoDevice;
    }
    
    return usb_devices[channel_index];
}

// Audio input callback with tone detection integration
static int audio_input_callback(const void *input, void *output, unsigned long frames,
                                const PaStreamCallbackTimeInfo *time_info,
                                PaStreamCallbackFlags flags, void *user_data)
{
    (void)output;    // Suppress unused parameter warning
    (void)time_info; // Suppress unused parameter warning
    (void)flags;     // Suppress unused parameter warning

    struct audio_stream *audio_stream = (struct audio_stream *)user_data;

    static int callback_count = 0;
    if (callback_count++ % 1000 == 0)
    { // More frequent logging - about every 3 seconds
        printf("Audio input callback called #%d (frames=%lu, transmitting=%d, gpio_active=%d)\n",
               callback_count, frames, audio_stream->transmitting, audio_stream->gpio_active);
    }

    if (!audio_stream->transmitting || !input || !audio_stream->gpio_active)
    {
        return paContinue;
    }

    static int audio_processing_count = 0;
    if (audio_processing_count++ % 1000 == 0)
    { // More frequent logging - about every 3 seconds
        printf("Audio processing for channel %s (frames=%lu)\n",
               audio_stream->channel_id, frames);
    }

    const float *samples = (const float *)input;

    // Check if this channel has tone detection enabled
    int channel_has_tone_detect = 0;
    for (int i = 0; i < MAX_CHANNELS; i++)
    {
        struct channel_config *channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid &&
            strcmp(channel_config->channel_id, audio_stream->channel_id) == 0)
        {
            channel_has_tone_detect = channel_config->tone_detect;
            break;
        }
    }

    // If tone detection is enabled for this channel, send audio to tone detection
    if (channel_has_tone_detect && is_tone_detect_enabled()) {
        update_shared_audio_buffer(samples, frames);
    }

    // Send audio data via UDP
    if (audio_stream->transmitting && audio_stream->gpio_active)
    {
        // Encode audio data
        int encoded_size = encode_audio_data(samples, frames, audio_stream->encoded_buffer, sizeof(audio_stream->encoded_buffer));
        if (encoded_size > 0)
        {
            // Send via UDP
            int udp_result = send_audio_data(audio_stream->channel_id, audio_stream->encoded_buffer, encoded_size);
            if (udp_result > 0)
            {
                static int audio_sent_count = 0;
                if (audio_sent_count++ % 1000 == 0)
                {
                    printf("Audio sent for channel %s (%d bytes, UDP result: %d)\n",
                           audio_stream->channel_id, encoded_size, udp_result);
                }
            }
        }
    }

    return paContinue;
}

// Audio output callback
static int audio_output_callback(const void *input, void *output, unsigned long frames,
                                 const PaStreamCallbackTimeInfo *time_info,
                                 PaStreamCallbackFlags flags, void *user_data)
{
    (void)input;     // Suppress unused parameter warning
    (void)time_info; // Suppress unused parameter warning
    (void)flags;     // Suppress unused parameter warning

    struct audio_stream *audio_stream = (struct audio_stream *)user_data;
    float *out = (float *)output;
    struct jitter_buffer *jitter = &audio_stream->output_jitter;

    static int callback_count = 0;
    if (callback_count++ % 100000 == 0)
    { // Even less frequent logging - about every 30 seconds
        printf("Audio output callback called for channel %s (frames=%lu, buffer_count=%d)\n",
               audio_stream->channel_id, frames, jitter->frame_count);
    }

    // Fill output with silence for now (EchoStream audio would come from jitter buffer)
    memset(out, 0, frames * sizeof(float));

    return paContinue;
}

// Setup audio stream for a channel
int setup_audio_stream(struct audio_stream *audio_stream, const char *channel_id)
{
    if (!audio_stream || !channel_id) {
        printf("[ERROR] Invalid parameters for setup_audio_stream\n");
        return 0;
    }

    strncpy(audio_stream->channel_id, channel_id, CHANNEL_ID_LEN - 1);
    audio_stream->channel_id[CHANNEL_ID_LEN - 1] = '\0';

    // Get device for this channel
    audio_stream->device_index = get_device_for_channel(audio_stream->channel_id);
    if (audio_stream->device_index == paNoDevice) {
        printf("[ERROR] No device available for channel %s\n", audio_stream->channel_id);
        return 0;
    }

    printf("[DEBUG] Channel %s assigned to device %d\n", audio_stream->channel_id, audio_stream->device_index);

    // Set up input parameters
    PaStreamParameters input_params;
    input_params.device = audio_stream->device_index;
    input_params.channelCount = 1; // Mono input
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(audio_stream->device_index)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;

    // Set up output parameters
    PaStreamParameters output_params;
    output_params.device = audio_stream->device_index;
    output_params.channelCount = 1; // Mono output
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(audio_stream->device_index)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;

    PaError err;

    // Create input stream
    printf("[DEBUG] Creating input stream for channel %s...\n", audio_stream->channel_id);
    err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
                        paClipOff, audio_input_callback, audio_stream);

    if (err != paNoError) {
        printf("[ERROR] Failed to create input stream for channel %s: %s\n",
               audio_stream->channel_id, Pa_GetErrorText(err));
        return 0;
    }

    // Create output stream
    printf("[DEBUG] Creating output stream for channel %s...\n", audio_stream->channel_id);
    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
                        paClipOff, audio_output_callback, audio_stream);

    if (err != paNoError) {
        printf("[ERROR] Failed to create output stream for channel %s: %s\n",
               audio_stream->channel_id, Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        return 0;
    }

    // Start input stream
    printf("[DEBUG] Starting input stream for channel %s...\n", audio_stream->channel_id);
    err = Pa_StartStream(audio_stream->input_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
    }

    // Start output stream
    printf("[DEBUG] Starting output stream for channel %s...\n", audio_stream->channel_id);
    err = Pa_StartStream(audio_stream->output_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio output start error: %s\n", Pa_GetErrorText(err));
        Pa_AbortStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
    }

    printf("Audio transmission started for channel %s (input + output)\n", audio_stream->channel_id);
    audio_stream->transmitting = 1;
    return 1;
}

// Setup channel
int setup_channel(const char *channel_id)
{
    if (!channel_id || strlen(channel_id) == 0) {
        printf("[ERROR] Invalid channel ID provided\n");
        return 0;
    }

    printf("Setting up channel with ID: %s\n", channel_id);

    // Find available slot
    int channel_index = -1;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (strlen(channels[i].audio.channel_id) == 0) {
            channel_index = i;
            break;
        }
    }

    if (channel_index == -1) {
        printf("[ERROR] No available channel slots\n");
        return 0;
    }

    // Assign USB device
    if (device_assigned < MAX_CHANNELS) {
        usb_devices[channel_index] = device_assigned;
        device_assigned++;
    } else {
        printf("[ERROR] No more USB devices available\n");
        return 0;
    }

    // Setup audio stream
    if (!setup_audio_stream(&channels[channel_index].audio, channel_id)) {
        printf("[ERROR] Failed to setup audio stream for channel %s\n", channel_id);
        return 0;
    }

    printf("[INFO] Channel %s setup completed successfully\n", channel_id);
    return 1;
}

// Cleanup audio devices
void cleanup_audio_devices(void)
{
    printf("[INFO] Cleaning up audio devices...\n");
    
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (channels[i].audio.input_stream) {
            Pa_AbortStream(channels[i].audio.input_stream);
            Pa_CloseStream(channels[i].audio.input_stream);
            channels[i].audio.input_stream = NULL;
        }
        if (channels[i].audio.output_stream) {
            Pa_AbortStream(channels[i].audio.output_stream);
            Pa_CloseStream(channels[i].audio.output_stream);
            channels[i].audio.output_stream = NULL;
        }
    }
    
    printf("[INFO] Audio devices cleaned up\n");
}