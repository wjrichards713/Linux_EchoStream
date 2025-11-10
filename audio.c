#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "audio.h"
#include "crypto.h"
#include "config.h"
#include "udp.h"
#include "tone_detect.h"
#include <math.h>
#include <stdlib.h>
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
        printf("[DEBUG] get_passthrough_target_channel_index: no tone config or passthrough disabled\n");
        return -1;
    }
    printf("[DEBUG] get_passthrough_target_channel_index: passthrough_channel=%s\n", tone_cfg->passthrough_channel);
    if (strcmp(tone_cfg->passthrough_channel, "channel_four") == 0) {
        printf("[DEBUG] Mapping channel_four to index 2\n");
        return 2; // Map to channel_three (index 2)
    }
    else if (strcmp(tone_cfg->passthrough_channel, "channel_three") == 0) {
        printf("[DEBUG] Mapping channel_three to index 2\n");
        return 2;
    }
    else if (strcmp(tone_cfg->passthrough_channel, "channel_two") == 0) {
        printf("[DEBUG] Mapping channel_two to index 1\n");
        return 1;
    }
    else if (strcmp(tone_cfg->passthrough_channel, "channel_one") == 0) {
        printf("[DEBUG] Mapping channel_one to index 0\n");
        return 0;
    }
    printf("[DEBUG] Unknown passthrough channel: %s\n", tone_cfg->passthrough_channel);
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
    
    // Special handling for the last channel (typically the passthrough target) - log when stream becomes inactive
    extern int global_channel_count;
    if (!is_active && channel_index == (global_channel_count - 1)) {
        static int last_channel_inactive_count = 0;
        if (last_channel_inactive_count++ % 100 == 0) {
            printf("[DEBUG] Last channel (index %d) output stream is inactive (count: %d)\n", 
                   channel_index, last_channel_inactive_count);
        }
    }
    
    // Return true only if stream exists AND is active
    // A stream that exists but isn't active can't play audio
    return is_active;
}

static int start_passthrough_fallback_output_stream(int target_channel_index) {
    if (target_channel_index < 0 || target_channel_index >= MAX_CHANNELS) {
        printf("[WARNING] Invalid target channel index %d for passthrough fallback\n", target_channel_index);
        return 0;
    }

    if (global_passthrough.active) {
        return 1;
    }

    const int max_devices = Pa_GetDeviceCount();
    PaDeviceIndex tried_devices[64];
    int tried_count = 0;

    PaDeviceIndex preferred = channels[target_channel_index].audio.device_index;
    if (preferred != paNoDevice && tried_count < 64) {
        tried_devices[tried_count++] = preferred;
    }

    PaDeviceIndex default_device = Pa_GetDefaultOutputDevice();
    if (default_device != paNoDevice && tried_count < 64) {
        int already_added = 0;
        for (int i = 0; i < tried_count; i++) {
            if (tried_devices[i] == default_device) {
                already_added = 1;
                break;
            }
        }
        if (!already_added) {
            tried_devices[tried_count++] = default_device;
        }
    }

    for (int device_index = 0; device_index < max_devices && tried_count < 64; device_index++) {
        const PaDeviceInfo* info = Pa_GetDeviceInfo(device_index);
        if (!info || info->maxOutputChannels <= 0) {
            continue;
        }
        int already_added = 0;
        for (int i = 0; i < tried_count; i++) {
            if (tried_devices[i] == device_index) {
                already_added = 1;
                break;
            }
        }
        if (!already_added) {
            tried_devices[tried_count++] = device_index;
        }
    }

    for (int i = 0; i < tried_count; i++) {
        PaDeviceIndex device = tried_devices[i];
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(device);
        if (!device_info || device_info->maxOutputChannels <= 0) {
            continue;
        }

        printf("[INFO] Passthrough fallback attempting device %d (%s)\n",
               (int)device, device_info->name);

        PaStreamParameters output_params;
        memset(&output_params, 0, sizeof(output_params));
        output_params.device = device;
        output_params.channelCount = 1;
        output_params.sampleFormat = paFloat32;
        output_params.suggestedLatency = device_info->defaultLowOutputLatency;
        output_params.hostApiSpecificStreamInfo = NULL;

        PaError err = Pa_OpenStream(&global_passthrough.output_stream,
                                    NULL,
                                    &output_params,
                                    48000,
                                    1024,
                                    paClipOff,
                                    NULL,
                                    NULL);
        if (err != paNoError) {
            printf("[WARNING] Passthrough fallback failed to open device %d (%s): %s\n",
                   (int)device, device_info->name, Pa_GetErrorText(err));
            continue;
        }

        err = Pa_StartStream(global_passthrough.output_stream);
        if (err != paNoError) {
            printf("[WARNING] Passthrough fallback failed to start device %d (%s): %s\n",
                   (int)device, device_info->name, Pa_GetErrorText(err));
            Pa_CloseStream(global_passthrough.output_stream);
            global_passthrough.output_stream = NULL;
            continue;
        }

        global_passthrough.output_device = device;
        global_passthrough.active = 1;
        global_passthrough.using_fallback_output = 1;

        if (pthread_create(&global_passthrough.thread, NULL, audio_passthrough_thread, NULL) != 0) {
            printf("[ERROR] Failed to create passthrough fallback thread for device %d (%s)\n",
                   (int)device, device_info->name);
            Pa_StopStream(global_passthrough.output_stream);
            Pa_CloseStream(global_passthrough.output_stream);
            global_passthrough.output_stream = NULL;
            global_passthrough.active = 0;
            global_passthrough.using_fallback_output = 0;
            continue;
        }

        printf("[INFO] Passthrough fallback output stream started on device %d (%s)\n",
               (int)device, device_info->name);
        return 1;
    }

    printf("[WARNING] Passthrough fallback could not open any available output device\n");
    return 0;
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
    if (strcmp(tone_cfg->passthrough_channel, "channel_four") == 0) idx = 2; // Map to channel_three (index 2)
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

// Initialize audio devices and kill interfering processes
int initialize_audio_devices(void) {
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

    // Configure ALSA to ensure all USB audio devices are available
    printf("[AUDIO INIT] Configuring ALSA audio devices...\n");

    // Force reload ALSA modules
    system("sudo modprobe -r snd-usb-audio 2>/dev/null || true");
    usleep(200000); // 200ms
    system("sudo modprobe snd-usb-audio 2>/dev/null || true");
    usleep(500000); // 500ms

    // Set all USB audio cards to both input and output mode
    printf("[AUDIO INIT] Configuring USB audio cards for input/output mode...\n");

    // Get list of USB audio cards
    FILE *fp = popen("cat /proc/asound/cards | grep -E 'USB Audio Device' | awk '{print $1}'", "r");
    if (fp) {
        char card_num[10];
        while (fgets(card_num, sizeof(card_num), fp)) {
            int card = atoi(card_num);
            if (card >= 0) {
                printf("[AUDIO INIT] Found USB audio card %d\n", card);
                
                // Just verify the card exists and is accessible
                char cmd[256];
                snprintf(cmd, sizeof(cmd), 
                    "test -e /proc/asound/card%d && echo 'Card %d: EXISTS' || echo 'Card %d: NOT FOUND'", 
                    card, card, card);
            system(cmd);
        }
        }
        pclose(fp);
    }

    // Verify PortAudio can see all devices
    printf("[AUDIO INIT] Verifying PortAudio device enumeration...\n");
    int device_count = Pa_GetDeviceCount();
    printf("[AUDIO INIT] PortAudio found %d audio devices\n", device_count);
    
    for (int i = 0; i < device_count; i++) {
        const PaDeviceInfo *device_info = Pa_GetDeviceInfo(i);
        if (device_info) {
            printf("[AUDIO INIT] Device %d: %s (Input: %d, Output: %d)\n", 
                   i, device_info->name, device_info->maxInputChannels, device_info->maxOutputChannels);
        }
    }

    printf("[AUDIO INIT] Audio device initialization completed\n");
    return 1;
}

// Cleanup audio devices and restore normal state
int cleanup_audio_devices(void) {
    printf("[AUDIO CLEANUP] Restoring audio devices to normal state...\n");
    
    // Stop any audio streams
    printf("[AUDIO CLEANUP] Stopping audio streams...\n");
    
    // Restart PulseAudio if it was running before
    printf("[AUDIO CLEANUP] Restarting PulseAudio...\n");
    system("pulseaudio --start 2>/dev/null || true");
    
    // Clean up temporary ALSA configurations
    printf("[AUDIO CLEANUP] Cleaning up temporary ALSA configurations...\n");
    system("rm -f /tmp/asound_card*.conf 2>/dev/null || true");
    
    printf("[AUDIO CLEANUP] Audio device cleanup completed\n");
    return 1;
}

// Enable tone detection
int enable_tone_detection(void) {
    pthread_mutex_lock(&global_tone_detect.mutex);
    global_tone_detect.enabled = 1;
    global_tone_detect.card1_input_enabled = 1;  // Enable Card 1 input for tone detection
    global_tone_detect.passthrough_mode = 0;  // Passthrough activated only during alerts
    pthread_mutex_unlock(&global_tone_detect.mutex);
    printf("[INFO] Tone detection ENABLED - source input active for tone detection\n");
    printf("[INFO] Passthrough will activate automatically during alerts\n");
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

    if (passthrough_mode) {
        int target_index = get_passthrough_target_channel_index();
        if (target_index >= 0) {
            if (!channel_has_output_stream(target_index)) {
                if (!start_passthrough_fallback_output_stream(target_index)) {
                    printf("[WARNING] Passthrough fallback output could not be started; target channel audio may be silent\n");
                }
            } else {
                global_passthrough.using_fallback_output = 0;
            }
        } else {
            printf("[WARNING] Passthrough mode enabled but no valid target channel index determined\n");
        }
    } else {
        if (global_passthrough.using_fallback_output) {
            stop_audio_passthrough();
        }
    }
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
    
    // Check if this channel has tone detection enabled (configurable from config.json)
    int channel_has_tone_detect = 0;
    for (int i = 0; i < MAX_CHANNELS; i++) {
        struct channel_config* channel_config = get_channel_config(i);
        if (channel_config && channel_config->valid && 
            strcmp(channel_config->channel_id, audio_stream->channel_id) == 0) {
            channel_has_tone_detect = channel_config->tone_detect;
            break;
        }
    }
    
    // For channels with tone detection, check if input is enabled
    // For other channels, always enable input
    int input_enabled = channel_has_tone_detect ? is_card1_input_enabled() : 1;
    
    if (!audio_stream->transmitting || !input || !audio_stream->gpio_active) {
        return paContinue;
    }

    static int audio_processing_count = 0;
    if (audio_processing_count++ % 100000 == 0) {  // Even less frequent logging - about every 30 seconds
        printf("Audio processing for channel %s (frames=%lu, input_enabled=%d)\n", 
               audio_stream->channel_id, frames, input_enabled);
    }
    
    const float *samples = (const float*)input;
    
    // Update shared buffer for passthrough (only for channels with tone detection enabled)
    // This allows any channel configured with tone_detect=true in config.json to provide audio for tone detection
    if (channel_has_tone_detect && is_tone_detect_enabled()) {
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
        if (shared_buffer_count++ % 1000 == 0) {
            printf("[DEBUG] Shared buffer updated: frames=%lu, valid=%d, sample_count=%d\n", 
                   frames, global_shared_buffer.valid, global_shared_buffer.sample_count);
        }
        
        // Process audio using Python approach (sliding window with FFT on specific time segments)
        if (process_audio_python_approach(samples, frames)) {
            printf("[TONE DETECTED] Alert tone detected on channel %s\n", audio_stream->channel_id);
                
                // Handle passthrough if configured
            struct channel_config* channel_config = NULL;
            for (int i = 0; i < MAX_CHANNELS; i++) {
                struct channel_config* cfg = get_channel_config(i);
                if (cfg && cfg->valid && strcmp(cfg->channel_id, audio_stream->channel_id) == 0) {
                    channel_config = cfg;
                    break;
                }
            }
            
            if (channel_config && channel_config->tone_config.tone_passthrough) {
                printf("[TONE] Passthrough triggered to %s\n", channel_config->tone_config.passthrough_channel);
                    // TODO: Implement passthrough functionality
                }
            }
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
int audio_output_callback(const void *input, void *output, unsigned long frames,
                         const PaStreamCallbackTimeInfo* time_info,
                         PaStreamCallbackFlags flags, void *user_data) {
    (void)input; // Suppress unused parameter warning
    (void)time_info; // Suppress unused parameter warning
    (void)flags; // Suppress unused parameter warning

    struct audio_stream* audio_stream = (struct audio_stream*)user_data;
    float *out = (float*)output;
    struct jitter_buffer *jitter = &audio_stream->output_jitter;

    static int callback_count = 0;
    if (callback_count++ % 1000 == 0) {  // More frequent logging for debugging
        printf("Audio output callback called for channel %s (frames=%lu, buffer_count=%d)\n",
               audio_stream->channel_id, frames, jitter->frame_count);
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
    
    // Special debug for the last channel (typically the passthrough target)
    extern int global_channel_count;
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    if (global_channel_count > 0 && strcmp(audio_stream->channel_id, global_channel_ids[global_channel_count - 1]) == 0) {
        static int last_channel_debug_count = 0;
        if (last_channel_debug_count++ % 1000 == 0) {
            printf("[DEBUG] Last channel callback: is_configured_target=%d, passthrough_mode=%d, frames=%lu\n", 
                   is_configured_target, passthrough_mode, frames);
        }
        
        // REMOVED: Test tone generation - this was causing the constant tone!
        // The target channel should only play alerts, not test tones
    }
    
    
    if (passthrough_mode) {
        // Configured passthrough target - route actual input audio (same as EchoStream) when recording is active
        // Check if recording is active (tone detected and timer running)
        extern int is_recording_active(void);
        extern struct shared_audio_buffer global_shared_buffer;
        int recording = is_recording_active();
        
        // Initialize output buffer to silence
        for (unsigned long i = 0; i < frames; i++) {
            out[i] = 0.0f;
        }
        
        if (recording) {
            // Recording active - route actual input audio from shared buffer (same audio as EchoStream)
            pthread_mutex_lock(&global_shared_buffer.mutex);
            
            if (global_shared_buffer.valid && global_shared_buffer.sample_count > 0) {
                // Copy actual input audio from shared buffer to output
                unsigned long samples_to_copy = frames;
                if (samples_to_copy > (unsigned long)global_shared_buffer.sample_count) {
                    samples_to_copy = global_shared_buffer.sample_count;
                }
                
                for (unsigned long i = 0; i < samples_to_copy; i++) {
                    out[i] = global_shared_buffer.samples[i];
                }
                
                // If we need more samples, repeat the last samples or fill with silence
                if (samples_to_copy < frames) {
                    // Repeat last sample or fill with silence
                    float last_sample = (samples_to_copy > 0) ? global_shared_buffer.samples[samples_to_copy - 1] : 0.0f;
                    for (unsigned long i = samples_to_copy; i < frames; i++) {
                        out[i] = last_sample; // Repeat last sample to avoid clicks
                    }
                }
                
                // DON'T mark buffer as invalid - let input callback overwrite it
                // This ensures continuous audio flow even if input callback is slightly delayed
                
                static int passthrough_log_count = 0;
                if (passthrough_log_count++ % 1000 == 0) {
                    printf("[PASSTHROUGH] Routing actual input audio to passthrough target (channel: %s, samples=%lu, valid=%d)\n", 
                           audio_stream->channel_id, samples_to_copy, global_shared_buffer.valid);
                }
            } else {
                // Buffer not ready yet - output silence for this frame
                // (input callback will update buffer soon)
                static int silence_warn_count = 0;
                if (silence_warn_count++ % 100 == 0) {
                    printf("[PASSTHROUGH] Buffer not ready - outputting silence (channel: %s, valid=%d, sample_count=%d)\n", 
                           audio_stream->channel_id, global_shared_buffer.valid, global_shared_buffer.sample_count);
                }
            }
            
            pthread_mutex_unlock(&global_shared_buffer.mutex);
        } else {
            // No recording active - output silence
            static int silence_count = 0;
            if (silence_count++ % 10000 == 0) {
                printf("[PASSTHROUGH] No recording active - outputting silence (channel: %s)\n", audio_stream->channel_id);
            }
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
    
    // Add alert tones if playing (for normal EchoStream output)
    // First, find the current channel index
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    extern int global_channel_count;
    int current_channel_index = -1;
    for (int i = 0; i < global_channel_count; i++) {
        if (strcmp(audio_stream->channel_id, global_channel_ids[i]) == 0) {
            current_channel_index = i;
            break;
        }
    }
    
    if (should_play_alert_on_channel(current_channel_index)) {
        // Track alert state to log only once when it starts
        static int was_playing_alert_2 = 0;
        
        int alert_samples = get_alert_audio_samples(out, frames);
        if (alert_samples > 0) {
            // Only log once when alert starts playing (not every callback)
            if (!was_playing_alert_2) {
                printf("[ALERT PLAYBACK] Playing alert tone on channel %s (index %d)\n", audio_stream->channel_id, current_channel_index);
                was_playing_alert_2 = 1;
            }
            // Alert is playing directly - no need to mix with EchoStream
            // The alert audio has already been written to the output buffer
        } else {
            // Alert finished, reset flag for next time
            if (was_playing_alert_2) {
                was_playing_alert_2 = 0;
            }
        }
    } else {
        // Debug: Log when alert is not playing - but only for the target channel
        if (strcmp(audio_stream->channel_id, "308e2478-072c-4d8b-ffff24d-51854e06711a") == 0) {
            static int not_playing_count = 0;
            if (++not_playing_count % 100 == 0) {
                printf("[DEBUG] Alert not playing for target channel %s (index %d) - frames=%lu\n", audio_stream->channel_id, current_channel_index, frames);
            }
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
    global_passthrough.using_fallback_output = 0;
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
        global_passthrough.using_fallback_output = 0;
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
    
    global_passthrough.using_fallback_output = 0;
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

    printf("[DEBUG] About to call Pa_OpenStream for input stream...\n");
    PaError err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, 48000, 1024, 
                                paClipOff, audio_input_callback, audio_stream);
    printf("[DEBUG] Pa_OpenStream for input stream returned: %s\n", Pa_GetErrorText(err));
    
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input stream error: %s\n", Pa_GetErrorText(err));
        return 0;
    }
    
    // Setup output stream for other channels
    // Use the assigned device for this channel to avoid conflicts
    output_params.device = audio_stream->device_index;
    output_params.channelCount = 1;
    
    // Check if this device is already in use by another channel
    static int used_devices[MAX_CHANNELS] = {-1, -1, -1, -1};
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (used_devices[i] == output_params.device) {
            printf("[DEBUG] Device %d already in use, trying next available device\n", output_params.device);
            // Try to find an unused device
            for (int j = 0; j < Pa_GetDeviceCount(); j++) {
                int device_in_use = 0;
                for (int k = 0; k < MAX_CHANNELS; k++) {
                    if (used_devices[k] == j) {
                        device_in_use = 1;
                        break;
                    }
                }
                if (!device_in_use) {
                    output_params.device = j;
                    printf("[DEBUG] Switching to unused device %d\n", j);
                    break;
                }
            }
            break;
        }
    }
    
    // Mark this device as used
    for (int i = 0; i < MAX_CHANNELS; i++) {
        if (used_devices[i] == -1) {
            used_devices[i] = output_params.device;
            break;
        }
    }
    output_params.sampleFormat = paFloat32;
    
    // Check device capabilities before setting latency
    const PaDeviceInfo* device_info = Pa_GetDeviceInfo(output_params.device);
    if (device_info) {
        printf("[DEBUG] Device %d info: maxOutputChannels=%d, maxInputChannels=%d, name=%s\n", 
               output_params.device, device_info->maxOutputChannels, device_info->maxInputChannels, device_info->name);
        
        // Ensure the device supports output
        if (device_info->maxOutputChannels == 0) {
            printf("[DEBUG] Device %d has no output channels, trying default output device\n", output_params.device);
            output_params.device = Pa_GetDefaultOutputDevice();
            device_info = Pa_GetDeviceInfo(output_params.device);
        }
        
        // Handle devices that PortAudio incorrectly reports as having 0 output channels
        // Some USB audio devices have output capability but PortAudio doesn't detect it properly
        if (device_info->maxOutputChannels == 0 && device_info->maxInputChannels > 0) {
            printf("[DEBUG] Device %d reported as input-only (0 output channels), but may actually support output\n", output_params.device);
            printf("[DEBUG] Attempting to use device anyway - PortAudio will handle the actual capability\n");
            // Don't adjust channel count - let PortAudio handle it
        } else if (output_params.channelCount > device_info->maxOutputChannels) {
            printf("[WARNING] Requested %d channels but device only supports %d, adjusting\n", 
                   output_params.channelCount, device_info->maxOutputChannels);
            output_params.channelCount = device_info->maxOutputChannels;
        }
        
        output_params.suggestedLatency = device_info->defaultLowOutputLatency;
    } else {
        printf("[ERROR] Could not get device info for device %d\n", output_params.device);
        return 0;
    }
    output_params.hostApiSpecificStreamInfo = NULL;

    printf("[DEBUG] Attempting to open output stream for channel %s on device %d\n", 
           audio_stream->channel_id, output_params.device);
    
    
    printf("[DEBUG] About to call Pa_OpenStream for output stream...\n");
    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                        paClipOff, audio_output_callback, audio_stream);
    printf("[DEBUG] Pa_OpenStream for output stream returned: %s\n", Pa_GetErrorText(err));
    
    // Check actual sample rate after stream creation
    if (err == paNoError) {
        const PaStreamInfo* stream_info = Pa_GetStreamInfo(audio_stream->output_stream);
        if (stream_info) {
            printf("[DEBUG] Output stream created with actual sample rate: %.1f Hz (requested: 48000 Hz)\n", stream_info->sampleRate);
            if (fabs(stream_info->sampleRate - 48000.0) > 1.0) {
                printf("[WARNING] Sample rate mismatch! Generated tones will play at wrong frequency!\n");
                printf("[WARNING] Frequency scaling factor: %.3f\n", stream_info->sampleRate / 48000.0);
            }
        }
    }

    if (err != paNoError) {
        fprintf(stderr, "PortAudio output stream error: %s\n", Pa_GetErrorText(err));
        printf("[DEBUG] Failed to create output stream for channel %s on device %d\n", audio_stream->channel_id, output_params.device);
        
        // Check if this is a device conflict (device already in use)
        if (err == paDeviceUnavailable) {
            printf("[DEBUG] Device %d is unavailable (likely in use by another channel)\n", output_params.device);
        }
        
        // Try alternative approaches for devices that fail with standard parameters
        printf("[DEBUG] Device %d failed, trying alternative parameters\n", output_params.device);
        
        // Try with different buffer sizes and sample rates
        int buffer_sizes[] = {512, 256, 1024, 2048};
        int sample_rates[] = {44100, 48000, 22050};
        
        for (int i = 0; i < 3 && err != paNoError; i++) {
            for (int j = 0; j < 4 && err != paNoError; j++) {
                printf("[DEBUG] Trying device %d with sample_rate=%d, buffer_size=%d\n", output_params.device, sample_rates[i], buffer_sizes[j]);
                err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, sample_rates[i], buffer_sizes[j],
                            paClipOff, audio_output_callback, audio_stream);
                if (err == paNoError) {
                    printf("[DEBUG] Device %d succeeded with sample_rate=%d, buffer_size=%d\n", output_params.device, sample_rates[i], buffer_sizes[j]);
                    break;
                }
            }
        }
        
         // If still failed, retry with default output device (skip for last channel to avoid PulseAudio issues)
         extern int global_channel_count;
         extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
         int is_last_channel_fallback = (global_channel_count > 0 && strcmp(audio_stream->channel_id, global_channel_ids[global_channel_count - 1]) == 0);
         
         if (err != paNoError && !is_last_channel_fallback) {
             PaDeviceIndex defOut = Pa_GetDefaultOutputDevice();
             if (defOut != paNoDevice && defOut != output_params.device) {
                 output_params.device = defOut;
                 output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
                 printf("[DEBUG] Retrying output open for channel %s using default output device %d\n", audio_stream->channel_id, (int)defOut);
                 err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                                     paClipOff, audio_output_callback, audio_stream);
                 
                 if (err == paNoError) {
                     printf("[DEBUG] Successfully opened output stream for channel %s on default device %d\n", 
                            audio_stream->channel_id, (int)defOut);
                 } else {
                     printf("[DEBUG] Default device %d also failed for channel %s: %s\n", 
                            (int)defOut, audio_stream->channel_id, Pa_GetErrorText(err));
                 }
             }
         }
    if (err != paNoError) {
            printf("WARNING: Output stream failed for channel %s (device %d), trying alternative output devices\n",
                   audio_stream->channel_id, audio_stream->device_index);

            // Special handling for the last channel - use Device 0 for output
            if (is_last_channel_fallback) {
                printf("[DEBUG] Last channel: Using Device 0 for output (bypassing problematic device)\n");
                output_params.device = 0; // Use Device 0 which we know works
                output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
                err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 48000, 1024,
                                    paClipOff, audio_output_callback, audio_stream);
                
                if (err == paNoError) {
                    printf("[DEBUG] Successfully opened last channel output on Device 0\n");
                } else {
                    printf("[DEBUG] Device 0 also failed for last channel: %s\n", Pa_GetErrorText(err));
                }
            }

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
                
                // Special debug for the last channel
                if (is_last_channel_fallback) {
                    printf("[DEBUG] Last channel is running in INPUT-ONLY mode - no output stream!\n");
                }
                
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

        printf("Audio transmission started for channel %s (input + output)\n", audio_stream->channel_id);
    
    // Special debug for the last channel
    extern int global_channel_count;
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    int is_last_channel_debug = (global_channel_count > 0 && strcmp(audio_stream->channel_id, global_channel_ids[global_channel_count - 1]) == 0);
    
    if (is_last_channel_debug) {
        printf("[DEBUG] Last channel stream status: input_active=%d, output_active=%d\n", 
               Pa_IsStreamActive(audio_stream->input_stream), 
               Pa_IsStreamActive(audio_stream->output_stream));
        printf("[DEBUG] Last channel stream pointers: input=%p, output=%p\n", 
               audio_stream->input_stream, audio_stream->output_stream);
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
    
     for (int i = 0; i < num_devices && usb_count < MAX_CHANNELS; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info && device_info->maxInputChannels > 0) {
            const PaHostApiInfo* host_info = Pa_GetHostApiInfo(device_info->hostApi);
            printf("[DEBUG] Device %d: %s (Host API: %s, Type: %d)\n", 
                   i, device_info->name, host_info->name, host_info->type);
            
            if (host_info && host_info->type == paALSA) {
                const char* name = device_info->name;
                if (strstr(name, "USB") || strstr(name, "usb") || 
                    strstr(name, "Audio Device") || strstr(name, "Headset") ||
                    strstr(name, "hw:2") || strstr(name, "hw:3") || 
                    strstr(name, "hw:4") || strstr(name, "hw:5")) {
                    usb_devices[usb_count] = i;
                    printf("USB Device %d assigned to slot %d: %s\n", i, usb_count, name);
                    usb_count++;
                }
            }
        }
    }
    
     if (usb_count == 0) {
         printf("No direct ALSA USB devices found, checking PulseAudio devices...\n");
         // Try to use PulseAudio devices that might be USB
         for (int i = 0; i < num_devices && usb_count < MAX_CHANNELS; i++) {
             const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
             if (device_info && device_info->maxInputChannels > 0) {
                 const PaHostApiInfo* host_info = Pa_GetHostApiInfo(device_info->hostApi);
                 if (host_info && strstr(host_info->name, "PulseAudio")) {
                     const char* name = device_info->name;
                     // For PulseAudio, we'll use the first few devices as they're likely USB
                     if (usb_count < 4) {  // We have 4 USB cards (2,3,4,5)
                         usb_devices[usb_count] = i;
                         printf("PulseAudio Device %d assigned to slot %d: %s\n", i, usb_count, name);
                         usb_count++;
                     }
                 }
             }
         }
         
         if (usb_count == 0) {
             printf("No USB audio devices found, using default input device for all channels\n");
    for (int i = 0; i < MAX_CHANNELS; i++) {
                 usb_devices[i] = Pa_GetDefaultInputDevice();
             }
         }
     } else if (usb_count < MAX_CHANNELS) {
         printf("Only %d USB device(s) found, some channels will share devices\n", usb_count);
         // Fill remaining slots with available devices
         for (int i = usb_count; i < MAX_CHANNELS; i++) {
             usb_devices[i] = usb_devices[i % usb_count];
         }
     }
    
    printf("Channel assignments:\n");
    extern int global_channel_count;
    for (int i = 0; i < global_channel_count; i++) {
        printf("Channel %s -> Device %d\n", global_channel_ids[i], usb_devices[i]);
    }
    
    device_assigned = 1;
}

PaDeviceIndex get_device_for_channel(const char* channel) {
    auto_assign_usb_devices();
    
    // Dynamic channel mapping based on config.json channel order
    // Find the channel index in the loaded configuration
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    extern int global_channel_count;
    
    int channel_index = -1;
    for (int i = 0; i < global_channel_count; i++) {
        if (strcmp(channel, global_channel_ids[i]) == 0) {
            channel_index = i;
            break;
        }
    }

    if (channel_index >= 0 && channel_index < MAX_CHANNELS) {
        printf("[DEBUG] Channel %s (index %d) assigned to USB device %d (device %d)\n", 
               channel, channel_index, channel_index, usb_devices[channel_index]);
        return usb_devices[channel_index];
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