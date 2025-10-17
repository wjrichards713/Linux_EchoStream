#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "audio.h"
#include "crypto.h"
#include "config.h"
#include "udp.h"
#include "tone_detect.h"
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

// Global shared audio buffer and passthrough
struct shared_audio_buffer global_shared_buffer = {0};
struct passthrough_audio_buffer global_passthrough_buffer = {0};
struct audio_passthrough global_passthrough = {0};

// Global tone detection control
struct tone_detect_control global_tone_detect = {0};

// Global tone passthrough control
struct tone_passthrough_control global_tone_passthrough = {0};

// Get the index of the passthrough target channel
int get_passthrough_target_channel_index(void) {
    struct tone_detect_config* tone_cfg = get_tone_detect_config(0);
    printf("[DEBUG] get_passthrough_target_channel_index: tone_cfg=%p\n", tone_cfg);
    if (tone_cfg) {
        printf("[DEBUG] get_passthrough_target_channel_index: tone_passthrough=%d, passthrough_channel='%s'\n", 
               tone_cfg->tone_passthrough, tone_cfg->passthrough_channel);
    }
    if (!tone_cfg || !tone_cfg->tone_passthrough) {
        printf("[DEBUG] get_passthrough_target_channel_index: returning -1 (no config or passthrough disabled)\n");
        return -1;
    }
    // FALLBACK: If channel_four is configured but Device 3 is input-only, use channel_two instead
    if (strcmp(tone_cfg->passthrough_channel, "channel_four") == 0) {
        printf("[WARNING] channel_four (Device 3) is input-only - using channel_two (Device 1) as passthrough target\n");
        return 1; // Use channel_two (666) which has working output
    }
    else if (strcmp(tone_cfg->passthrough_channel, "channel_three") == 0) {
        printf("[DEBUG] get_passthrough_target_channel_index: returning 2 (channel_three)\n");
        return 2;
    }
    else if (strcmp(tone_cfg->passthrough_channel, "channel_two") == 0) {
        printf("[DEBUG] get_passthrough_target_channel_index: returning 1 (channel_two)\n");
        return 1;
    }
    else if (strcmp(tone_cfg->passthrough_channel, "channel_one") == 0) {
        printf("[DEBUG] get_passthrough_target_channel_index: returning 0 (channel_one)\n");
        return 0;
    }
    printf("[DEBUG] get_passthrough_target_channel_index: returning -1 (unknown channel)\n");
    return -1;
}

// Create delayed output stream for configured passthrough target channel
int create_delayed_passthrough_output_stream(void) {
    printf("[DEBUG] *** create_delayed_passthrough_output_stream() CALLED ***\n");
    fflush(stdout); // Force output flush
    extern struct channel_context channels[];
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    
    // Get the configured passthrough target channel from config
    int passthrough_index = get_passthrough_target_channel_index();
    printf("[DEBUG] create_delayed_passthrough_output_stream: passthrough_index=%d\n", passthrough_index);
    if (passthrough_index == -1) {
        printf("[DEBUG] No passthrough target configured - skipping delayed output stream creation\n");
        return 1; // Not an error, just no passthrough configured
    }
    
    // Check input stream status before proceeding
    struct channel_context* channel = &channels[passthrough_index];
    struct audio_stream* audio_stream = &channel->audio;
    
    printf("[DEBUG] *** INPUT STREAM STATUS CHECK FOR CHANNEL %d ***\n", passthrough_index);
    printf("[DEBUG] Input stream pointer: %p\n", (void*)audio_stream->input_stream);
    printf("[DEBUG] Output stream pointer: %p\n", (void*)audio_stream->output_stream);
    printf("[DEBUG] Device index: %d\n", audio_stream->device_index);
    
    if (audio_stream->input_stream == NULL) {
        printf("[CRITICAL] *** INPUT STREAM IS NULL - THIS SHOULD NOT HAPPEN ***\n");
        printf("[ERROR] Passthrough target channel %d has no input stream - cannot create output stream\n", passthrough_index);
        printf("[ERROR] The input stream should have been created during main channel initialization\n");
        return 0;
    } else {
        printf("[DEBUG] Input stream exists - checking if active\n");
        if (Pa_IsStreamActive(audio_stream->input_stream)) {
            printf("[DEBUG] Input stream is active ✓\n");
        } else {
            printf("[WARNING] Input stream exists but is not active\n");
        }
    }
    
    if (passthrough_index >= MAX_CHANNELS) {
        printf("[ERROR] Invalid passthrough target index %d\n", passthrough_index);
        return 0;
    }
    
    printf("[DEBUG] *** CREATING DELAYED OUTPUT STREAM FOR PASSTHROUGH TARGET CHANNEL %d (%s) ***\n", 
           passthrough_index, global_channel_ids[passthrough_index]);
    printf("[DEBUG] Waiting 3 seconds for other channels to stabilize...\n");
    sleep(3); // Wait 3 seconds for other channels to fully initialize
    
    // CRITICAL: Passthrough target MUST work - try with limited attempts
    printf("[CRITICAL] *** PASSTHROUGH TARGET MUST WORK - RETRYING WITH LIMITED ATTEMPTS ***\n");
    
    int attempt_count = 0;
    int max_attempts = 3; // Limit attempts to prevent infinite loop
    while (attempt_count < max_attempts) {
        attempt_count++;
        printf("[DEBUG] *** PASSTHROUGH TARGET CREATION ATTEMPT #%d ***\n", attempt_count);
        
        // List all devices for debugging
        list_all_audio_devices();
        
        // Check if device index is valid
        int total_devices = Pa_GetDeviceCount();
        if (audio_stream->device_index >= total_devices) {
            printf("[ERROR] *** DEVICE INDEX %d IS INVALID - ONLY %d DEVICES AVAILABLE! ***\n", 
                   audio_stream->device_index, total_devices);
            printf("[ERROR] *** This is why passthrough target is failing! ***\n");
            sleep(5); // Wait before retry
            continue;
        }
        
        // CRITICAL: Create a duplex stream (input+output) instead of separate streams
        // This avoids device conflicts and is the proper way to handle passthrough
        printf("[DEBUG] Creating duplex stream for passthrough target (input+output on same device)\n");
        
        // First, close the existing input stream to free the device
        if (audio_stream->input_stream != NULL) {
            printf("[DEBUG] Closing existing input stream to create duplex stream\n");
            Pa_StopStream(audio_stream->input_stream);
            Pa_CloseStream(audio_stream->input_stream);
            audio_stream->input_stream = NULL;
            usleep(500000); // Wait 500ms for device to be fully released
        }
        
        // Set up input parameters for duplex stream
        PaStreamParameters input_params;
        input_params.device = audio_stream->device_index;
        input_params.channelCount = 1;
        input_params.sampleFormat = paFloat32;
        input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
        input_params.hostApiSpecificStreamInfo = NULL;
        
        // Set up output parameters for duplex stream
        PaStreamParameters output_params;
        output_params.device = audio_stream->device_index; // Same device for duplex
        output_params.channelCount = 2;
        output_params.sampleFormat = paFloat32;
        output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
        output_params.hostApiSpecificStreamInfo = NULL;
        
        // Add comprehensive device diagnostics
        printf("[DEBUG] Device diagnostics for device %d:\n", audio_stream->device_index);
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(audio_stream->device_index);
        if (device_info) {
            printf("[DEBUG] Device name: %s\n", device_info->name);
            printf("[DEBUG] Max output channels: %d\n", device_info->maxOutputChannels);
            printf("[DEBUG] Default sample rate: %f\n", device_info->defaultSampleRate);
            printf("[DEBUG] Default low output latency: %f\n", device_info->defaultLowOutputLatency);
            printf("[DEBUG] Default high output latency: %f\n", device_info->defaultHighOutputLatency);
            
            // Check if device supports output
            if (device_info->maxOutputChannels == 0) {
                printf("[ERROR] *** DEVICE %d HAS NO OUTPUT CHANNELS - CANNOT CREATE OUTPUT STREAM! ***\n", audio_stream->device_index);
                printf("[ERROR] *** This device is INPUT-ONLY and cannot be used for passthrough! ***\n");
                // Try to select an alternative USB device with output capability for OUTPUT ONLY
                // Check if any other channels are using the same device for output
                PaDeviceIndex fallback_output = paNoDevice;
                for (int i = 0; i < MAX_CHANNELS; i++) {
                    PaDeviceIndex cand = usb_devices[i];
                    if (cand == paNoDevice || cand == audio_stream->device_index) continue;
                    
                    // Check if this device is already being used by another channel for output
                    int device_in_use = 0;
                    for (int j = 0; j < MAX_CHANNELS; j++) {
                        if (j != passthrough_index && channels[j].audio.output_stream != NULL) {
                            // Check if this channel is using the same device
                            if (channels[j].audio.device_index == cand) {
                                device_in_use = 1;
                                break;
                            }
                        }
                    }
                    
                    if (device_in_use) continue; // Skip devices already in use
                    
                    const PaDeviceInfo* cand_info = Pa_GetDeviceInfo(cand);
                    if (cand_info && cand_info->maxOutputChannels > 0) {
                        // Only use ALSA devices, skip PulseAudio and default
                        const PaHostApiInfo* host_api = Pa_GetHostApiInfo(cand_info->hostApi);
                        if (host_api && strcmp(host_api->name, "ALSA") == 0) {
                            fallback_output = cand;
                            break;
                        }
                    }
                }
                if (fallback_output != paNoDevice) {
                    printf("[DEBUG] Using alternative device %d for OUTPUT while keeping INPUT on %d\n", fallback_output, audio_stream->device_index);
                    output_params.device = fallback_output;
                    output_params.suggestedLatency = Pa_GetDeviceInfo(fallback_output)->defaultLowOutputLatency;
                } else {
                    printf("[CRITICAL] *** NO ALTERNATIVE OUTPUT DEVICE AVAILABLE! ***\n");
                    printf("[CRITICAL] *** ALL USB DEVICES ARE INPUT-ONLY OR IN USE! ***\n");
                    sleep(5);
                    continue;
                }
            }
            
            // Check if device supports 44100 Hz (native sample rate) - test the ACTUAL output device
            PaError test_err = Pa_IsFormatSupported(NULL, &output_params, 44100.0);
            if (test_err != paFormatIsSupported) {
                if (test_err == paUnanticipatedHostError) {
                    printf("[WARNING] *** OUTPUT DEVICE %d IS BUSY - LIKELY USED BY INPUT STREAM ***\n", output_params.device);
                    printf("[WARNING] *** Format test error: %s (code: %d) - Device is in use ***\n", Pa_GetErrorText(test_err), test_err);
                    
                    // Check if this device is being used by the input stream of the same channel
                    if (audio_stream->input_stream != NULL) {
                        printf("[DEBUG] *** TEMPORARILY CLOSING INPUT STREAM TO FREE DEVICE FOR OUTPUT ***\n");
                        printf("[DEBUG] *** CLOSING INPUT STREAM FOR CHANNEL %d (device %d) ***\n", 
                               passthrough_index, audio_stream->device_index);
                        Pa_StopStream(audio_stream->input_stream);
                        Pa_CloseStream(audio_stream->input_stream);
                        audio_stream->input_stream = NULL;
                        printf("[DEBUG] *** INPUT STREAM CLOSED AND SET TO NULL FOR CHANNEL %d ***\n", passthrough_index);
                        usleep(1000000); // Wait 1 second for device to be fully released
                        
                        // Retry the format test
                        test_err = Pa_IsFormatSupported(NULL, &output_params, 44100.0);
                        if (test_err == paFormatIsSupported) {
                            printf("[DEBUG] Output device %d supports 44100 Hz sample rate ✓ (after closing input stream)\n", output_params.device);
                        } else {
                            printf("[ERROR] *** OUTPUT DEVICE %d STILL BUSY AFTER CLOSING INPUT STREAM! ***\n", output_params.device);
                            printf("[ERROR] *** Format test error: %s (code: %d) ***\n", Pa_GetErrorText(test_err), test_err);
                            sleep(5); // Wait before retry
                            continue;
                        }
                    } else {
                        printf("[ERROR] *** DEVICE %d IS BUSY BUT NO INPUT STREAM TO CLOSE! ***\n", audio_stream->device_index);
                        sleep(5); // Wait before retry
                        continue;
                    }
                } else {
                    printf("[ERROR] *** OUTPUT DEVICE %d DOES NOT SUPPORT 44100 Hz SAMPLE RATE! ***\n", output_params.device);
                    printf("[ERROR] *** Format test error: %s (code: %d) ***\n", Pa_GetErrorText(test_err), test_err);
                    sleep(5); // Wait before retry
                    continue;
                }
            } else {
                printf("[DEBUG] Output device %d supports 44100 Hz sample rate ✓\n", output_params.device);
            }
        } else {
            printf("[ERROR] *** CANNOT GET DEVICE INFO FOR DEVICE %d - DEVICE DOES NOT EXIST! ***\n", audio_stream->device_index);
            printf("[ERROR] *** This is a critical error - device %d is invalid! ***\n", audio_stream->device_index);
            sleep(5); // Wait before retry
            continue;
        }
        
        int FORCED_SAMPLE_RATE = SAMPLE_RATE; // Use consistent 48000 Hz
        int buffer_sizes[] = {1024, 2048, 512, 256, 4096, 8192}; // Balanced approach
        
        printf("[DEBUG] *** STARTING STREAM CREATION LOOP FOR DELAYED CREATION ***\n");
        printf("[DEBUG] *** Device %d, Sample Rate: %d, Channels: %d ***\n", 
               output_params.device, FORCED_SAMPLE_RATE, output_params.channelCount);
        
        // CRITICAL: Test format support BEFORE attempting to create stream
        printf("[DEBUG] *** TESTING FORMAT SUPPORT FOR DUPLEX STREAM ***\n");
        PaError format_test = Pa_IsFormatSupported(&input_params, &output_params, FORCED_SAMPLE_RATE);
        if (format_test == paFormatIsSupported) {
            printf("[DEBUG] *** FORMAT SUPPORT TEST PASSED - DUPLEX STREAM SHOULD WORK ***\n");
        } else {
            printf("[ERROR] *** FORMAT SUPPORT TEST FAILED: %s (code: %d) ***\n", Pa_GetErrorText(format_test), format_test);
            printf("[ERROR] *** Device %d does not support duplex stream with sample rate %d ***\n", 
                   output_params.device, FORCED_SAMPLE_RATE);
            
            // Try with device's default sample rate instead
            const PaDeviceInfo* device_info = Pa_GetDeviceInfo(output_params.device);
            if (device_info) {
                double default_rate = device_info->defaultSampleRate;
                printf("[DEBUG] *** TRYING WITH DEVICE DEFAULT SAMPLE RATE: %.0f Hz ***\n", default_rate);
                format_test = Pa_IsFormatSupported(&input_params, &output_params, default_rate);
                if (format_test == paFormatIsSupported) {
                    printf("[DEBUG] *** FORMAT SUPPORT TEST PASSED WITH DEFAULT RATE %.0f Hz ***\n", default_rate);
                    // Update the sample rate to use device default
                    FORCED_SAMPLE_RATE = (int)default_rate;
                } else {
                    printf("[ERROR] *** FORMAT SUPPORT TEST FAILED EVEN WITH DEFAULT RATE: %s ***\n", Pa_GetErrorText(format_test));
                }
            }
        }
        
        PaError err = paNoError;
        for (int j = 0; j < 6; j++) {
            printf("[DEBUG] *** DELAYED CREATION ATTEMPT %d/6: Trying sample_rate=%d, buffer_size=%d ***\n", 
                   j+1, FORCED_SAMPLE_RATE, buffer_sizes[j]);
            
                    // Create duplex stream (input+output) and use output callback to ensure output is filled
                    err = Pa_OpenStream(&audio_stream->output_stream, &input_params, &output_params, 
                                       FORCED_SAMPLE_RATE, buffer_sizes[j], 
                                       paClipOff, audio_output_callback, audio_stream);
            
            if (err == paNoError) {
                printf("[DEBUG] *** SUCCESS! Delayed duplex stream created with sample_rate=%d, buffer_size=%d ***\n", 
                       FORCED_SAMPLE_RATE, buffer_sizes[j]);
                
                // Start the duplex stream
                err = Pa_StartStream(audio_stream->output_stream);
                if (err == paNoError) {
                    printf("[DEBUG] *** PASSTHROUGH TARGET CHANNEL %d DELAYED DUPLEX STREAM STARTED SUCCESSFULLY! ***\n", passthrough_index);
                    printf("[DEBUG] *** PASSTHROUGH AUDIO SHOULD NOW WORK ON CHANNEL %d (%s)! ***\n", 
                           passthrough_index, global_channel_ids[passthrough_index]);
                    
                    // Set the input stream pointer to the same duplex stream
                    audio_stream->input_stream = audio_stream->output_stream;
                    printf("[DEBUG] *** INPUT STREAM POINTER SET TO DUPLEX STREAM FOR CHANNEL %d ***\n", passthrough_index);
                    
                    return 1; // SUCCESS - exit the function
                } else {
                    printf("[ERROR] Pa_StartStream failed for delayed stream: %s\n", Pa_GetErrorText(err));
                    Pa_CloseStream(audio_stream->output_stream);
                    audio_stream->output_stream = NULL;
                    err = paNoError;
                }
            } else if (err == paDeviceUnavailable) {
                printf("[DEBUG] Device %d is busy - killing processes using it\n", output_params.device);
                kill_processes_using_audio_device(output_params.device);
                usleep(1000000); // Wait 1 second
                err = paNoError;
            } else if (err == paUnanticipatedHostError) {
                printf("[DEBUG] Device %d has hardware error - waiting and retrying\n", output_params.device);
                usleep(2000000); // Wait 2 seconds
                err = paNoError;
            } else {
                // Log any other errors with full details
                printf("[ERROR] Pa_OpenStream failed with error: %s (code: %d)\n", Pa_GetErrorText(err), err);
                printf("[ERROR] Device: %d, Sample Rate: %d, Buffer Size: %d\n", 
                       output_params.device, FORCED_SAMPLE_RATE, buffer_sizes[j]);
                printf("[ERROR] Input params: device=%d, channels=%d, format=%ld, latency=%f\n",
                       input_params.device, input_params.channelCount, input_params.sampleFormat, input_params.suggestedLatency);
                printf("[ERROR] Output params: device=%d, channels=%d, format=%ld, latency=%f\n",
                       output_params.device, output_params.channelCount, output_params.sampleFormat, output_params.suggestedLatency);
                err = paNoError; // Try next buffer size
            }
        }
        
        // If we get here, all attempts failed - wait and try again
        printf("[ERROR] *** ATTEMPT #%d FAILED - WAITING 5 SECONDS BEFORE RETRY ***\n", attempt_count);
        if (attempt_count < max_attempts) {
            printf("[CRITICAL] *** PASSTHROUGH TARGET MUST WORK - CONTINUING TO RETRY ***\n");
            sleep(5); // Wait 5 seconds before next attempt
        } else {
            printf("[CRITICAL] *** ALL %d ATTEMPTS FAILED - PASSTHROUGH TARGET CANNOT BE CREATED ***\n", max_attempts);
        }
    }
    
    // If we get here, all attempts failed
    printf("[CRITICAL] *** PASSTHROUGH TARGET CREATION FAILED AFTER %d ATTEMPTS ***\n", max_attempts);
    return 0;
}

// List all available PortAudio devices for debugging
void list_all_audio_devices(void) {
    printf("[DEBUG] === LISTING ALL AVAILABLE AUDIO DEVICES ===\n");
    int num_devices = Pa_GetDeviceCount();
    printf("[DEBUG] Total devices available: %d\n", num_devices);
    
    for (int i = 0; i < num_devices; i++) {
        const PaDeviceInfo* device_info = Pa_GetDeviceInfo(i);
        if (device_info) {
            printf("[DEBUG] Device %d: %s\n", i, device_info->name);
            printf("[DEBUG]   - Max input channels: %d\n", device_info->maxInputChannels);
            printf("[DEBUG]   - Max output channels: %d\n", device_info->maxOutputChannels);
            printf("[DEBUG]   - Default sample rate: %f\n", device_info->defaultSampleRate);
            printf("[DEBUG]   - Host API: %s\n", Pa_GetHostApiInfo(device_info->hostApi)->name);
        } else {
            printf("[DEBUG] Device %d: <INVALID>\n", i);
        }
    }
    printf("[DEBUG] === END DEVICE LIST ===\n");
}

// Kill processes using a specific audio device
void kill_processes_using_audio_device(PaDeviceIndex device_index) {
    // Convert PortAudio device index to ALSA device name
    // Device 3 = hw:5,0 (PortAudio device 3 maps to ALSA card 5)
    int alsa_card = device_index + 2; // PortAudio device 3 -> ALSA card 5
    
    printf("[DEBUG] Killing processes using ALSA card %d (PortAudio device %d)\n", alsa_card, device_index);
    
    // Kill processes using the specific ALSA card
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "fuser -k /dev/snd/pcmC%dD0p 2>/dev/null", alsa_card);
    printf("[DEBUG] Executing: %s\n", cmd);
    system(cmd);
    
    // Also kill processes using the card in general
    snprintf(cmd, sizeof(cmd), "fuser -k /dev/snd/controlC%d 2>/dev/null", alsa_card);
    printf("[DEBUG] Executing: %s\n", cmd);
    system(cmd);
    
    // Kill any PulseAudio processes that might be using the device
    system("pkill -f pulseaudio 2>/dev/null");
    
    // Small delay to let processes terminate
    usleep(100000); // 100ms
    
    printf("[DEBUG] Finished killing processes for device %d\n", device_index);
}

// Repair/restart an inactive output stream for a passthrough target channel
int repair_passthrough_output_stream(int channel_index) {
    extern struct channel_context channels[];
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    
    if (channel_index < 0 || channel_index >= MAX_CHANNELS) {
        printf("[ERROR] repair_passthrough_output_stream: invalid channel_index %d\n", channel_index);
        return 0;
    }
    
    struct channel_context* channel = &channels[channel_index];
    struct audio_stream* audio_stream = &channel->audio;
    
    printf("[DEBUG] *** REPAIR FUNCTION STREAM STATUS CHECK FOR CHANNEL %d ***\n", channel_index);
    printf("[DEBUG] Input stream pointer: %p\n", (void*)audio_stream->input_stream);
    printf("[DEBUG] Output stream pointer: %p\n", (void*)audio_stream->output_stream);
    printf("[DEBUG] Device index: %d\n", audio_stream->device_index);
    
    // If both streams are NULL, prefer creating OUTPUT first;
    // input will be recreated after output succeeds.
    if (!audio_stream->input_stream && !audio_stream->output_stream) {
        printf("[CRITICAL] *** NO AUDIO STREAMS FOR CHANNEL %d - WILL CREATE OUTPUT FIRST ***\n", channel_index);
    }
    
    printf("[DEBUG] *** ATTEMPTING TO REPAIR PASSTHROUGH TARGET CHANNEL %d (%s) ***\n", 
           channel_index, global_channel_ids[channel_index]);
    
    // If stream exists but is inactive, try to restart it
    if (audio_stream->output_stream) {
        printf("[DEBUG] Channel %d has output stream but is inactive - attempting restart\n", channel_index);
        
        // Stop the stream first
        PaError err = Pa_StopStream(audio_stream->output_stream);
        if (err != paNoError) {
            printf("[DEBUG] Pa_StopStream failed: %s\n", Pa_GetErrorText(err));
        }
        
        // Close the stream
        err = Pa_CloseStream(audio_stream->output_stream);
        if (err != paNoError) {
            printf("[DEBUG] Pa_CloseStream failed: %s\n", Pa_GetErrorText(err));
        }
        
        audio_stream->output_stream = NULL;
    }
    
    // Now try to recreate the output stream - FORCE 48000 Hz ONLY
    printf("[DEBUG] Recreating output stream for passthrough target channel %d\n", channel_index);
    
    // List all devices for debugging
    list_all_audio_devices();
    
    // Check if device index is valid
    int total_devices = Pa_GetDeviceCount();
    if (audio_stream->device_index >= total_devices) {
        printf("[ERROR] *** DEVICE INDEX %d IS INVALID - ONLY %d DEVICES AVAILABLE! ***\n", 
               audio_stream->device_index, total_devices);
        printf("[ERROR] *** This is why passthrough target is failing! ***\n");
        return 0;
    }
    
    // Define constants locally
    const int AUDIO_BUFFER_SIZE = 1024; // Balanced to prevent underruns without choppiness
    const int AUDIO_CHANNELS = 2;
    const int FORCED_SAMPLE_RATE = SAMPLE_RATE; // Use consistent 48000 Hz
    
    // Set up output parameters for diagnostics
    PaStreamParameters output_params;
    output_params.device = audio_stream->device_index;
    output_params.channelCount = AUDIO_CHANNELS;
    output_params.sampleFormat = paFloat32;
    output_params.suggestedLatency = Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    // Add comprehensive device diagnostics
    printf("[DEBUG] Device diagnostics for device %d:\n", audio_stream->device_index);
    const PaDeviceInfo* device_info = Pa_GetDeviceInfo(audio_stream->device_index);
    if (device_info) {
        printf("[DEBUG] Device name: %s\n", device_info->name);
        printf("[DEBUG] Max output channels: %d\n", device_info->maxOutputChannels);
        printf("[DEBUG] Default sample rate: %f\n", device_info->defaultSampleRate);
        printf("[DEBUG] Default low output latency: %f\n", device_info->defaultLowOutputLatency);
        printf("[DEBUG] Default high output latency: %f\n", device_info->defaultHighOutputLatency);
        
        // Check if device supports output
        if (device_info->maxOutputChannels == 0) {
            printf("[ERROR] *** DEVICE %d HAS NO OUTPUT CHANNELS - CANNOT CREATE OUTPUT STREAM! ***\n", audio_stream->device_index);
            printf("[ERROR] *** This device is INPUT-ONLY and cannot be used for passthrough! ***\n");
            // Try to select an alternative USB device with output capability for OUTPUT ONLY
            // Check if any other channels are using the same device for output
            PaDeviceIndex fallback_output = paNoDevice;
            for (int i = 0; i < MAX_CHANNELS; i++) {
                PaDeviceIndex cand = usb_devices[i];
                if (cand == paNoDevice || cand == audio_stream->device_index) continue;
                
                // Check if this device is already being used by another channel for output
                int device_in_use = 0;
                for (int j = 0; j < MAX_CHANNELS; j++) {
                    if (j != channel_index && channels[j].audio.output_stream != NULL) {
                        // Check if this channel is using the same device
                        if (channels[j].audio.device_index == cand) {
                            device_in_use = 1;
                            break;
                        }
                    }
                }
                
                if (device_in_use) continue; // Skip devices already in use
                
                const PaDeviceInfo* cand_info = Pa_GetDeviceInfo(cand);
                if (cand_info && cand_info->maxOutputChannels > 0) {
                    // Only use ALSA devices, skip PulseAudio and default
                    const PaHostApiInfo* host_api = Pa_GetHostApiInfo(cand_info->hostApi);
                    if (host_api && strcmp(host_api->name, "ALSA") == 0) {
                        fallback_output = cand;
                        break;
                    }
                }
            }
            if (fallback_output != paNoDevice) {
                printf("[DEBUG] Using alternative device %d for OUTPUT while keeping INPUT on %d (repair)\n", fallback_output, audio_stream->device_index);
                output_params.device = fallback_output;
                output_params.suggestedLatency = Pa_GetDeviceInfo(fallback_output)->defaultLowOutputLatency;
            } else {
                printf("[CRITICAL] *** NO ALTERNATIVE OUTPUT DEVICE AVAILABLE! ***\n");
                printf("[CRITICAL] *** ALL USB DEVICES ARE INPUT-ONLY OR IN USE! ***\n");
                return 0;
            }
        }
        
        // Check if device supports 44100 Hz (native sample rate) - test the ACTUAL output device
        PaError test_err = Pa_IsFormatSupported(NULL, &output_params, 44100.0);
        if (test_err != paFormatIsSupported) {
        if (test_err == paUnanticipatedHostError) {
            printf("[WARNING] *** DEVICE %d IS BUSY - LIKELY USED BY INPUT STREAM ***\n", audio_stream->device_index);
            printf("[WARNING] *** Format test error: %s (code: %d) - Device is in use ***\n", Pa_GetErrorText(test_err), test_err);
            
            // Check if this device is being used by the input stream of the same channel
            if (audio_stream->input_stream != NULL) {
                printf("[DEBUG] *** TEMPORARILY CLOSING INPUT STREAM TO FREE DEVICE FOR OUTPUT ***\n");
                printf("[DEBUG] *** CLOSING INPUT STREAM FOR CHANNEL %d (device %d) IN REPAIR FUNCTION ***\n", 
                       channel_index, audio_stream->device_index);
                Pa_StopStream(audio_stream->input_stream);
                Pa_CloseStream(audio_stream->input_stream);
                audio_stream->input_stream = NULL;
                printf("[DEBUG] *** INPUT STREAM CLOSED AND SET TO NULL FOR CHANNEL %d IN REPAIR FUNCTION ***\n", channel_index);
                usleep(500000); // Wait 500ms for device to be fully released
                
                // Retry the format test
                test_err = Pa_IsFormatSupported(NULL, &output_params, 44100.0);
                if (test_err == paFormatIsSupported) {
                    printf("[DEBUG] Device %d supports 44100 Hz sample rate ✓ (after closing input stream)\n", audio_stream->device_index);
                } else {
                    printf("[ERROR] *** OUTPUT DEVICE %d STILL BUSY AFTER CLOSING INPUT STREAM! ***\n", output_params.device);
                    printf("[ERROR] *** Format test error: %s (code: %d) ***\n", Pa_GetErrorText(test_err), test_err);
                    return 0;
                }
            } else {
                printf("[ERROR] *** DEVICE %d IS BUSY BUT NO INPUT STREAM TO CLOSE! ***\n", audio_stream->device_index);
                return 0;
            }
            } else {
                printf("[ERROR] *** OUTPUT DEVICE %d DOES NOT SUPPORT 44100 Hz SAMPLE RATE! ***\n", output_params.device);
                printf("[ERROR] *** Format test error: %s (code: %d) ***\n", Pa_GetErrorText(test_err), test_err);
                return 0;
            }
        } else {
            printf("[DEBUG] Device %d supports 44100 Hz sample rate ✓\n", audio_stream->device_index);
        }
    } else {
        printf("[ERROR] *** CANNOT GET DEVICE INFO FOR DEVICE %d - DEVICE DOES NOT EXIST! ***\n", audio_stream->device_index);
        printf("[ERROR] *** This is a critical error - device %d is invalid! ***\n", audio_stream->device_index);
        return 0;
    }
    
    // Try different parameters with FORCED SAMPLE_RATE - balanced approach
    int buffer_sizes[] = {AUDIO_BUFFER_SIZE, 1024, 2048, 512, 256, 4096, 8192}; // Balanced approach
    PaSampleFormat sample_formats[] = { paFloat32, paInt16, paInt24, paInt32 };
    const char* sample_format_names[] = { "paFloat32", "paInt16", "paInt24", "paInt32" };
    double latencies[] = { Pa_GetDeviceInfo(output_params.device)->defaultLowOutputLatency,
                           Pa_GetDeviceInfo(output_params.device)->defaultHighOutputLatency };
    int channel_counts[] = { AUDIO_CHANNELS, 1 };
    
    // Always free the input stream if it's on the same device before opening output
    if (audio_stream->input_stream != NULL && audio_stream->device_index == output_params.device) {
        printf("[DEBUG] *** ALWAYS CLOSING INPUT STREAM BEFORE OUTPUT OPEN ON DEVICE %d ***\n", output_params.device);
        Pa_StopStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->input_stream);
        audio_stream->input_stream = NULL;
        usleep(500000); // allow ALSA to fully release device
    }
    
    printf("[DEBUG] *** STARTING STREAM CREATION LOOP FOR REPAIR ***\n");
    printf("[DEBUG] *** Device %d, Sample Rate: %d, Channels: %d ***\n", 
           output_params.device, FORCED_SAMPLE_RATE, output_params.channelCount);
    
    PaError err = paNoError;
    for (int sf = 0; sf < 4; sf++) {
        for (int cc = 0; cc < 2; cc++) {
            for (int lt = 0; lt < 2; lt++) {
                for (int j = 0; j < 7; j++) {
                    output_params.channelCount = channel_counts[cc];
                    output_params.sampleFormat = sample_formats[sf];
                    output_params.suggestedLatency = latencies[lt];
                    printf("[DEBUG] *** REPAIR TRY: fmt=%s, channels=%d, latency=%s, rate=%d, buffer=%d ***\n",
                           sample_format_names[sf], output_params.channelCount,
                           lt == 0 ? "low" : "high", FORCED_SAMPLE_RATE, buffer_sizes[j]);
        
        err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 
                           FORCED_SAMPLE_RATE, buffer_sizes[j], 
                           paClipOff, audio_output_callback, audio_stream);
        
        if (err == paNoError) {
                        printf("[DEBUG] *** SUCCESS! Repaired output stream with rate=%d, buffer=%d, fmt=%s, ch=%d, latency=%s ***\n",
                               FORCED_SAMPLE_RATE, buffer_sizes[j], sample_format_names[sf], output_params.channelCount,
                               lt == 0 ? "low" : "high");
            
                        PaError start_err = Pa_StartStream(audio_stream->output_stream);
                        if (start_err == paNoError) {
                printf("[DEBUG] *** PASSTHROUGH TARGET CHANNEL %d REPAIR COMPLETE! ***\n", channel_index);
                printf("[DEBUG] *** CHANNEL %d NOW HAS WORKING OUTPUT STREAM - PASSTHROUGH SHOULD WORK! ***\n", channel_index);
                printf("[DEBUG] *** AUDIO SHOULD NOW BE PLAYING ON CHANNEL %d OUTPUT! ***\n", channel_index);
                
                if (audio_stream->input_stream == NULL) {
                    printf("[DEBUG] *** RECREATING INPUT STREAM FOR CHANNEL %d AFTER REPAIR ***\n", channel_index);
                    PaStreamParameters input_params;
                    input_params.device = audio_stream->device_index;
                    input_params.channelCount = 1;
                    input_params.sampleFormat = paFloat32;
                    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
                    input_params.hostApiSpecificStreamInfo = NULL;
                    
                                int input_buffer = buffer_sizes[j] == 0 ? AUDIO_BUFFER_SIZE : buffer_sizes[j];
                                PaError in_err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL,
                                                               FORCED_SAMPLE_RATE, input_buffer,
                                       paClipOff, audio_input_callback, audio_stream);
                                if (in_err == paNoError) {
                                    in_err = Pa_StartStream(audio_stream->input_stream);
                                    if (in_err == paNoError) {
                                printf("[DEBUG] *** INPUT STREAM RECREATED SUCCESSFULLY FOR CHANNEL %d AFTER REPAIR ***\n", channel_index);
                                printf("[DEBUG] *** INPUT STREAM POINTER AFTER REPAIR RECREATION: %p ***\n", (void*)audio_stream->input_stream);
                            } else {
                                        printf("[ERROR] Failed to start recreated input stream after repair: %s\n", Pa_GetErrorText(in_err));
                            }
                        } else {
                                    printf("[ERROR] Failed to recreate input stream after repair: %s\n", Pa_GetErrorText(in_err));
                        }
                }
                
                            force_passthrough_reevaluation = 1;
                return 1;
            } else {
                            printf("[ERROR] Pa_StartStream failed after repair: %s\n", Pa_GetErrorText(start_err));
                Pa_CloseStream(audio_stream->output_stream);
                audio_stream->output_stream = NULL;
                            // continue trying
            }
        } else if (err == paDeviceUnavailable) {
            printf("[DEBUG] Device %d is busy - killing processes using it\n", output_params.device);
            kill_processes_using_audio_device(output_params.device);
                        usleep(500000);
                        // continue trying other combos
        } else if (err == paUnanticipatedHostError) {
            printf("[DEBUG] Device %d has hardware error - waiting and retrying\n", output_params.device);
                        usleep(1000000);
                        // continue
        } else {
            printf("[ERROR] Pa_OpenStream failed with error: %s (code: %d)\n", Pa_GetErrorText(err), err);
                        const PaHostErrorInfo* host_err = Pa_GetLastHostErrorInfo();
                        if (host_err) {
                            printf("[ERROR] Host error API: %d, Code: %ld, Text: %s\n", host_err->hostApiType, (long)host_err->errorCode, host_err->errorText ? host_err->errorText : "(null)");
                        }
                        printf("[ERROR] Device: %d, Rate: %d, Buffer: %d, Fmt: %s, Ch: %d, Latency: %s\n",
                               output_params.device, FORCED_SAMPLE_RATE, buffer_sizes[j], sample_format_names[sf], output_params.channelCount,
                               lt == 0 ? "low" : "high");
                        // continue
                    }
                }
            }
        }
    }
    
    // NO ALTERNATIVE DEVICES - Passthrough target must use its assigned device
    if (err != paNoError) {
        printf("[ERROR] *** FAILED TO CREATE OUTPUT STREAM ON ASSIGNED DEVICE %d ***\n", output_params.device);
        printf("[ERROR] *** Passthrough target MUST use its assigned device - no alternatives allowed ***\n");
    }
    
    printf("[ERROR] *** FAILED TO REPAIR PASSTHROUGH TARGET CHANNEL %d ***\n", channel_index);
    return 0;
}

// Find the best available channel for passthrough (one with working output stream)
int find_best_passthrough_channel(void) {
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    extern int global_channel_count;
    
    // Check if we need to force re-evaluation due to successful repair
    if (force_passthrough_reevaluation) {
        printf("[DEBUG] *** FORCING PASSTHROUGH RE-EVALUATION DUE TO SUCCESSFUL REPAIR ***\n");
        force_passthrough_reevaluation = 0; // Reset flag
    }
    
    // First try the configured passthrough target
    int configured_target = get_passthrough_target_channel_index();
    if (configured_target >= 0 && configured_target < global_channel_count) {
        if (channel_has_output_stream(configured_target)) {
            printf("[DEBUG] Configured passthrough target channel %d (%s) has working output stream\n", 
                   configured_target, global_channel_ids[configured_target]);
            return configured_target;
        } else {
            printf("[WARNING] Configured passthrough target channel %d (%s) has no working output stream - attempting repair\n", 
                   configured_target, global_channel_ids[configured_target]);
            
            // Try to repair the passthrough target channel
            if (repair_passthrough_output_stream(configured_target)) {
                printf("[DEBUG] *** PASSTHROUGH TARGET CHANNEL %d REPAIR SUCCESSFUL! ***\n", configured_target);
                printf("[DEBUG] *** FORCING PASSTHROUGH TO USE REPAIRED CHANNEL %d ***\n", configured_target);
                return configured_target;
            } else {
                printf("[ERROR] *** PASSTHROUGH TARGET CHANNEL %d REPAIR FAILED! ***\n", configured_target);
            }
        }
    }
    
    // CRITICAL: Channel 4 MUST be the passthrough target - no alternatives allowed
    return configured_target; // Return the configured target even if it's not working
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

// Global flag to force passthrough target re-evaluation
int force_passthrough_reevaluation = 0;

// Periodic repair attempt for passthrough target channels
static void periodic_passthrough_repair(void) {
    static int repair_attempt_count = 0;
    repair_attempt_count++;
    
    // Try to repair every 1000 calls (roughly every 10-20 seconds) - MUST SUCCEED
    if (repair_attempt_count % 1000 == 0) {
        int configured_target = get_passthrough_target_channel_index();
        if (configured_target >= 0) {
            if (!channel_has_output_stream(configured_target)) {
                printf("[DEBUG] *** PERIODIC REPAIR ATTEMPT #%d FOR PASSTHROUGH TARGET CHANNEL %d ***\n", 
                       repair_attempt_count / 1000, configured_target);
                printf("[CRITICAL] *** PASSTHROUGH TARGET MUST WORK - ATTEMPTING REPAIR ***\n");
                
                // Keep trying repair until success
                int repair_attempts = 0;
                while (!repair_passthrough_output_stream(configured_target)) {
                    repair_attempts++;
                    printf("[CRITICAL] *** REPAIR ATTEMPT #%d FAILED - RETRYING IN 2 SECONDS ***\n", repair_attempts);
                    sleep(2); // Wait 2 seconds before retry
                }
                
                printf("[DEBUG] *** PERIODIC REPAIR SUCCESSFUL AFTER %d ATTEMPTS - FORCING PASSTHROUGH RE-EVALUATION ***\n", repair_attempts + 1);
                force_passthrough_reevaluation = 1;
            }
        }
    }
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
    
    // Passthrough repair disabled in minimal pipeline
    
    // SIMPLIFIED: Directly check if this is Channel 4 (the configured passthrough target)
    // Channel 4 is always index 3 and has ID "channel_4"
    if (strcmp(channel_id, "channel_4") == 0) {
        return 1;
    }
    
    // Fallback to original logic
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
    
    // Restart PulseAudio to ensure it's working properly
    printf("[AUDIO INIT] Restarting PulseAudio...\n");
    system("pulseaudio --kill 2>/dev/null || true");
    usleep(200000); // 200ms
    system("pulseaudio --start 2>/dev/null || true");
    usleep(500000); // 500ms
    
    // Configure ALSA to ensure all USB audio devices are available
    printf("[AUDIO INIT] Configuring ALSA audio devices...\n");
    
    // CRITICAL: Remove ALSA loopback devices that cause hardware passthrough conflicts
    printf("[AUDIO INIT] Checking for and removing ALSA loopback devices...\n");
    
    // Check if loopback devices exist
    system("lsmod | grep snd-aloop && echo '[WARNING] ALSA loopback device detected - removing...' || echo '[INFO] No ALSA loopback device found'");
    system("lsmod | grep snd-dummy && echo '[WARNING] ALSA dummy device detected - removing...' || echo '[INFO] No ALSA dummy device found'");
    
    system("sudo modprobe -r snd-aloop 2>/dev/null || true");
    system("sudo modprobe -r snd-dummy 2>/dev/null || true");
    usleep(200000); // 200ms
    
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
                
                // Configure the card for both input and output
                printf("[AUDIO INIT] Configuring card %d for input/output...\n", card);
                
                // Test input capability
                snprintf(cmd, sizeof(cmd), 
                    "arecord -D hw:%d,0 -f S16_LE -r 48000 -c 1 -d 1 /dev/null 2>&1 | head -1", card);
                FILE *test_fp = popen(cmd, "r");
                if (test_fp) {
                    char result[256];
                    if (fgets(result, sizeof(result), test_fp)) {
                        printf("[AUDIO INIT] Card %d input test: %s", card, result);
                    }
                    pclose(test_fp);
                }
                
                // Test output capability
                snprintf(cmd, sizeof(cmd), 
                    "aplay -D hw:%d,0 -f S16_LE -r 48000 -c 1 /dev/zero 2>&1 | head -1", card);
                test_fp = popen(cmd, "r");
                if (test_fp) {
                    char result[256];
                    if (fgets(result, sizeof(result), test_fp)) {
                        printf("[AUDIO INIT] Card %d output test: %s", card, result);
                    }
                    pclose(test_fp);
                }
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
    if (callback_count++ % 1000 == 0) {  // More frequent logging - about every 3 seconds
        printf("Audio input callback called #%d (frames=%lu, transmitting=%d, gpio_active=%d)\n", 
               callback_count, frames, audio_stream->transmitting, audio_stream->gpio_active);
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
    if (audio_processing_count++ % 1000 == 0) {  // More frequent logging - about every 3 seconds
        printf("Audio processing for channel %s (frames=%lu, input_enabled=%d)\n", 
               audio_stream->channel_id, frames, input_enabled);
    }
    
    const float *samples = (const float*)input;
    
    // Update shared buffer strictly from the source input (channel_one) for passthrough
    int should_update_shared_buffer = 0;
    extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
    if (is_tone_detect_enabled() && strcmp(audio_stream->channel_id, global_channel_ids[0]) == 0) {
        // Only feed passthrough buffers when passthrough mode is active
        should_update_shared_buffer = is_passthrough_mode();
    }
    
    if (should_update_shared_buffer) {
        // Debug: Track buffer updates
        static int buffer_update_count = 0;
        if (buffer_update_count++ % 1000 == 0) {
            printf("[DEBUG] Input buffer update #%d: frames=%lu, passthrough_mode=%d\n", 
                   buffer_update_count, frames, is_passthrough_mode());
        }
        
        // COMPLETELY CLEAN PASSTHROUGH - NO PROCESSING AT ALL
        // Direct copy of raw input samples to preserve original audio quality
        
        // Update shared buffer with raw samples - use actual frame size
        pthread_mutex_lock(&global_shared_buffer.mutex);
        // Clear only the portion we'll use
        for (unsigned long i = 0; i < frames && i < SAMPLES_PER_FRAME; i++) {
            global_shared_buffer.samples[i] = samples[i]; // Raw copy - no processing
        }
        // Clear any unused portion to prevent noise
        for (unsigned long i = frames; i < SAMPLES_PER_FRAME; i++) {
            global_shared_buffer.samples[i] = 0.0f;
        }
        global_shared_buffer.sample_count = frames;
        global_shared_buffer.valid = 1;
        pthread_cond_signal(&global_shared_buffer.data_ready);
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        // Update passthrough buffer with raw samples - use actual frame size
        pthread_mutex_lock(&global_passthrough_buffer.mutex);
        // Copy only the actual frame data
        for (unsigned long i = 0; i < frames && i < SAMPLES_PER_FRAME; i++) {
            global_passthrough_buffer.samples[i] = samples[i]; // Raw copy - no processing
        }
        // Clear any unused portion to prevent noise
        for (unsigned long i = frames; i < SAMPLES_PER_FRAME; i++) {
            global_passthrough_buffer.samples[i] = 0.0f;
        }
        global_passthrough_buffer.sample_count = frames;
        global_passthrough_buffer.valid = 1;
        pthread_mutex_unlock(&global_passthrough_buffer.mutex);
        
        // No debug logging to avoid timing issues
    } else {
        // When passthrough is not active, mark buffers invalid to avoid stale audio
        pthread_mutex_lock(&global_passthrough_buffer.mutex);
        global_passthrough_buffer.valid = 0;
        global_passthrough_buffer.sample_count = 0;
        pthread_mutex_unlock(&global_passthrough_buffer.mutex);
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
    if (callback_count++ % 100000 == 0) {  // Even less frequent logging - about every 30 seconds
        printf("Audio output callback called for channel %s (frames=%lu, buffer_count=%d)\n", 
               audio_stream->channel_id, frames, jitter->frame_count);
    }
    
    // Check if this channel is the configured passthrough target
    int is_configured_target = is_configured_passthrough_channel_id(audio_stream->channel_id);
    int passthrough_mode = is_configured_target ? is_passthrough_mode() : 0;
    
    // Debug: Track passthrough mode changes
    static int last_passthrough_mode = -1;
    if (passthrough_mode != last_passthrough_mode) {
        printf("[DEBUG] Passthrough mode changed: %s (channel: %s, is_target: %d)\n", 
               passthrough_mode ? "ACTIVE" : "INACTIVE", audio_stream->channel_id, is_configured_target);
        last_passthrough_mode = passthrough_mode;
    }

    // Persisted state for passthrough processing and reliable reset on mode changes
    static float pt_dc_offset = 0.0f;
    static int pt_was_passthrough = 0;
    
    if (passthrough_mode) {
        if (!pt_was_passthrough) {
            pt_dc_offset = 0.0f;
        }
        pt_was_passthrough = 1;
        
        // RESTORED: Software passthrough is working correctly
        // The hardware passthrough was causing the noise conflict
        
        // Configured passthrough target in passthrough mode - play audio from dedicated passthrough buffer
        pthread_mutex_lock(&global_passthrough_buffer.mutex);
        if (global_passthrough_buffer.valid && global_passthrough_buffer.sample_count > 0) {
            // COMPLETELY CLEAN PASSTHROUGH OUTPUT - NO PROCESSING AT ALL
            unsigned long samples_to_process = global_passthrough_buffer.sample_count;
            if (samples_to_process > frames) samples_to_process = frames;
            
            // Get device info to determine output channel count
            const PaDeviceInfo* device_info = Pa_GetDeviceInfo(audio_stream->device_index);
            int output_channels = (device_info && device_info->maxOutputChannels >= 2) ? 2 : 1;
            
            // ABSOLUTELY MINIMAL PASSTHROUGH - NO CACHING, NO LOOPING, NO EXTRA LOGIC
            for (unsigned long i = 0; i < samples_to_process; i++) {
                float sample = global_passthrough_buffer.samples[i]; // raw sample - no processing at all
                
                // Duplicate mono to both stereo channels or write mono
                if (output_channels >= 2) {
                    out[i * 2] = sample;     // Left channel
                    out[i * 2 + 1] = sample; // Right channel
                } else {
                    out[i] = sample; // Mono output
                }
            }
            
            // Fill any remainder with silence - no fancy logic
            for (unsigned long i = samples_to_process; i < frames; i++) {
                if (output_channels >= 2) {
                    out[i * 2] = 0.0f;     // Left channel
                    out[i * 2 + 1] = 0.0f; // Right channel
                } else {
                    out[i] = 0.0f; // Mono output
                }
            }
            
            // Keep buffer valid for smooth playback - don't invalidate to prevent choppy noise
            // The buffer will be overwritten by new audio data from input callback
        } else {
            // No audio data - fill with silence (no caching logic)
            const PaDeviceInfo* device_info = Pa_GetDeviceInfo(audio_stream->device_index);
            int output_channels = (device_info && device_info->maxOutputChannels >= 2) ? 2 : 1;
            
            for (unsigned long i = 0; i < frames; i++) {
                if (output_channels >= 2) {
                    out[i * 2] = 0.0f;     // Left channel
                    out[i * 2 + 1] = 0.0f; // Right channel
                } else {
                    out[i] = 0.0f; // Mono output
                }
            }
            
            // No debug logging to avoid timing issues
        }
        pthread_mutex_unlock(&global_passthrough_buffer.mutex);
        return paContinue;
    } else {
        // Leaving passthrough mode – ensure next entry resets smoothing state
        pt_was_passthrough = 0;
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
    
    printf("[INFO] Audio passthrough thread started - COMPLETELY DISABLED\n");
    
    // COMPLETELY DISABLED: This thread conflicts with callback-based passthrough
    // Just sleep forever to prevent any interference
    while (global_passthrough.active && !global_interrupted) {
        usleep(1000000); // 1 second delay - thread is completely disabled
        // No processing whatsoever to prevent audio conflicts
    }
    
    printf("[INFO] Audio passthrough thread stopped\n");
    return NULL;
}

// Initialize shared audio buffer
int init_shared_audio_buffer(void) {
    memset(&global_shared_buffer, 0, sizeof(struct shared_audio_buffer));
    pthread_mutex_init(&global_shared_buffer.mutex, NULL);
    pthread_cond_init(&global_shared_buffer.data_ready, NULL);
    
    // Explicitly zero out all sample data to prevent noise
    for (int i = 0; i < SAMPLES_PER_FRAME; i++) {
        global_shared_buffer.samples[i] = 0.0f;
    }
    global_shared_buffer.sample_count = 0;
    global_shared_buffer.valid = 0;
    printf("[INFO] Shared audio buffer initialized and zeroed\n");
    
    // Initialize dedicated passthrough buffer
    memset(&global_passthrough_buffer, 0, sizeof(struct passthrough_audio_buffer));
    pthread_mutex_init(&global_passthrough_buffer.mutex, NULL);
    
    // Explicitly zero out all sample data to prevent noise
    for (int i = 0; i < SAMPLES_PER_FRAME; i++) {
        global_passthrough_buffer.samples[i] = 0.0f;
    }
    global_passthrough_buffer.sample_count = 0;
    global_passthrough_buffer.valid = 0;
    printf("[INFO] Passthrough audio buffer initialized and zeroed\n");
    
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
    
    // Setup buffers - balanced size to prevent underruns without excessive latency
    audio_stream->buffer_size = 2400;  // Balanced buffer size
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
    
    // Force consistent audio parameters for all channels - balanced buffers
    const int AUDIO_BUFFER_SIZE = 1024; // Balanced: prevents underruns without excessive latency
    const int AUDIO_CHANNELS = 1;
    
    // No channel is hard-reserved for passthrough; selection is driven by JSON.
    
    // Setup input stream for other channels
    input_params.device = audio_stream->device_index;
    if (input_params.device == paNoDevice) {
        fprintf(stderr, "No input device for channel %s\n", audio_stream->channel_id);
        return 0;
    }
    
    input_params.channelCount = AUDIO_CHANNELS;
    input_params.sampleFormat = paFloat32;
    input_params.suggestedLatency = Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;
    input_params.hostApiSpecificStreamInfo = NULL;
    
    printf("[DEBUG] About to call Pa_OpenStream for input stream...\n");
    // Use consistent sample rate and smaller buffer for lower latency
    PaError err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, SAMPLE_RATE, AUDIO_BUFFER_SIZE, 
                                paClipOff, audio_input_callback, audio_stream);
    printf("[DEBUG] Pa_OpenStream for input stream returned: %s\n", Pa_GetErrorText(err));
    
    if (err != paNoError) {
        printf("WARNING: USB device %d failed for channel %s: %s\n", 
               audio_stream->device_index, audio_stream->channel_id, Pa_GetErrorText(err));
        fflush(stdout);
        
        // Try different parameters for the same USB device first
        printf("[DEBUG] Retrying USB device %d with different parameters...\n", audio_stream->device_index);
        
        // Try different sample rates - prioritize 48000 for consistency
        int sample_rates[] = {SAMPLE_RATE, 44100, 96000};
        int buffer_sizes[] = {AUDIO_BUFFER_SIZE, 1024, 2048};
        
        for (int i = 0; i < 3 && err != paNoError; i++) {
            for (int j = 0; j < 3 && err != paNoError; j++) {
                printf("[DEBUG] Trying device %d with sample_rate=%d, buffer_size=%d\n", 
                       audio_stream->device_index, sample_rates[i], buffer_sizes[j]);
                err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, 
                                   sample_rates[i], buffer_sizes[j], paClipOff, audio_input_callback, audio_stream);
                if (err == paNoError) {
                    printf("[DEBUG] Device %d succeeded with sample_rate=%d, buffer_size=%d\n", 
                           audio_stream->device_index, sample_rates[i], buffer_sizes[j]);
                    break;
                }
            }
        }
        
        // If USB device still fails, try other USB devices
        if (err != paNoError) {
            printf("[DEBUG] USB device %d failed with all parameters, trying other USB devices...\n", 
                   audio_stream->device_index);
            
            for (int i = 0; i < MAX_CHANNELS && err != paNoError; i++) {
                if (usb_devices[i] != audio_stream->device_index && usb_devices[i] != paNoDevice) {
                    input_params.device = usb_devices[i];
                    input_params.suggestedLatency = Pa_GetDeviceInfo(usb_devices[i])->defaultLowInputLatency;
                    
                    printf("[DEBUG] Trying alternative USB device %d for channel %s\n", 
                           usb_devices[i], audio_stream->channel_id);
                    err = Pa_OpenStream(&audio_stream->input_stream, &input_params, NULL, SAMPLE_RATE, AUDIO_BUFFER_SIZE, 
                                        paClipOff, audio_input_callback, audio_stream);
                    
                    if (err == paNoError) {
                        printf("Successfully opened input stream on USB device %d for channel %s\n", 
                               usb_devices[i], audio_stream->channel_id);
                        audio_stream->device_index = usb_devices[i];
                        break;
                    } else {
                        printf("[DEBUG] Alternative USB device %d also failed: %s\n", 
                               usb_devices[i], Pa_GetErrorText(err));
                    }
                }
            }
        }
        
        // If all USB devices fail, try default device as last resort
        if (err != paNoError) {
            printf("[ERROR] All ALSA USB devices failed for channel %s; aborting setup to avoid PulseAudio fallback.\n", audio_stream->channel_id);
            return 0;
        }
    }
    
    // Create output stream for audio playback
    printf("[DEBUG] Creating output stream for channel %s...\n", audio_stream->channel_id);
    fflush(stdout);
    
    // Check if this is a passthrough target channel - give it priority treatment
    int is_passthrough_target = is_configured_passthrough_channel_id(audio_stream->channel_id);
    
    // SPECIAL HANDLING: Skip passthrough target output stream creation initially to avoid conflicts
    if (is_passthrough_target) {
        printf("[DEBUG] *** SKIPPING PASSTHROUGH TARGET OUTPUT STREAM CREATION - WILL CREATE LATER ***\n");
        printf("[DEBUG] *** Passthrough target input stream created successfully, output will be created after other channels ***\n");
        
        // Start only the input stream for now
        err = Pa_StartStream(audio_stream->input_stream);
        if (err != paNoError) {
            printf("[ERROR] Failed to start input stream for channel %s: %s\n", 
                   audio_stream->channel_id, Pa_GetErrorText(err));
            return 0;
        }
        
        printf("[DEBUG] Input stream started successfully for channel %s\n", audio_stream->channel_id);
        printf("[DEBUG] Input stream is active for channel %s\n", audio_stream->channel_id);
        printf("[DEBUG] Stream status check for channel %s:\n", audio_stream->channel_id);
        printf("[DEBUG] - Pa_IsStreamActive(input): %s\n", Pa_IsStreamActive(audio_stream->input_stream) ? "YES" : "NO");
        printf("[DEBUG] - Pa_IsStreamStopped(input): %s\n", Pa_IsStreamStopped(audio_stream->input_stream) ? "YES" : "NO");
        printf("[DEBUG] - Input latency: %.3f ms\n", Pa_GetStreamInfo(audio_stream->input_stream)->inputLatency * 1000.0);
        printf("[DEBUG] - Sample rate: %.1f Hz\n", Pa_GetStreamInfo(audio_stream->input_stream)->sampleRate);
        printf("[DEBUG] Output stream will be created later for channel %s\n", audio_stream->channel_id);
        printf("Audio transmission started for channel %s (input only - output delayed)\n", audio_stream->channel_id);
        printf("Audio transmission started for channel %s (input only - output delayed)\n", audio_stream->channel_id);
        printf("Audio transmission ready for channel %s (waiting for GPIO activation)\n", audio_stream->channel_id);
        
        return 1; // Success - input stream created, output will be created later
    }
    
    // Initialize output parameters with consistent settings
    output_params.channelCount = AUDIO_CHANNELS;
    output_params.sampleFormat = paFloat32;
    output_params.hostApiSpecificStreamInfo = NULL;
    
    // Try to use the same device as input for output (if it supports output)
    const PaDeviceInfo* input_device_info = Pa_GetDeviceInfo(audio_stream->device_index);
    if (input_device_info && input_device_info->maxOutputChannels > 0) {
    output_params.device = audio_stream->device_index;
        output_params.suggestedLatency = input_device_info->defaultLowOutputLatency;
        printf("[DEBUG] Using same device %d for both input and output for channel %s\n", 
               audio_stream->device_index, audio_stream->channel_id);
    } else {
        // Find a dedicated output device for this channel
        printf("[DEBUG] Input device %d doesn't support output, finding dedicated output device...\n", 
               audio_stream->device_index);
        
        // Try to use a different USB device for output
        int output_device_found = 0;
        for (int i = 0; i < MAX_CHANNELS; i++) {
            if (usb_devices[i] != paNoDevice && usb_devices[i] != audio_stream->device_index) {
                const PaDeviceInfo* device_info = Pa_GetDeviceInfo(usb_devices[i]);
                if (device_info && device_info->maxOutputChannels > 0) {
                    output_params.device = usb_devices[i];
                    output_params.suggestedLatency = device_info->defaultLowOutputLatency;
                    printf("[DEBUG] Using USB device %d for output for channel %s\n", 
                           usb_devices[i], audio_stream->channel_id);
                    output_device_found = 1;
                    break;
                }
            }
        }
        
        if (!output_device_found) {
            // Fall back to default output device
            PaDeviceIndex default_output_device = Pa_GetDefaultOutputDevice();
            if (default_output_device != paNoDevice) {
                output_params.device = default_output_device;
                output_params.suggestedLatency = Pa_GetDeviceInfo(default_output_device)->defaultLowOutputLatency;
                printf("[DEBUG] Using default output device %d for channel %s\n", 
                       default_output_device, audio_stream->channel_id);
            } else {
                printf("[DEBUG] No output device available for channel %s\n", audio_stream->channel_id);
                audio_stream->output_stream = NULL;
                err = paNoError;  // Continue with input-only mode
            }
        }
    }
    
    if (audio_stream->output_stream == NULL) {  // Only try to create if not already set to NULL
    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
                        paClipOff, audio_output_callback, audio_stream);
        
        if (err != paNoError) {
            printf("[DEBUG] Output stream creation failed for channel %s: %s\n", 
                   audio_stream->channel_id, Pa_GetErrorText(err));
            printf("WARNING: Output device %d failed for channel %s, trying different parameters\n", 
                   output_params.device, audio_stream->channel_id);
            fflush(stdout);
            
            // Try different parameters for output - prioritize 48000 for consistency
            int sample_rates[] = {SAMPLE_RATE, 44100, 96000};
            int buffer_sizes[] = {AUDIO_BUFFER_SIZE, 1024, 2048};
            int channel_counts[] = {AUDIO_CHANNELS, 2};
            
            for (int i = 0; i < 3 && err != paNoError; i++) {
                for (int j = 0; j < 3 && err != paNoError; j++) {
                    for (int k = 0; k < 2 && err != paNoError; k++) {
                        output_params.channelCount = channel_counts[k];
                        printf("[DEBUG] Trying output device %d with sample_rate=%d, buffer_size=%d, channels=%d\n", 
                               output_params.device, sample_rates[i], buffer_sizes[j], channel_counts[k]);
                        err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 
                                           sample_rates[i], buffer_sizes[j], paClipOff, audio_output_callback, audio_stream);
                        if (err == paNoError) {
                            printf("[DEBUG] Output device %d succeeded with sample_rate=%d, buffer_size=%d, channels=%d\n", 
                                   output_params.device, sample_rates[i], buffer_sizes[j], channel_counts[k]);
                            break;
                        }
                    }
                }
            }
            
            if (err != paNoError) {
                printf("[DEBUG] Output device %d failed with all parameters: %s\n", 
                       output_params.device, Pa_GetErrorText(err));
                
                // CRITICAL: Passthrough target channels CANNOT be input-only
                if (is_passthrough_target) {
                    printf("[ERROR] *** CRITICAL ERROR: PASSTHROUGH TARGET CHANNEL %s HAS NO OUTPUT STREAM! ***\n", audio_stream->channel_id);
                    printf("[ERROR] Tone passthrough will NOT work without an output stream on this channel!\n");
                    printf("[ERROR] This is a configuration error - passthrough target must have working output.\n");
                    // Don't set to NULL - keep trying to create output stream
                } else {
                    printf("[DEBUG] Continuing with input-only mode for channel %s\n", audio_stream->channel_id);
                    audio_stream->output_stream = NULL;  // No output stream
                    err = paNoError;  // Continue with input-only mode
                }
            }
        } else {
            printf("[DEBUG] Output stream created successfully for channel %s on device %d\n", 
                   audio_stream->channel_id, output_params.device);
        }
    }
    
    if (err != paNoError) {
        printf("[DEBUG] Output stream creation failed, continuing with input-only mode\n");
    } else {
        printf("[DEBUG] Output stream created successfully, proceeding to start streams\n");
    }

    if (err != paNoError) {
        fprintf(stderr, "PortAudio output stream error: %s\n", Pa_GetErrorText(err));
        printf("[DEBUG] Failed to create output stream for channel %s\n", audio_stream->channel_id);
        
        // Try alternative approaches for devices that fail with standard parameters
        printf("[DEBUG] Device %d failed, trying alternative parameters\n", output_params.device);
        
        // Try with different buffer sizes and sample rates - prioritize 48000
        int buffer_sizes[] = {AUDIO_BUFFER_SIZE, 256, 1024, 2048};
        int sample_rates[] = {SAMPLE_RATE, 44100, 22050};
        
        // Special handling for passthrough target channels - FORCE 44100 Hz ONLY
        if (is_passthrough_target) {
            printf("[DEBUG] *** CRITICAL: PASSTHROUGH TARGET CHANNEL FAILED - FORCING 44100 Hz ***\n");
            
            // FORCE SAMPLE_RATE (48000) Hz sample rate only - no alternatives
            const int FORCED_SAMPLE_RATE = SAMPLE_RATE;
            int passthrough_buffer_sizes[] = {AUDIO_BUFFER_SIZE, 1024, 2048, 512, 4096, 8192}; // Balanced approach
            
            // Try with FORCED 44100 Hz sample rate
            for (int j = 0; j < 6 && err != paNoError; j++) {
                printf("[DEBUG] Trying passthrough device %d with FORCED sample_rate=%d, buffer_size=%d\n", 
                       output_params.device, FORCED_SAMPLE_RATE, passthrough_buffer_sizes[j]);
                err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, 
                                   FORCED_SAMPLE_RATE, passthrough_buffer_sizes[j], 
                                   paClipOff, audio_output_callback, audio_stream);
                if (err == paNoError) {
                    printf("[DEBUG] Passthrough device %d succeeded with FORCED sample_rate=%d, buffer_size=%d\n", 
                           output_params.device, FORCED_SAMPLE_RATE, passthrough_buffer_sizes[j]);
                    break;
                } else if (err == paDeviceUnavailable) {
                    // Device is busy - kill processes using it
                    printf("[DEBUG] Passthrough device %d is busy - killing processes using it\n", output_params.device);
                    kill_processes_using_audio_device(output_params.device);
                    usleep(500000); // Wait 500ms for processes to fully terminate
                    err = paNoError; // Try again after killing processes
                } else if (err == paUnanticipatedHostError) {
                    // Device has hardware issues - wait longer and try again
                    printf("[DEBUG] Passthrough device %d has hardware error - waiting and retrying\n", output_params.device);
                    usleep(1000000); // Wait 1 second for hardware to stabilize
                    err = paNoError; // Try again
                }
            }
            
            // NO ALTERNATIVE DEVICES - Passthrough target must use its assigned device
            if (err != paNoError) {
                printf("[ERROR] *** FAILED TO CREATE PASSTHROUGH OUTPUT STREAM ON ASSIGNED DEVICE %d ***\n", output_params.device);
                printf("[ERROR] *** Passthrough target MUST use its assigned device - no alternatives allowed ***\n");
                printf("[CRITICAL] *** PASSTHROUGH TARGET MUST WORK - WILL BE RETRIED LATER ***\n");
            }
        }
        
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
            err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
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
                err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
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
                    
                    err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
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
                        
                        err = Pa_OpenStream(&audio_stream->output_stream, NULL, &output_params, SAMPLE_RATE, AUDIO_BUFFER_SIZE,
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
    
    // Start input stream (output stream is skipped for now)
    printf("[DEBUG] Starting input stream for channel %s...\n", audio_stream->channel_id);
    fflush(stdout);
    
    err = Pa_StartStream(audio_stream->input_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio input start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        return 0;
    }
    printf("[DEBUG] Input stream started successfully for channel %s\n", audio_stream->channel_id);
    fflush(stdout);
    
    // Skip output stream for now - focus on getting tone detection working
    if (audio_stream->output_stream) {
        printf("[DEBUG] Starting output stream for channel %s...\n", audio_stream->channel_id);
        fflush(stdout);
    
    err = Pa_StartStream(audio_stream->output_stream);
    if (err != paNoError) {
        fprintf(stderr, "PortAudio output start error: %s\n", Pa_GetErrorText(err));
        Pa_CloseStream(audio_stream->input_stream);
        Pa_CloseStream(audio_stream->output_stream);
        return 0;
        }
        printf("[DEBUG] Output stream started successfully for channel %s\n", audio_stream->channel_id);
        fflush(stdout);
    } else {
        printf("[DEBUG] No output stream to start for channel %s (input-only mode)\n", audio_stream->channel_id);
        fflush(stdout);
    }
    
    // Check if streams are actually running
    if (Pa_IsStreamActive(audio_stream->input_stream)) {
        printf("Input stream is active for channel %s\n", audio_stream->channel_id);
    } else {
        printf("WARNING: Input stream is NOT active for channel %s\n", audio_stream->channel_id);
    }
    
    // Additional debugging for stream status
    printf("[DEBUG] Stream status check for channel %s:\n", audio_stream->channel_id);
    printf("[DEBUG] - Pa_IsStreamActive(input): %s\n", Pa_IsStreamActive(audio_stream->input_stream) ? "YES" : "NO");
    printf("[DEBUG] - Pa_IsStreamStopped(input): %s\n", Pa_IsStreamStopped(audio_stream->input_stream) ? "YES" : "NO");
    
    // Check stream info
    const PaStreamInfo* stream_info = Pa_GetStreamInfo(audio_stream->input_stream);
    if (stream_info) {
        printf("[DEBUG] - Input latency: %.3f ms\n", stream_info->inputLatency * 1000.0);
        printf("[DEBUG] - Sample rate: %.1f Hz\n", stream_info->sampleRate);
    }
    
    if (audio_stream->output_stream) {
    if (Pa_IsStreamActive(audio_stream->output_stream)) {
        printf("Output stream is active for channel %s\n", audio_stream->channel_id);
    } else {
        printf("WARNING: Output stream is NOT active for channel %s\n", audio_stream->channel_id);
        }
    } else {
        printf("No output stream for channel %s (input-only mode)\n", audio_stream->channel_id);
    }
    
    if (audio_stream->output_stream) {
        printf("Audio transmission started for channel %s (input + output)\n", audio_stream->channel_id);
    } else {
        printf("Audio transmission started for channel %s (input-only mode)\n", audio_stream->channel_id);
    }
    
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
    printf("[TONE PASSTHROUGH] DISABLED - using software passthrough instead to prevent audio conflicts\n");
    return 1; // Success but disabled
    
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