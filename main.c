#include "echostream.h"
#include "audio.h"
#include "websocket.h"
#include "gpio.h"
#include "udp.h"
#include "config.h"
#include "crypto.h"

// Global state
volatile int global_interrupted = 0;
char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN] = {0};
int global_channel_count = 0;

static void handle_interrupt(int sig) {
    (void)sig; // Suppress unused parameter warning
    printf("\nShutdown signal received, cleaning up...\n");
    global_interrupted = 1;
    
    // Cleanup audio devices immediately on interrupt
    cleanup_audio_devices();
    
    // Close the single WebSocket connection
    if (global_ws_client) {
        // Don't call lws_close_reason() - let the context destruction handle it
        global_ws_client = NULL;
    }
    
    for (int i = 0; i < 4; i++) {
        if (channels[i].active) {
            channels[i].audio.transmitting = 0;
            
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
    }
    
    if (global_udp_socket >= 0) {
        close(global_udp_socket);
        global_udp_socket = -1;
    }
    
    // Stop audio passthrough
    stop_audio_passthrough();
    
    // Stop tone detection
    stop_tone_detection();
}

int main(int argc, char *argv[]) {
    (void)argc; // Suppress unused parameter warning
    (void)argv; // Suppress unused parameter warning
    // Initialize global variables
    global_interrupted = 0;
    
    // Load channel configuration from JSON file
    printf("Loading channel configuration from /home/will/.an/config.json...\n");
    global_channel_count = load_channel_config(global_channel_ids);
    if (global_channel_count > 0) {
        printf("Successfully loaded %d channels from config\n", global_channel_count);
    } else {
        printf("No channels loaded from config, using generic defaults\n");
        // Set generic default channels if config loading fails
        for (int i = 0; i < 4; i++) {
            snprintf(global_channel_ids[i], CHANNEL_ID_LEN, "channel_%d", i + 1);
        }
        global_channel_count = 4;
    }
    
    // Load complete configuration including tone detection settings
    printf("[MAIN] Loading complete configuration from /home/will/.an/config.json...\n");
    if (load_complete_config()) {
        printf("[MAIN] Complete configuration loaded successfully\n");
    } else {
        printf("[MAIN] ERROR: Failed to load JSON config - NO TONE DETECTION AVAILABLE\n");
        printf("[MAIN] Please check /home/will/.an/config.json file exists and is readable\n");
        return 1;  // Exit if config cannot be loaded
    }
    
    if (!initialize_portaudio()) {
        fprintf(stderr, "PortAudio initialization failed\n");
        return 1;
    }
    
    // Initialize audio devices and kill interfering processes
    if (!initialize_audio_devices()) {
        fprintf(stderr, "Audio device initialization failed\n");
        return 1;
    }
    
    // Initialize tone detection control
    if (!init_tone_detect_control()) {
        fprintf(stderr, "Failed to initialize tone detection control\n");
        return 1;
    }
    
    // Initialize tone passthrough control
    if (!init_tone_passthrough_control()) {
        fprintf(stderr, "Failed to initialize tone passthrough control\n");
        return 1;
    }
    
    // Initialize tone detection system
    if (!init_tone_detection()) {
        fprintf(stderr, "Failed to initialize tone detection system\n");
        return 1;
    }
    
    // Initialize shared audio buffer and passthrough
    if (!init_shared_audio_buffer()) {
        fprintf(stderr, "Failed to initialize shared audio buffer\n");
        return 1;
    }
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    signal(SIGINT, handle_interrupt);
    
    pthread_t gpio_thread;
    if (pthread_create(&gpio_thread, NULL, gpio_monitor_worker, NULL)) {
        fprintf(stderr, "Failed to create GPIO monitor thread\n");
        curl_global_cleanup();
        return 1;
    }
    
    // UDP configuration will be received via WebSocket
    // UDP listener thread will be started after UDP connection is established
    
    printf("Setting up %d channels...\n", global_channel_count);
    
    for (int i = 0; i < global_channel_count; i++) {
        printf("Setting up channel %d with ID: %s\n", i + 1, global_channel_ids[i]);
        if (!setup_channel(&channels[i], global_channel_ids[i])) {
            fprintf(stderr, "Failed to setup channel %d (%s)\n", i + 1, global_channel_ids[i]);
            curl_global_cleanup();
            return 1;
        }
    }
    
    // Initialize audio passthrough (but don't start yet - need devices assigned first)
    if (!init_audio_passthrough()) {
        fprintf(stderr, "Failed to initialize audio passthrough\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Connect global WebSocket for all channels
    if (!connect_global_websocket()) {
        fprintf(stderr, "Failed to connect WebSocket\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Start audio passthrough after WebSocket is connected and channels are set up
    if (!start_audio_passthrough()) {
        fprintf(stderr, "Failed to start audio passthrough\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Start tone detection system
    if (!start_tone_detection()) {
        fprintf(stderr, "Failed to start tone detection\n");
        curl_global_cleanup();
        return 1;
    }
    
    pthread_t ws_thread;
    if (pthread_create(&ws_thread, NULL, global_websocket_thread, NULL)) {
        fprintf(stderr, "Failed to create WebSocket thread\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Tone definitions and filters are now loaded from JSON configuration in ~/.an/config.json
    // No hardcoded test tones needed
    
    printf("All %d channels running with single WebSocket. Press Ctrl+C to stop.\n", global_channel_count);
    
    // Wait for channel initialization to complete before creating passthrough target output stream
    printf("\n=== WAITING FOR CHANNEL INITIALIZATION TO COMPLETE ===\n");
    printf("[INFO] Waiting 5 seconds for all channels to be initialized...\n");
    sleep(5);
    printf("\n=== PASSTHROUGH OUTPUT INITIALIZATION ===\n");
    if (create_delayed_passthrough_output_stream()) {
        printf("[INFO] Passthrough target output stream ready\n");
    } else {
        printf("[WARNING] Passthrough target output stream not available (will operate without passthrough)\n");
    }
    
    printf("\n=== SYSTEM BEHAVIOR ===\n");
    printf("Channel Configuration:\n");
    for (int i = 0; i < global_channel_count; i++) {
        printf("  Channel %d (%s):\n", i + 1, global_channel_ids[i]);
        printf("    - Output: ALWAYS plays EchoStream audio (unaffected by tone detection)\n");
        
        // Check if this channel has tone detection enabled
        int has_tone_detect = 0;
        for (int j = 0; j < MAX_CHANNELS; j++) {
            struct channel_config* channel_config = get_channel_config(j);
            if (channel_config && channel_config->valid && 
                strcmp(channel_config->channel_id, global_channel_ids[i]) == 0) {
                has_tone_detect = channel_config->tone_detect;
                break;
            }
        }
        
        if (has_tone_detect) {
            printf("    - Input: %s (for tone detection and passthrough)\n", 
                   is_card1_input_enabled() ? "ENABLED" : "DISABLED");
        } else {
            printf("    - Input: ENABLED (no tone detection)\n");
        }
    }
    // Reflect configured passthrough channel from JSON
    struct tone_detect_config* __tdcfg = get_tone_detect_config(0);
    if (__tdcfg && __tdcfg->tone_passthrough) {
        const char* pt = __tdcfg->passthrough_channel;
        printf("Passthrough output target: %s\n", pt);
    }
    printf("\nTone detection control available:\n");
    printf("  - Call enable_tone_detection() to enable tone detect mode\n");
    printf("  - Call disable_tone_detection() to disable tone detect mode\n");
    printf("  - Current mode: %s\n", is_tone_detect_enabled() ? "ENABLED" : "DISABLED");
    // Remove stale example tones output; tones are from JSON only
    
    // Wait for the WebSocket thread to complete
    pthread_join(ws_thread, NULL);
    
    // Cleanup
    stop_tone_detection();
    stop_tone_passthrough();
    stop_audio_passthrough();
    cleanup_audio_devices();  // Restore audio devices to normal state
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}