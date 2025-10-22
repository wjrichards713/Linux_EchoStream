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
    
    // Load complete configuration
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
    
    // Initialize shared audio buffer
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
        // Only set up channels with valid (non-empty) IDs
        if (global_channel_ids[i][0] != '\0') {
            printf("Setting up channel %d with ID: %s\n", i + 1, global_channel_ids[i]);
            if (!setup_channel(&channels[i], global_channel_ids[i])) {
                fprintf(stderr, "Failed to setup channel %d (%s)\n", i + 1, global_channel_ids[i]);
                curl_global_cleanup();
                return 1;
            }
        } else {
            printf("Skipping channel %d - no valid ID\n", i + 1);
        }
    }
    
    
    // Connect global WebSocket for all channels
    if (!connect_global_websocket()) {
        fprintf(stderr, "Failed to connect WebSocket\n");
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
    
    printf("\n=== SYSTEM BEHAVIOR ===\n");
    printf("Channel Configuration:\n");
    for (int i = 0; i < global_channel_count; i++) {
        if (global_channel_ids[i][0] != '\0') {
            printf("  Channel %d (%s):\n", i + 1, global_channel_ids[i]);
            printf("    - Output: ALWAYS plays EchoStream audio\n");
            printf("    - Input: ENABLED (standard EchoStream)\n");
        }
    }
    // Remove stale example tones output; tones are from JSON only
    
    // Wait for the WebSocket thread to complete
    pthread_join(ws_thread, NULL);
    
    // Cleanup
    
    cleanup_audio_devices();  // Restore audio devices to normal state
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}