#include "echostream.h"
#include "audio.h"
#include "websocket.h"
#include "gpio.h"
#include "udp.h"
#include "config.h"
#include "crypto.h"

// Global state
volatile int global_interrupted = 0;
char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN] = {"555", "666", "308e2478-072c-4d8b-ffff24d-51854e06711a", "94415b61-8007-430d-ffffea0-10fc9fee2d8e"};

static void handle_interrupt(int sig) {
    (void)sig; // Suppress unused parameter warning
    printf("\nShutdown signal received, cleaning up...\n");
    global_interrupted = 1;
    
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
}

int main(int argc, char *argv[]) {
    (void)argc; // Suppress unused parameter warning
    (void)argv; // Suppress unused parameter warning
    // Initialize global variables
    global_interrupted = 0;
    
    // Load channel configuration from JSON file
    printf("Loading channel configuration from /home/will/.an/config.json...\n");
    if (load_channel_config(global_channel_ids)) {
        printf("Channel configuration loaded successfully\n");
    } else {
        printf("Using default channel IDs\n");
    }
    
    if (!initialize_portaudio()) {
        fprintf(stderr, "PortAudio initialization failed\n");
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
    
    printf("Setting up all 4 channels...\n");
    
    for (int i = 0; i < 4; i++) {
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
    
    // Start audio passthrough now that devices are assigned
    if (!start_audio_passthrough()) {
        fprintf(stderr, "Failed to start audio passthrough\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Connect global WebSocket for all channels
    if (!connect_global_websocket()) {
        fprintf(stderr, "Failed to connect WebSocket\n");
        stop_audio_passthrough();
        curl_global_cleanup();
        return 1;
    }
    
    pthread_t ws_thread;
    if (pthread_create(&ws_thread, NULL, global_websocket_thread, NULL)) {
        fprintf(stderr, "Failed to create WebSocket thread\n");
        curl_global_cleanup();
        return 1;
    }
    
    printf("All 4 channels running with single WebSocket. Press Ctrl+C to stop.\n");
    
    // Wait for the WebSocket thread to complete
    pthread_join(ws_thread, NULL);
    
    // Cleanup
    stop_audio_passthrough();
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}
