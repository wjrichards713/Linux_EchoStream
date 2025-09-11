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
    
    // Cleanup tone detection
    tone_detect_cleanup();
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
    
    // Initialize tone detection system
    if (!tone_detect_init()) {
        fprintf(stderr, "Tone detection initialization failed\n");
        Pa_Terminate();
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
        
        // Enable tone detection for Channel 1 (index 0)
        if (i == 0) {
            enable_tone_detection_for_channel(i);
            
            // Setup basic tone detection configuration for testing
            const char* basic_tone_config = 
                "{"
                "  \"tone_details\": ["
                "    {"
                "      \"tone_id\": \"test-tone-1\","
                "      \"tone_a\": 1000.0,"
                "      \"tone_b\": 2000.0,"
                "      \"tone_a_length\": 10,"
                "      \"tone_b_length\": 10,"
                "      \"tone_a_range\": 50,"
                "      \"tone_b_range\": 50,"
                "      \"record_length\": 100"
                "    }"
                "  ],"
                "  \"tone_config\": {"
                "    \"threshold\": 0.7,"
                "    \"gain\": 0.4,"
                "    \"db\": -45,"
                "    \"detect_new_tones\": true,"
                "    \"new_tone_length\": 50,"
                "    \"new_tone_range\": 100"
                "  },"
                "  \"filter_frequencies\": ["
                "    {"
                "      \"filter_id\": \"low-pass\","
                "      \"frequency\": 300,"
                "      \"filter_range\": 0,"
                "      \"type\": \"below\""
                "    }"
                "  ]"
                "}";
            
            if (setup_tone_detection_for_channel(i, basic_tone_config)) {
                printf("Basic tone detection configuration loaded for Channel 1\n");
            } else {
                printf("Warning: Failed to load tone detection configuration for Channel 1\n");
            }
        }
    }
    
    // Connect global WebSocket for all channels
    if (!connect_global_websocket()) {
        fprintf(stderr, "Failed to connect WebSocket\n");
        curl_global_cleanup();
        return 1;
    }
    
    // Start tone detection threads (if any channels have tone detection enabled)
    start_tone_detection_threads();
    
    // Ensure tone detection thread is started for Channel 1
    if (channels[0].audio.tone_detect_enabled) {
        printf("Tone detection is active for Channel 1 - monitoring for tones...\n");
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
    
    curl_global_cleanup();
    Pa_Terminate();
    return 0;
}
