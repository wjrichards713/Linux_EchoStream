#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include "tone_detect.h"

// Simple test program for tone detection
int main() {
    printf("=== Tone Detection Test Program ===\n");
    
    // Initialize tone detection
    printf("Initializing tone detection system...\n");
    if (!init_tone_detection()) {
        printf("ERROR: Failed to initialize tone detection\n");
        return 1;
    }
    
    // Test tone generation
    printf("\nTesting tone generation...\n");
    float test_samples[1024];
    int samples_generated = generate_tone_samples(test_samples, 1024, 1000.0, 100.0, 48000.0);
    printf("Generated %d samples at 1000 Hz for 100ms\n", samples_generated);
    
    // Test frequency conversion functions
    printf("\nTesting frequency conversion functions...\n");
    double test_freq = 1000.0;
    int bin = frequency_to_bin(test_freq);
    double converted_freq = bin_to_frequency(bin);
    printf("Frequency %.1f Hz -> bin %d -> frequency %.1f Hz\n", test_freq, bin, converted_freq);
    
    // Test frequency range checking
    printf("\nTesting frequency range checking...\n");
    int in_range = is_frequency_in_range(1005.0, 1000.0, 10.0);
    printf("1005 Hz within ±10 Hz of 1000 Hz: %s\n", in_range ? "YES" : "NO");
    
    in_range = is_frequency_in_range(1020.0, 1000.0, 10.0);
    printf("1020 Hz within ±10 Hz of 1000 Hz: %s\n", in_range ? "YES" : "NO");
    
    // Test magnitude to dB conversion
    printf("\nTesting magnitude to dB conversion...\n");
    double test_magnitude = 0.5;
    double db = magnitude_to_db(test_magnitude);
    printf("Magnitude %.2f -> %.1f dB\n", test_magnitude, db);
    
    // Test current time function
    printf("\nTesting current time function...\n");
    double current_time = get_current_time_ms();
    printf("Current time: %.2f ms\n", current_time);
    
    // Cleanup
    printf("\nCleaning up...\n");
    cleanup_tone_detection();
    
    printf("Test completed successfully!\n");
    return 0;
}
