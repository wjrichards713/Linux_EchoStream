#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "s3_upload.h"
#include "tone_detect.h"

// Recording state for new tones
static struct {
    FILE* recording_file;
    int is_recording;
    float tone_a_hz;
    float tone_b_hz;
    int duration_ms;
    int start_time_ms;
    char filename[256];  // Store filename for S3 upload
    pthread_mutex_t mutex;
} recording_state = {
    .recording_file = NULL,
    .is_recording = 0,
    .tone_a_hz = 0.0f,
    .tone_b_hz = 0.0f,
    .duration_ms = 0,
    .start_time_ms = 0,
    .filename = {0},
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

// Get current time in milliseconds
static int get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// Write audio samples to recording file (called from audio processing thread)
// samples: Audio samples (32-bit float)
// sample_count: Number of samples
// sample_rate: Sample rate in Hz (typically 48000)
// Returns: 1 on success, 0 on failure
int write_audio_samples_to_recording(float* samples, int sample_count, int sample_rate) {
    pthread_mutex_lock(&recording_state.mutex);
    
    if (!recording_state.is_recording || !recording_state.recording_file) {
        pthread_mutex_unlock(&recording_state.mutex);
        return 0;
    }
    
    // Check if recording duration has elapsed
    int current_time_ms = get_current_time_ms();
    int elapsed_ms = current_time_ms - recording_state.start_time_ms;
    
    if (elapsed_ms >= recording_state.duration_ms) {
        // Recording complete - close file
        fclose(recording_state.recording_file);
        
        // Use stored filename
        char filename[256];
        strncpy(filename, recording_state.filename, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';
        
        float tone_a = recording_state.tone_a_hz;
        float tone_b = recording_state.tone_b_hz;
        
        recording_state.recording_file = NULL;
        recording_state.is_recording = 0;
        recording_state.filename[0] = '\0';  // Clear filename
        
        pthread_mutex_unlock(&recording_state.mutex);
        
        // Upload to S3 (this will be called outside the mutex to avoid blocking)
        printf("[S3] Recording complete, uploading to S3: %s\n", filename);
        upload_audio_to_s3(filename, tone_a, tone_b);
        
        return 0; // Recording stopped
    }
    
    // Write samples as raw 32-bit float PCM
    size_t written = fwrite(samples, sizeof(float), sample_count, recording_state.recording_file);
    if (written != sample_count) {
        printf("[S3] Warning: Failed to write all samples (wrote %zu of %d)\n", written, sample_count);
    }
    
    fflush(recording_state.recording_file); // Ensure data is written
    
    pthread_mutex_unlock(&recording_state.mutex);
    return 1;
}

// Start recording audio for new tone pair (unknown tones - not in config)
int start_new_tone_audio_recording(float tone_a_hz, float tone_b_hz, int duration_ms) {
    pthread_mutex_lock(&recording_state.mutex);
    
    // Stop any existing recording
    if (recording_state.is_recording && recording_state.recording_file) {
        fclose(recording_state.recording_file);
        recording_state.recording_file = NULL;
    }
    
    // Create filename with timestamp
    time_t now = time(NULL);
    snprintf(recording_state.filename, sizeof(recording_state.filename), 
             "/tmp/new_tone_%.1f_%.1f_%ld.raw",
             tone_a_hz, tone_b_hz, (long)now);
    
    // Open file for writing
    FILE* file = fopen(recording_state.filename, "wb");
    if (!file) {
        printf("[S3] Error: Failed to create recording file: %s\n", recording_state.filename);
        recording_state.filename[0] = '\0';
        pthread_mutex_unlock(&recording_state.mutex);
        return 0;
    }
    
    // Initialize recording state
    recording_state.recording_file = file;
    recording_state.is_recording = 1;
    recording_state.tone_a_hz = tone_a_hz;
    recording_state.tone_b_hz = tone_b_hz;
    recording_state.duration_ms = duration_ms;
    recording_state.start_time_ms = get_current_time_ms();
    
    printf("[S3] Started recording new tone audio: Tone A=%.1f Hz, Tone B=%.1f Hz, Duration=%d ms\n",
           tone_a_hz, tone_b_hz, duration_ms);
    printf("[S3] Recording file: %s\n", recording_state.filename);
    
    pthread_mutex_unlock(&recording_state.mutex);
    return 1;
}

// Recording state for known tones (from config/shadow)
static struct {
    FILE* recording_file;
    int is_recording;
    float tone_a_hz;
    float tone_b_hz;
    int duration_ms;
    int start_time_ms;
    char filename[256];  // Store filename for S3 upload
    pthread_mutex_t mutex;
} known_recording_state = {
    .recording_file = NULL,
    .is_recording = 0,
    .tone_a_hz = 0.0f,
    .tone_b_hz = 0.0f,
    .duration_ms = 0,
    .start_time_ms = 0,
    .filename = {0},
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

// Write audio samples to known tone recording file
int write_audio_samples_to_known_recording(float* samples, int sample_count, int sample_rate) {
    (void)sample_rate; // Not used
    pthread_mutex_lock(&known_recording_state.mutex);
    
    if (!known_recording_state.is_recording || !known_recording_state.recording_file) {
        pthread_mutex_unlock(&known_recording_state.mutex);
        return 0;
    }
    
    // Check if recording duration has elapsed
    int current_time_ms = get_current_time_ms();
    int elapsed_ms = current_time_ms - known_recording_state.start_time_ms;
    
    if (elapsed_ms >= known_recording_state.duration_ms) {
        // Recording complete - close file
        fclose(known_recording_state.recording_file);
        
        // Use stored filename
        char filename[256];
        strncpy(filename, known_recording_state.filename, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';
        
        float tone_a = known_recording_state.tone_a_hz;
        float tone_b = known_recording_state.tone_b_hz;
        
        known_recording_state.recording_file = NULL;
        known_recording_state.is_recording = 0;
        known_recording_state.filename[0] = '\0';  // Clear filename
        
        pthread_mutex_unlock(&known_recording_state.mutex);
        
        // Upload to S3
        printf("[S3] Known tone recording complete, uploading to S3: %s\n", filename);
        upload_audio_to_s3(filename, tone_a, tone_b);
        
        return 0; // Recording stopped
    }
    
    // Write samples as raw 32-bit float PCM
    size_t written = fwrite(samples, sizeof(float), sample_count, known_recording_state.recording_file);
    if (written != sample_count) {
        printf("[S3] Warning: Failed to write all samples to known tone recording (wrote %zu of %d)\n", written, sample_count);
    }
    
    fflush(known_recording_state.recording_file);
    
    pthread_mutex_unlock(&known_recording_state.mutex);
    return 1;
}

// Start recording audio for known tone pair (from config/shadow) - records ALL incoming audio
int start_known_tone_audio_recording(float tone_a_hz, float tone_b_hz, int duration_ms) {
    pthread_mutex_lock(&known_recording_state.mutex);
    
    // Stop any existing recording
    if (known_recording_state.is_recording && known_recording_state.recording_file) {
        fclose(known_recording_state.recording_file);
        known_recording_state.recording_file = NULL;
    }
    
    // Create filename with timestamp
    time_t now = time(NULL);
    snprintf(known_recording_state.filename, sizeof(known_recording_state.filename), 
             "/tmp/known_tone_%.1f_%.1f_%ld.raw",
             tone_a_hz, tone_b_hz, (long)now);
    
    // Open file for writing
    FILE* file = fopen(known_recording_state.filename, "wb");
    if (!file) {
        printf("[S3] Error: Failed to create known tone recording file: %s\n", known_recording_state.filename);
        known_recording_state.filename[0] = '\0';
        pthread_mutex_unlock(&known_recording_state.mutex);
        return 0;
    }
    
    // Initialize recording state
    known_recording_state.recording_file = file;
    known_recording_state.is_recording = 1;
    known_recording_state.tone_a_hz = tone_a_hz;
    known_recording_state.tone_b_hz = tone_b_hz;
    known_recording_state.duration_ms = duration_ms;
    known_recording_state.start_time_ms = get_current_time_ms();
    
    printf("[S3] Started recording known tone audio (ALL incoming audio): Tone A=%.1f Hz, Tone B=%.1f Hz, Duration=%d ms\n",
           tone_a_hz, tone_b_hz, duration_ms);
    printf("[S3] Recording file: %s\n", known_recording_state.filename);
    
    pthread_mutex_unlock(&known_recording_state.mutex);
    return 1;
}

// Stop known tone recording if active
void stop_known_tone_audio_recording(void) {
    pthread_mutex_lock(&known_recording_state.mutex);
    
    if (known_recording_state.is_recording && known_recording_state.recording_file) {
        fclose(known_recording_state.recording_file);
        known_recording_state.recording_file = NULL;
        known_recording_state.is_recording = 0;
        printf("[S3] Known tone recording stopped\n");
    }
    
    pthread_mutex_unlock(&known_recording_state.mutex);
}

// Check if known tone recording is active
int is_known_tone_recording_active(void) {
    pthread_mutex_lock(&known_recording_state.mutex);
    int active = known_recording_state.is_recording;
    pthread_mutex_unlock(&known_recording_state.mutex);
    return active;
}

// Stop current recording if active
void stop_new_tone_audio_recording(void) {
    pthread_mutex_lock(&recording_state.mutex);
    
    if (recording_state.is_recording && recording_state.recording_file) {
        fclose(recording_state.recording_file);
        recording_state.recording_file = NULL;
        recording_state.is_recording = 0;
        printf("[S3] Recording stopped\n");
    }
    
    pthread_mutex_unlock(&recording_state.mutex);
}

// Check if recording is active (called from audio processing)
int is_new_tone_recording_active(void) {
    pthread_mutex_lock(&recording_state.mutex);
    int active = recording_state.is_recording;
    pthread_mutex_unlock(&recording_state.mutex);
    return active;
}

// Upload audio file to AWS S3
int upload_audio_to_s3(const char* file_path, float tone_a_hz, float tone_b_hz) {
    if (!file_path) {
        printf("[S3] Error: Invalid file path\n");
        return 0;
    }
    
    // Check if file exists
    struct stat st;
    if (stat(file_path, &st) != 0) {
        printf("[S3] Error: File does not exist: %s\n", file_path);
        return 0;
    }
    
    // Create S3 key (path) with timestamp
    // Determine if this is a known or new tone based on filename
    int is_known = (strstr(file_path, "known_tone") != NULL);
    time_t now = time(NULL);
    char s3_key[512];
    if (is_known) {
        snprintf(s3_key, sizeof(s3_key), "known_tones/tone_a_%.1f_tone_b_%.1f_%ld.raw",
                 tone_a_hz, tone_b_hz, (long)now);
    } else {
        snprintf(s3_key, sizeof(s3_key), "new_tones/tone_a_%.1f_tone_b_%.1f_%ld.raw",
                 tone_a_hz, tone_b_hz, (long)now);
    }
    
    // For now, use AWS CLI to upload
    // In production, you might want to use AWS SDK for C
    char command[1024];
    snprintf(command, sizeof(command),
             "aws s3 cp \"%s\" s3://your-bucket-name/%s 2>&1",
             file_path, s3_key);
    
    printf("[S3] Uploading to S3: %s\n", s3_key);
    printf("[S3] Command: %s\n", command);
    
    int result = system(command);
    
    if (result == 0) {
        printf("[S3] Successfully uploaded to S3: %s\n", s3_key);
        
        // Delete local file after successful upload
        unlink(file_path);
        printf("[S3] Deleted local file: %s\n", file_path);
        return 1;
    } else {
        printf("[S3] Error: Failed to upload to S3 (exit code: %d)\n", result);
        printf("[S3] File remains at: %s\n", file_path);
        return 0;
    }
}

