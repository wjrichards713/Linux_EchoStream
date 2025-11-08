#ifndef S3_UPLOAD_H
#define S3_UPLOAD_H

#include <stdint.h>

// Start recording audio for a new tone pair and upload to S3 when recording completes
// tone_a_hz: Frequency of first tone in Hz
// tone_b_hz: Frequency of second tone in Hz  
// duration_ms: Recording duration in milliseconds
// Returns: 1 on success, 0 on failure
int start_new_tone_audio_recording(float tone_a_hz, float tone_b_hz, int duration_ms);

// Start recording audio for a known tone pair (from config/shadow) and upload to S3 when recording completes
// tone_a_hz: Frequency of first tone in Hz
// tone_b_hz: Frequency of second tone in Hz  
// duration_ms: Recording duration in milliseconds
// Returns: 1 on success, 0 on failure
int start_known_tone_audio_recording(float tone_a_hz, float tone_b_hz, int duration_ms);

// Stop current recording if active (called when recording timer expires)
void stop_new_tone_audio_recording(void);

// Upload audio file to AWS S3
// file_path: Path to the audio file to upload
// tone_a_hz: Frequency of first tone
// tone_b_hz: Frequency of second tone
// Returns: 1 on success, 0 on failure
int upload_audio_to_s3(const char* file_path, float tone_a_hz, float tone_b_hz);

// Check if new tone recording is currently active
// Returns: 1 if recording, 0 otherwise
int is_new_tone_recording_active(void);

// Write audio samples to active recording (called from audio processing thread)
// samples: Audio samples (32-bit float)
// sample_count: Number of samples
// sample_rate: Sample rate in Hz
// Returns: 1 on success, 0 on failure
int write_audio_samples_to_recording(float* samples, int sample_count, int sample_rate);

// Write audio samples to known tone recording (called from audio processing thread)
// samples: Audio samples (32-bit float)
// sample_count: Number of samples
// sample_rate: Sample rate in Hz
// Returns: 1 on success, 0 on failure
int write_audio_samples_to_known_recording(float* samples, int sample_count, int sample_rate);

// Stop known tone recording if active
void stop_known_tone_audio_recording(void);

// Check if known tone recording is active
// Returns: 1 if recording, 0 otherwise
int is_known_tone_recording_active(void);

// Play recorded audio file on passthrough channel
// file_path: Path to WAV audio file
void play_recorded_audio_on_passthrough(const char* file_path);

#endif // S3_UPLOAD_H
