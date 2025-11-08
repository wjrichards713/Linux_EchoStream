#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "s3_upload.h"
#include "tone_detect.h"
#include "audio.h"
#include "echostream.h"

struct audio_recording_context {
    FILE* recording_file;
    int is_recording;
    float tone_a_hz;
    float tone_b_hz;
    int duration_ms;
    int start_time_ms;
    char filename[256];
    int sample_rate;
    int bits_per_sample;
    int channels;
    long samples_written;
    pthread_mutex_t mutex;
};

static void write_wav_header(FILE* file, int sample_rate, int bits_per_sample, int channels, uint32_t data_bytes) {
    unsigned char header[44];
    uint32_t byte_rate = (uint32_t)(sample_rate * channels * bits_per_sample / 8);
    uint16_t block_align = (uint16_t)(channels * bits_per_sample / 8);
    uint32_t chunk_size = data_bytes + 36;
    uint32_t subchunk1_size = 16;
    uint16_t audio_format = 1; // PCM
    uint32_t subchunk2_size = data_bytes;

    memset(header, 0, sizeof(header));

    memcpy(header, "RIFF", 4);
    header[4] = (unsigned char)(chunk_size & 0xFF);
    header[5] = (unsigned char)((chunk_size >> 8) & 0xFF);
    header[6] = (unsigned char)((chunk_size >> 16) & 0xFF);
    header[7] = (unsigned char)((chunk_size >> 24) & 0xFF);
    memcpy(header + 8, "WAVE", 4);
    memcpy(header + 12, "fmt ", 4);
    header[16] = (unsigned char)(subchunk1_size & 0xFF);
    header[17] = (unsigned char)((subchunk1_size >> 8) & 0xFF);
    header[18] = (unsigned char)(audio_format & 0xFF);
    header[19] = (unsigned char)((audio_format >> 8) & 0xFF);
    header[20] = (unsigned char)(channels & 0xFF);
    header[21] = (unsigned char)((channels >> 8) & 0xFF);
    header[22] = (unsigned char)(sample_rate & 0xFF);
    header[23] = (unsigned char)((sample_rate >> 8) & 0xFF);
    header[24] = (unsigned char)((sample_rate >> 16) & 0xFF);
    header[25] = (unsigned char)((sample_rate >> 24) & 0xFF);
    header[26] = (unsigned char)(byte_rate & 0xFF);
    header[27] = (unsigned char)((byte_rate >> 8) & 0xFF);
    header[28] = (unsigned char)((byte_rate >> 16) & 0xFF);
    header[29] = (unsigned char)((byte_rate >> 24) & 0xFF);
    header[30] = (unsigned char)(block_align & 0xFF);
    header[31] = (unsigned char)((block_align >> 8) & 0xFF);
    header[32] = (unsigned char)(bits_per_sample & 0xFF);
    header[33] = (unsigned char)((bits_per_sample >> 8) & 0xFF);
    memcpy(header + 36, "data", 4);
    header[40] = (unsigned char)(subchunk2_size & 0xFF);
    header[41] = (unsigned char)((subchunk2_size >> 8) & 0xFF);
    header[42] = (unsigned char)((subchunk2_size >> 16) & 0xFF);
    header[43] = (unsigned char)((subchunk2_size >> 24) & 0xFF);

    fseek(file, 0, SEEK_SET);
    fwrite(header, 1, sizeof(header), file);
}

static void finalize_wav_recording_locked(struct audio_recording_context* ctx) {
    if (!ctx->recording_file) {
        return;
    }

    uint32_t bytes_per_sample = (uint32_t)(ctx->bits_per_sample / 8);
    uint32_t data_bytes = (uint32_t)(ctx->samples_written * ctx->channels * bytes_per_sample);

    write_wav_header(ctx->recording_file, ctx->sample_rate, ctx->bits_per_sample, ctx->channels, data_bytes);
    fflush(ctx->recording_file);
    fclose(ctx->recording_file);

    ctx->recording_file = NULL;
    ctx->is_recording = 0;
    ctx->samples_written = 0;
    ctx->start_time_ms = 0;
}

static size_t write_samples_to_wav_locked(struct audio_recording_context* ctx, float* samples, int sample_count) {
    if (!ctx->recording_file || sample_count <= 0) {
        return 0;
    }

    const int bytes_per_sample = ctx->bits_per_sample / 8;
    const int channels = ctx->channels;
    const int total_samples = sample_count * channels;

    int16_t* pcm_buffer = (int16_t*)malloc((size_t)total_samples * sizeof(int16_t));
    if (!pcm_buffer) {
        printf("[S3] Error: Failed to allocate PCM buffer for recording\n");
        return 0;
    }

    for (int i = 0; i < sample_count; i++) {
        float sample = samples[i];
        if (sample > 1.0f) sample = 1.0f;
        if (sample < -1.0f) sample = -1.0f;
        int16_t pcm_sample = (int16_t)(sample * 32767.0f);
        pcm_buffer[i] = pcm_sample;
    }

    size_t written = fwrite(pcm_buffer, sizeof(int16_t), (size_t)sample_count, ctx->recording_file);
    if (written != (size_t)sample_count) {
        printf("[S3] Warning: Failed to write all samples (wrote %zu of %d)\n", written, sample_count);
    }

    ctx->samples_written += (long)written;

    free(pcm_buffer);
    fflush(ctx->recording_file);
    return written;
}

// Recording state for new tones
static struct audio_recording_context recording_state = {
    .recording_file = NULL,
    .is_recording = 0,
    .tone_a_hz = 0.0f,
    .tone_b_hz = 0.0f,
    .duration_ms = 0,
    .start_time_ms = 0,
    .filename = {0},
    .sample_rate = 48000,
    .bits_per_sample = 16,
    .channels = 1,
    .samples_written = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

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
        char filename[256];
        strncpy(filename, recording_state.filename, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';
        
        float tone_a = recording_state.tone_a_hz;
        float tone_b = recording_state.tone_b_hz;
        
        finalize_wav_recording_locked(&recording_state);
        recording_state.filename[0] = '\0';
        
        pthread_mutex_unlock(&recording_state.mutex);
        
        printf("[S3] Recording complete, uploading to S3: %s\n", filename);
        upload_audio_to_s3(filename, tone_a, tone_b);
        
        return 0; // Recording stopped
    }
    
    if (sample_rate != recording_state.sample_rate) {
        // Warn if sample rate differs (shouldn't happen)
        static int warning_count = 0;
        if (warning_count++ % 100 == 0) {
            printf("[S3] Warning: Sample rate mismatch (expected %d, got %d)\n",
                   recording_state.sample_rate, sample_rate);
        }
    }
    
    write_samples_to_wav_locked(&recording_state, samples, sample_count);
    
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
             "/tmp/new_tone_%.1f_%.1f_%ld.wav",
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
    recording_state.sample_rate = 48000;
    recording_state.bits_per_sample = 16;
    recording_state.channels = 1;
    recording_state.samples_written = 0;
    
    write_wav_header(recording_state.recording_file,
                     recording_state.sample_rate,
                     recording_state.bits_per_sample,
                     recording_state.channels,
                     0);
    
    printf("[S3] Started recording new tone audio: Tone A=%.1f Hz, Tone B=%.1f Hz, Duration=%d ms\n",
           tone_a_hz, tone_b_hz, duration_ms);
    printf("[S3] Recording file: %s\n", recording_state.filename);
    
    pthread_mutex_unlock(&recording_state.mutex);
    return 1;
}

// Recording state for known tones (from config/shadow)
static struct audio_recording_context known_recording_state = {
    .recording_file = NULL,
    .is_recording = 0,
    .tone_a_hz = 0.0f,
    .tone_b_hz = 0.0f,
    .duration_ms = 0,
    .start_time_ms = 0,
    .filename = {0},
    .sample_rate = 48000,
    .bits_per_sample = 16,
    .channels = 1,
    .samples_written = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

// Write audio samples to known tone recording file
int write_audio_samples_to_known_recording(float* samples, int sample_count, int sample_rate) {
    pthread_mutex_lock(&known_recording_state.mutex);
    
    if (!known_recording_state.is_recording || !known_recording_state.recording_file) {
        pthread_mutex_unlock(&known_recording_state.mutex);
        return 0;
    }
    
    // Check if recording duration has elapsed
    int current_time_ms = get_current_time_ms();
    int elapsed_ms = current_time_ms - known_recording_state.start_time_ms;
    
    if (elapsed_ms >= known_recording_state.duration_ms) {
        char filename[256];
        strncpy(filename, known_recording_state.filename, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';
        
        float tone_a = known_recording_state.tone_a_hz;
        float tone_b = known_recording_state.tone_b_hz;
        
        finalize_wav_recording_locked(&known_recording_state);
        known_recording_state.filename[0] = '\0';
        
        pthread_mutex_unlock(&known_recording_state.mutex);
        
        printf("[S3] Known tone recording complete, uploading to S3: %s\n", filename);
        upload_audio_to_s3(filename, tone_a, tone_b);
        
        return 0; // Recording stopped
    }
    
    if (sample_rate != known_recording_state.sample_rate) {
        static int warning_count = 0;
        if (warning_count++ % 100 == 0) {
            printf("[S3] Warning: Known tone sample rate mismatch (expected %d, got %d)\n",
                   known_recording_state.sample_rate, sample_rate);
        }
    }
    
    write_samples_to_wav_locked(&known_recording_state, samples, sample_count);
    
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
             "/tmp/known_tone_%.1f_%.1f_%ld.wav",
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
    known_recording_state.sample_rate = 48000;
    known_recording_state.bits_per_sample = 16;
    known_recording_state.channels = 1;
    known_recording_state.samples_written = 0;

    write_wav_header(known_recording_state.recording_file,
                     known_recording_state.sample_rate,
                     known_recording_state.bits_per_sample,
                     known_recording_state.channels,
                     0);
    
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
        finalize_wav_recording_locked(&known_recording_state);
        known_recording_state.filename[0] = '\0';
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
        finalize_wav_recording_locked(&recording_state);
        recording_state.filename[0] = '\0';
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

// Play recorded audio file on passthrough channel
// file_path: Path to WAV audio file
void play_recorded_audio_on_passthrough(const char* file_path) {
    if (!file_path) {
        printf("[PASSTHROUGH PLAYBACK] Error: Invalid file path\n");
        return;
    }
    
    FILE* audio_file = fopen(file_path, "rb");
    if (!audio_file) {
        printf("[PASSTHROUGH PLAYBACK] Error: Failed to open file: %s\n", file_path);
        return;
    }
    
    printf("[PASSTHROUGH PLAYBACK] Playing recorded audio: %s\n", file_path);
    
    // Read WAV header
    unsigned char header[64];
    if (fread(header, 1, 12, audio_file) != 12) {
        printf("[PASSTHROUGH PLAYBACK] Error: Failed to read WAV header\n");
        fclose(audio_file);
        return;
    }
    
    // Check for RIFF and WAVE signature
    if (memcmp(header, "RIFF", 4) != 0 || memcmp(header + 8, "WAVE", 4) != 0) {
        printf("[PASSTHROUGH PLAYBACK] Error: Not a valid WAV file\n");
        fclose(audio_file);
        return;
    }
    
    // Parse WAV chunks to find fmt and data
    int sample_rate = 48000;
    int channels = 1;
    int bits_per_sample = 16;
    long data_size = 0;
    long data_start = 0;
    
    int found_fmt = 0;
    int found_data = 0;
    
    // Read chunks until we find fmt and data
    while (!found_fmt || !found_data) {
        unsigned char chunk_header[8];
        if (fread(chunk_header, 1, sizeof(chunk_header), audio_file) != sizeof(chunk_header)) {
            break;
        }
        
        char chunk_id[5] = {0};
        memcpy(chunk_id, chunk_header, 4);
        uint32_t chunk_size = (uint32_t)chunk_header[4] |
                              ((uint32_t)chunk_header[5] << 8) |
                              ((uint32_t)chunk_header[6] << 16) |
                              ((uint32_t)chunk_header[7] << 24);
        
        if (memcmp(chunk_id, "fmt ", 4) == 0) {
            // Read fmt chunk
            unsigned char fmt_data[32] = {0};
            size_t to_read = chunk_size < sizeof(fmt_data) ? chunk_size : sizeof(fmt_data);
            if (fread(fmt_data, 1, to_read, audio_file) < 16) {
                break;
            }
            
            uint16_t audio_format = (uint16_t)fmt_data[0] | ((uint16_t)fmt_data[1] << 8);
            channels = (uint16_t)fmt_data[2] | ((uint16_t)fmt_data[3] << 8);
            sample_rate = (int)(fmt_data[4] | (fmt_data[5] << 8) | (fmt_data[6] << 16) | (fmt_data[7] << 24));
            bits_per_sample = (uint16_t)fmt_data[14] | ((uint16_t)fmt_data[15] << 8);
            
            if (audio_format != 1) {
                printf("[PASSTHROUGH PLAYBACK] Warning: Unsupported WAV audio format (%u)\n", audio_format);
                fclose(audio_file);
                return;
            }
            
            found_fmt = 1;
            
            // Skip any remaining bytes in fmt chunk
            if (chunk_size > to_read) {
                fseek(audio_file, (long)(chunk_size - to_read), SEEK_CUR);
            }
        } else if (memcmp(chunk_id, "data", 4) == 0) {
            data_size = chunk_size;
            data_start = ftell(audio_file);
            found_data = 1;
            break;
        } else {
            // Skip unknown chunk (with padding if chunk size is odd)
            fseek(audio_file, (long)chunk_size, SEEK_CUR);
            if (chunk_size % 2 != 0) {
                fseek(audio_file, 1, SEEK_CUR);
            }
        }
        
        // Ensure even chunk alignment
        if (chunk_size % 2 != 0) {
            fseek(audio_file, 1, SEEK_CUR);
        }
    }
    
    if (!found_fmt || !found_data) {
        printf("[PASSTHROUGH PLAYBACK] Error: Failed to find fmt or data chunk in WAV file\n");
        fclose(audio_file);
        return;
    }
    
    printf("[PASSTHROUGH PLAYBACK] WAV info: sample_rate=%d, channels=%d, bits_per_sample=%d, data_size=%ld bytes\n",
           sample_rate, channels, bits_per_sample, data_size);
    
    // Calculate total samples
    int bytes_per_sample = bits_per_sample / 8;
    long total_samples = data_size / (bytes_per_sample * channels);
    
    printf("[PASSTHROUGH PLAYBACK] File contains %ld samples (%.2f seconds)\n", 
           total_samples, (float)total_samples / (float)sample_rate);
    
    if (data_start > 0) {
        fseek(audio_file, data_start, SEEK_SET);
    }
    
    // Read and play audio in chunks
    float buffer[SAMPLES_PER_FRAME];
    const size_t max_bytes_per_chunk = (size_t)SAMPLES_PER_FRAME * (size_t)channels * (size_t)(bits_per_sample / 8);
    unsigned char* pcm_buffer = (unsigned char*)malloc(max_bytes_per_chunk);
    if (!pcm_buffer) {
        printf("[PASSTHROUGH PLAYBACK] Error: Failed to allocate PCM buffer\n");
        fclose(audio_file);
        return;
    }
    
    long samples_played = 0;
    
    while (samples_played < total_samples && !global_interrupted) {
        // Calculate samples to read in this chunk
        long samples_to_read = SAMPLES_PER_FRAME;
        if (samples_played + samples_to_read > total_samples) {
            samples_to_read = total_samples - samples_played;
        }
        
        // Read PCM samples from file
        size_t bytes_to_read = (size_t)(samples_to_read * bytes_per_sample * channels);
        if (bytes_to_read > max_bytes_per_chunk) {
            bytes_to_read = max_bytes_per_chunk;
        }
        
        size_t bytes_read = fread(pcm_buffer, 1, bytes_to_read, audio_file);
        if (bytes_read == 0) {
            break; // End of file or error
        }
        
        // Convert PCM samples to float
        int samples_converted = 0;
        int frame_count = (int)(bytes_read / (bytes_per_sample * channels));
        
        for (int i = 0; i < frame_count; i++) {
            float sample = 0.0f;
            int sample_offset = i * bytes_per_sample * channels;
            
            if (bits_per_sample == 16) {
                // 16-bit PCM (signed short, little-endian)
                short pcm_sample = *(short*)(pcm_buffer + sample_offset);
                sample = (float)pcm_sample / 32768.0f;
                
                // If stereo, average channels
                if (channels > 1) {
                    short pcm_sample_r = *(short*)(pcm_buffer + sample_offset + bytes_per_sample);
                    sample = (sample + ((float)pcm_sample_r / 32768.0f)) / 2.0f;
                }
            } else if (bits_per_sample == 24) {
                // 24-bit PCM (signed, little-endian)
                int pcm_sample = (int)(pcm_buffer[sample_offset]) |
                                ((int)(pcm_buffer[sample_offset + 1]) << 8) |
                                ((int)(pcm_buffer[sample_offset + 2]) << 16);
                if (pcm_sample & 0x800000) pcm_sample |= 0xFF000000; // Sign extend
                sample = (float)pcm_sample / 8388608.0f;
                
                // If stereo, average channels
                if (channels > 1) {
                    int pcm_sample_r = (int)(pcm_buffer[sample_offset + 3]) |
                                      ((int)(pcm_buffer[sample_offset + 4]) << 8) |
                                      ((int)(pcm_buffer[sample_offset + 5]) << 16);
                    if (pcm_sample_r & 0x800000) pcm_sample_r |= 0xFF000000;
                    sample = (sample + ((float)pcm_sample_r / 8388608.0f)) / 2.0f;
                }
            } else if (bits_per_sample == 32) {
                // 32-bit PCM (signed int, little-endian)
                int pcm_sample = *(int*)(pcm_buffer + sample_offset);
                sample = (float)pcm_sample / 2147483648.0f;
                
                // If stereo, average channels
                if (channels > 1) {
                    int pcm_sample_r = *(int*)(pcm_buffer + sample_offset + bytes_per_sample);
                    sample = (sample + ((float)pcm_sample_r / 2147483648.0f)) / 2.0f;
                }
            } else {
                printf("[PASSTHROUGH PLAYBACK] Warning: Unsupported bits_per_sample: %d\n", bits_per_sample);
                sample = 0.0f;
            }
            
            buffer[samples_converted++] = sample;
        }
        
        if (samples_converted == 0) {
            break;
        }
        
        // Write to shared buffer for passthrough playback
        pthread_mutex_lock(&global_shared_buffer.mutex);
        for (int i = 0; i < samples_converted && i < SAMPLES_PER_FRAME; i++) {
            global_shared_buffer.samples[i] = buffer[i];
        }
        global_shared_buffer.sample_count = samples_converted;
        global_shared_buffer.valid = 1;
        pthread_cond_signal(&global_shared_buffer.data_ready);
        pthread_mutex_unlock(&global_shared_buffer.mutex);
        
        samples_played += samples_converted;
        
        // Sleep to match playback rate
        int sleep_us = (int)((samples_converted * 1000000) / sample_rate);
        if (sleep_us > 0) {
            usleep(sleep_us);
        }
    }
    
    free(pcm_buffer);
    fclose(audio_file);
    
    printf("[PASSTHROUGH PLAYBACK] Finished playing %ld samples (%.2f seconds)\n", 
           samples_played, (float)samples_played / (float)sample_rate);
    
    // Clear the shared buffer after playback
    pthread_mutex_lock(&global_shared_buffer.mutex);
    global_shared_buffer.valid = 0;
    global_shared_buffer.sample_count = 0;
    pthread_mutex_unlock(&global_shared_buffer.mutex);
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
        snprintf(s3_key, sizeof(s3_key), "known_tones/tone_a_%.1f_tone_b_%.1f_%ld.wav",
                 tone_a_hz, tone_b_hz, (long)now);
    } else {
        snprintf(s3_key, sizeof(s3_key), "new_tones/tone_a_%.1f_tone_b_%.1f_%ld.wav",
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
        // Note: Playback already happened before upload (in recording completion handlers)
        unlink(file_path);
        printf("[S3] Deleted local file: %s\n", file_path);
        return 1;
    } else {
        printf("[S3] Error: Failed to upload to S3 (exit code: %d)\n", result);
        printf("[S3] File remains at: %s\n", file_path);
        return 0;
    }
}

