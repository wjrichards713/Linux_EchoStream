#ifndef ECHOSTREAM_H
#define ECHOSTREAM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libwebsockets.h>
#include <signal.h>
#include <time.h>
#include <gpiod.h>
#include <portaudio.h>
#include <opus/opus.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>

// Constants
#define JITTER_BUFFER_SIZE 8
#define SAMPLE_RATE 48000
#define SAMPLES_PER_FRAME 1920
#define AUDIO_BUFFER_SIZE 512
#define MAX_CHANNELS 4
#define CHANNEL_ID_LEN 64

// Global state
extern volatile int global_interrupted;
extern char global_channel_ids[MAX_CHANNELS][CHANNEL_ID_LEN];
extern int global_channel_count;

// Forward declarations for modules
void audio_init(void);
void audio_cleanup(void);
void websocket_init(void);
void websocket_cleanup(void);
void gpio_init(void);
void gpio_cleanup(void);
void udp_init(void);
void udp_cleanup(void);
void config_init(void);
void config_cleanup(void);

#endif // ECHOSTREAM_H
