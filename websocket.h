#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include "echostream.h"

// WebSocket structures
struct server_config {
    int udp_port;
    char udp_host[128];
    int websocket_id;
};

struct websocket_ctx {
    struct lws_context *context;
    struct lws *client_wsi;
    int interrupted;
    char channel_id[CHANNEL_ID_LEN];
};

// Global WebSocket state
extern struct lws_context *global_ws_context;
extern struct lws *global_ws_client;
extern struct server_config global_config;
extern int global_config_initialized;

// Function declarations
int connect_global_websocket(void);
int parse_websocket_config(const char *json_str, struct server_config *cfg);
void send_websocket_transmit_event(const char* channel_id, int is_started);
void send_websocket_passthrough_event(const char* source_channel_id, const char* target_channel_id, int is_active);
void* global_websocket_thread(void* arg);

#endif // WEBSOCKET_H
