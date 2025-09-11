#ifndef UDP_H
#define UDP_H

#include "echostream.h"

// Forward declaration
struct server_config;

// Global UDP state
extern int global_udp_socket;
extern struct sockaddr_in global_server_addr;
extern pthread_t heartbeat_thread;
extern pthread_t udp_listener_thread;

// Function declarations
int setup_global_udp(struct server_config* config);
void* heartbeat_worker(void* arg);
void* udp_listener_worker(void* arg);

#endif // UDP_H
