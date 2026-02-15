#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include "config.h"

#define MAX_HOPS 30
#define MAX_RETRIES 3
#define TIMEOUT_SEC 1
#define TIMEOUT_USEC 0
#define MAX_PROBES 10  // Max probes per hop for array sizing

// Hop information structure
typedef struct {
    int hop_num;
    uint32_t ip_addr[MAX_PROBES];           // IPs for each probe (load balancing)
    uint8_t mac_addr[6];
    double rtt_ms[MAX_PROBES];           // RTT for probes
    struct timespec start_times[MAX_PROBES]; // Nanosecond-precise start times
    int probes_received;        // Number of successful probes
    int reached;
    int has_mac;
    char error_msg[128];
} HopInfo;

// Global state for threads
typedef struct {
    AutopathConfig *config;
    const char *interface;
    uint32_t src_ip;
    uint32_t dst_ip;
    int sock_icmp;
    int sock_l2;
    uint16_t id;
    HopInfo *all_hops;
    int destination_reached;
    int target_ttl;
    struct timespec dest_reached_time;
    int grace_triggered;
    pthread_mutex_t mutex;
    pthread_cond_t cond; // For waking printer instantly
    int done; // Global exit flag
    int show_animation; // Toggle for bouncing line
} ThreadContext;

/**
 * Main traceroute function - performs Layer 3 and optionally Layer 2 discovery
 */
int run_traceroute(AutopathConfig *config, const char *interface);


/**
 * Perform Layer 2 ARP resolution for a given IP
 */
int resolve_mac_l2(int sock_l2, uint32_t target_ip, uint8_t *mac,
                   AutopathConfig *config, const char *interface);

/**
 * Parse ICMP response and extract hop information
 */
int parse_icmp_response(uint8_t *buffer, int len, uint16_t id, HopInfo *hop);

/**
 * Display hop information
 */
void print_hop(HopInfo *hop, AutopathConfig *config);

/**
 * Smart mode: Query router ARP table when hop is unreachable
 */
int smart_mode_query(uint32_t router_ip, uint32_t target_ip, 
                     AutopathConfig *config);

#endif // TRACEROUTE_H
