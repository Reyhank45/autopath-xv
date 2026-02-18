/**
 * @file traceroute.c
 * @brief Core multi-threaded traceroute engine.
 * 
 * Implements the "Shotgun" style traceroute engine using three main threads:
 * 1. Sender: Sends all probes as fast as possible with minimal delay.
 * 2. Receiver: Uses epoll for high-performance non-blocking packet capture.
 * 3. Printer: Coordinates display and real-time path analysis.
 */

#include "traceroute.h"
#include "netutils.h"
#include "config.h"
#include "snmp_query.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

/**
 * @brief Animation thread for the high-speed "Laser Bouncer" visual effect.
 * Provides real-time feedback during the sub-second trace execution.
 */
void *animation_thread_func(void *arg) {
    ThreadContext *ctx = (ThreadContext *)arg;
    struct winsize w;
    int col_width = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 10) {
        col_width = w.ws_col;
    }

    int pos = 0;
    int dir = 1;
    int laser_len = 15;

    while (!ctx->done && ctx->show_animation) {
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 10) {
            col_width = w.ws_col;
        }

        pthread_mutex_lock(&ctx->mutex);
        int track_width = col_width - 12;
        if (track_width < 10) track_width = 10;

        printf("\r\033[1;36m[");
        for (int i = 0; i < track_width; i++) {
            if (i >= pos && i < pos + laser_len) {
                // Gradient laser effects
                if (i == pos || i == pos + laser_len - 1) printf("\033[1;36m=");
                else printf("\033[1;37m#");
            } else {
                printf("\033[0;34m."); 
            }
        }
        printf("\033[1;36m] \033[1;33mSPEED\033[0m");
        fflush(stdout);
        pthread_mutex_unlock(&ctx->mutex);

        pos += dir;
        if (pos >= (track_width - laser_len) || pos <= 0) {
            dir *= -1;
        }
        
        usleep(8000); // 125 FPS refresh rate
    }
    
    pthread_mutex_lock(&ctx->mutex);
    printf("\r\033[K");
    fflush(stdout);
    pthread_mutex_unlock(&ctx->mutex);
    return NULL;
}

/**
 * @brief Sender Thread: Transmits ICMP/UDP probes at maximum speed.
 * Uses a microscopic 500us stagger to prevent ICMP rate-limiting artifacts.
 */
void *sender_thread_func(void *arg) {
    ThreadContext *ctx = (ThreadContext *)arg;
    int num_probes = ctx->config->num_probes;
    int use_udp = ctx->config->use_udp;
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ctx->dst_ip;

    for (int ttl = 1; ttl <= MAX_HOPS && !ctx->done; ttl++) {
        for (int probe = 0; probe < num_probes && !ctx->done; probe++) {
            uint16_t seq = (ttl << 8) | probe;
            uint16_t probe_id = (ctx->id + probe) & 0xFFFF;
            uint8_t packet[MAX_PACKET_SIZE];
            int pkt_len;

            if (use_udp) {
                dest_addr.sin_port = htons(33434 + seq);
                pkt_len = build_udp_packet(packet, ctx->src_ip, ctx->dst_ip, 
                                          33434 + probe, 33434 + seq, ttl);
            } else {
                pkt_len = build_icmp_packet(packet, probe_id, seq, ctx->src_ip, ctx->dst_ip, ttl);
            }
            
            clock_gettime(CLOCK_MONOTONIC, &ctx->all_hops[ttl].start_times[probe]);
            
            if (sendto(ctx->sock_icmp, packet, pkt_len, 0, 
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
                if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
                    snprintf(ctx->all_hops[ttl].error_msg, sizeof(ctx->all_hops[ttl].error_msg), 
                             "Route Error: %s", (errno == ENETUNREACH) ? "Unreachable" : "Host Unreachable");
                    ctx->done = 1;
                    break;
                }
            }
            // microscopic stagger to maintain router veracity
            usleep(500); 
        }
    }
    return NULL;
}

/**
 * @brief Receiver Thread: Listens for ICMP responses via epoll.
 * Performs real-time protocol-agnostic response parsing (TTL Exceeded vs Destination Reached).
 */
void *receiver_thread_func(void *arg) {
    ThreadContext *ctx = (ThreadContext *)arg;
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) return NULL;

    struct epoll_event event, events[MAX_HOPS * MAX_PROBES];
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = ctx->sock_icmp;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->sock_icmp, &event);

    while (!ctx->done) {
        int n = epoll_wait(epoll_fd, events, MAX_HOPS * MAX_PROBES, 10);
        if (n <= 0) continue;

        for (int i = 0; i < n; i++) {
            uint8_t recv_buffer[MAX_PACKET_SIZE];
            ssize_t recv_len;
            while (1) {
                recv_len = recvfrom(ctx->sock_icmp, recv_buffer, sizeof(recv_buffer), 0, NULL, NULL);
                if (recv_len < 0) break;

                struct timespec end_time;
                clock_gettime(CLOCK_MONOTONIC, &end_time);

                struct iphdr *ip = (struct iphdr *)recv_buffer;
                int ip_hdr_len = ip->ihl * 4;
                struct icmphdr *icmp = (struct icmphdr *)(recv_buffer + ip_hdr_len);
                
                uint16_t resp_seq = 0;
                uint16_t resp_id = 0;
                int is_udp = ctx->config->use_udp;
                
                if (icmp->type == ICMP_ECHOREPLY) {
                    resp_seq = ntohs(icmp->un.echo.sequence);
                    resp_id = ntohs(icmp->un.echo.id);
                } else if (icmp->type == ICMP_TIME_EXCEEDED || icmp->type == ICMP_DEST_UNREACH) {
                    // Extract original packet from ICMP quote for verification
                    struct iphdr *orig_ip = (struct iphdr *)(recv_buffer + ip_hdr_len + 8);
                    int orig_ip_hdr_len = orig_ip->ihl * 4;
                    
                    if (is_udp) {
                        uint16_t *orig_udp_ports = (uint16_t *)((uint8_t *)orig_ip + orig_ip_hdr_len);
                        resp_seq = ntohs(orig_udp_ports[1]) - 33434;
                        resp_id = ctx->id + (ntohs(orig_udp_ports[0]) - 33434);
                    } else {
                        struct icmphdr *orig_icmp = (struct icmphdr *)((uint8_t *)orig_ip + orig_ip_hdr_len);
                        resp_seq = ntohs(orig_icmp->un.echo.sequence);
                        resp_id = ntohs(orig_icmp->un.echo.id);
                    }
                } else {
                    continue;
                }

                // Verify the response belongs to our current process and probe ID range
                if (resp_id < ctx->id || resp_id >= ctx->id + ctx->config->num_probes) continue;

                int h_idx = (resp_seq >> 8) & 0xFF;
                int p_idx = resp_seq & 0xFF;

                if (h_idx >= 1 && h_idx <= MAX_HOPS && p_idx >= 0 && p_idx < ctx->config->num_probes) {
                    pthread_mutex_lock(&ctx->mutex);
                    if (ctx->all_hops[h_idx].rtt_ms[p_idx] < 0) {
                        double rtt = (end_time.tv_sec - ctx->all_hops[h_idx].start_times[p_idx].tv_sec) * 1000.0 +
                                     (end_time.tv_nsec - ctx->all_hops[h_idx].start_times[p_idx].tv_nsec) / 1000000.0;
                        
                        ctx->all_hops[h_idx].rtt_ms[p_idx] = rtt;
                        ctx->all_hops[h_idx].probes_received++;
                        ctx->all_hops[h_idx].ip_addr[p_idx] = ip->saddr;
                        ctx->all_hops[h_idx].reached = 1;
                        
                        // Check if we hit the actual target or terminal destination
                        if (ip->saddr == ctx->dst_ip || 
                           (icmp->type == ICMP_ECHOREPLY) || 
                           (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_PORT_UNREACH)) {
                            
                            if (!ctx->destination_reached) {
                                ctx->destination_reached = 1;
                                clock_gettime(CLOCK_MONOTONIC, &ctx->dest_reached_time);
                                ctx->grace_triggered = 1;
                            }
                            if (h_idx < ctx->target_ttl) ctx->target_ttl = h_idx;
                        }
                        // Alert the printer loop to wake up immediately
                        pthread_cond_signal(&ctx->cond);
                    }
                    pthread_mutex_unlock(&ctx->mutex);
                }
            }
        }
    }
    close(epoll_fd);
    return NULL;
}

/**
 * @brief Orchestrates the multi-threaded traceroute operation.
 */
int run_traceroute(AutopathConfig *config, const char *interface) {
    struct in_addr local_ip_addr;
    if (get_local_ip(interface, &local_ip_addr) < 0) {
        fprintf(stderr, "Failed to get local IP for interface %s\n", interface);
        return -1;
    }
    uint32_t src_ip = local_ip_addr.s_addr;

    uint32_t dst_ip = 0;
    if (inet_pton(AF_INET, config->target_ip, &dst_ip) != 1) {
        fprintf(stderr, "Invalid target IP: %s\n", config->target_ip);
        return -1;
    }

    // Advanced modes (L2/Bypass) use specific interface binding
    const char *bind_interface = (config->layer2_enabled || config->use_arp || config->smart_mode) ? interface : NULL;
    int sock_icmp = create_raw_socket_icmp(bind_interface);
    if (sock_icmp < 0) {
        fprintf(stderr, "Failed to create ICMP socket (need root/CAP_NET_RAW)\n");
        return -1;
    }
    
    int flags = fcntl(sock_icmp, F_GETFL, 0);
    fcntl(sock_icmp, F_SETFL, flags | O_NONBLOCK);

    int sock_l2 = -1;
    if (config->layer2_enabled || config->use_arp) {
        sock_l2 = create_raw_socket_l2(interface);
    }

    // Local subnet optimization for single-hop traces
    int is_local = 0;
    struct in_addr netmask;
    if (get_local_netmask(interface, &netmask) == 0) {
        if (is_same_subnet(src_ip, dst_ip, netmask.s_addr)) {
            is_local = 1;
        }
    }

    if (config->layer2_enabled || config->use_arp || config->smart_mode) {
        printf("\033[1;33m[!] Advanced Bypass Active: Ignoring local routing table redirects.\033[0m\n");
    }
    printf("Path Tracing to %s, max %d hops:\n", config->target_ip, MAX_HOPS);

    HopInfo all_hops[MAX_HOPS + 1];
    memset(all_hops, 0, sizeof(all_hops));
    for (int i = 1; i <= MAX_HOPS; i++) {
        all_hops[i].hop_num = i;
        for (int j = 0; j < MAX_PROBES; j++) {
            all_hops[i].rtt_ms[j] = -1.0;
            all_hops[i].ip_addr[j] = 0;
        }
    }

    ThreadContext ctx = {0};
    ctx.config = config;
    ctx.interface = interface;
    ctx.src_ip = src_ip;
    ctx.dst_ip = dst_ip;
    ctx.sock_icmp = sock_icmp;
    ctx.sock_l2 = sock_l2;
    ctx.id = getpid() & 0xFFFF;
    ctx.all_hops = all_hops;
    ctx.target_ttl = is_local ? 1 : MAX_HOPS;
    ctx.show_animation = !config->debug; 
    pthread_mutex_init(&ctx.mutex, NULL);
    pthread_cond_init(&ctx.cond, NULL);

    pthread_t sender, receiver, animation;
    pthread_create(&sender, NULL, sender_thread_func, &ctx);
    pthread_create(&receiver, NULL, receiver_thread_func, &ctx);
    if (ctx.show_animation) pthread_create(&animation, NULL, animation_thread_func, &ctx);

    struct timespec start_trace, now;
    clock_gettime(CLOCK_MONOTONIC, &start_trace);
    
    int last_printed = 0;
    while (!ctx.done) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start_trace.tv_sec) * 1000 + (now.tv_nsec - start_trace.tv_nsec) / 1000000;
        
        if (elapsed > 2000) ctx.done = 1; // 2s global safety timeout

        if (ctx.grace_triggered) {
            long grace_elapsed = (now.tv_sec - ctx.dest_reached_time.tv_sec) * 1000 + (now.tv_nsec - ctx.dest_reached_time.tv_nsec) / 1000000;
            if (grace_elapsed > 400) ctx.done = 1; 
        }

        // Printer Loop: High-performance Zero-Lag wait
        pthread_mutex_lock(&ctx.mutex);
        struct timespec wait_time;
        clock_gettime(CLOCK_REALTIME, &wait_time); 
        wait_time.tv_nsec += 1000000; // 1ms sleep interval for micro-latency updates
        if (wait_time.tv_nsec >= 1000000000) {
            wait_time.tv_sec++;
            wait_time.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&ctx.cond, &ctx.mutex, &wait_time);

        while (last_printed < ctx.target_ttl) {
            int h = last_printed + 1;
            int ready = 0;
            
            if (all_hops[h].probes_received == config->num_probes) {
                ready = 1;
            } else {
                int probes_done = 0;
                for (int p = 0; p < config->num_probes; p++) {
                    if (all_hops[h].rtt_ms[p] >= 0) {
                        probes_done++;
                    } else {
                        long p_elapsed = (now.tv_sec - all_hops[h].start_times[p].tv_sec) * 1000 + 
                                         (now.tv_nsec - all_hops[h].start_times[p].tv_nsec) / 1000000;
                        if (p_elapsed >= 1000 || (ctx.destination_reached && ctx.grace_triggered && 
                            ((now.tv_sec - ctx.dest_reached_time.tv_sec) * 1000 + (now.tv_nsec - ctx.dest_reached_time.tv_nsec) / 1000000 > 250))) 
                            probes_done++; 
                    }
                }
                if (probes_done == config->num_probes) ready = 1;
            }

            if (ready) {
                if (all_hops[h].reached && config->layer2_enabled && config->use_arp && sock_l2 >= 0) {
                    if (h == 1 || config->repeat) {
                        pthread_mutex_unlock(&ctx.mutex);
                        uint32_t l2_ip = 0;
                        for (int p = 0; p < config->num_probes; p++) if (all_hops[h].ip_addr[p]) l2_ip = all_hops[h].ip_addr[p];
                        if (l2_ip && resolve_mac_l2(sock_l2, l2_ip, all_hops[h].mac_addr, config, interface) == 0) {
                            all_hops[h].has_mac = 1;
                        }
                        pthread_mutex_lock(&ctx.mutex);
                    }
                }
                if (ctx.show_animation) printf("\r\033[K"); 
                print_hop(&all_hops[h], config);
                
                last_printed = h;
                if (ctx.destination_reached && h >= ctx.target_ttl) {
                    ctx.done = 1;
                    break;
                }
            } else {
                break; 
            }
        }
        pthread_mutex_unlock(&ctx.mutex);
    }

    ctx.done = 1;
    pthread_cond_broadcast(&ctx.cond);
    pthread_join(sender, NULL);
    pthread_join(receiver, NULL);
    if (ctx.show_animation) pthread_join(animation, NULL);
    pthread_mutex_destroy(&ctx.mutex);
    pthread_cond_destroy(&ctx.cond);

    // Final Path Analytics: Router ARP Table Exploration
    if (config->smart_mode && !ctx.destination_reached) {
        uint32_t last_ip = src_ip;
        for (int i = last_printed; i >= 1; i--) {
            if (all_hops[i].reached) {
                for (int p = 0; p < config->num_probes; p++) {
                    if (all_hops[i].ip_addr[p]) {
                        last_ip = all_hops[i].ip_addr[p];
                        break;
                    }
                }
                break;
            }
        }
        if (last_ip != src_ip) {
            printf("\n--- Smart Mode Analysis ---\n");
            query_router_arp_table(last_ip, dst_ip, config);
        }
    } 
    
    // Path Breakdown Summary
    if (!ctx.destination_reached) {
        int last_responding_hop = 0;
        for (int i = 1; i <= MAX_HOPS; i++) {
            if (all_hops[i].reached) last_responding_hop = i;
        }
        
        printf("\n\033[1;31m[!!!] PATH BREAKDOWN DETECTED AFTER HOP %d\033[0m\n", last_responding_hop);
        if (last_responding_hop == 0) {
            printf("Check local connection.");
            if (config->layer2_enabled || config->use_arp || config->smart_mode) {
                printf(" (Note: Bypass flags were active and may have ignored local routing redirects)");
            }
            printf("\n");
        } else {
            printf("The link between Hop %d and Hop %d is failing to pass traffic.\n", last_responding_hop, last_responding_hop + 1);
        }
    }

    if (sock_icmp >= 0) close(sock_icmp);
    if (sock_l2 >= 0) close(sock_l2);
    return 0;
}

/**
 * @brief Resolves target MAC address using Layer 2 ARP probes.
 */
int resolve_mac_l2(int sock_l2, uint32_t target_ip, uint8_t *mac,
                   AutopathConfig *config, const char *interface) {
    if (sock_l2 < 0 || !config || !interface) return -1;
    
    uint8_t packet[MAX_PACKET_SIZE];
    uint8_t local_mac[6];
    uint8_t local_ip[4];

    if (get_local_mac(interface, local_mac) < 0) return -1;

    struct in_addr local_ip_addr;
    if (get_local_ip(interface, &local_ip_addr) < 0) return -1;
    memcpy(local_ip, &local_ip_addr.s_addr, 4);

    uint8_t target_ip_bytes[4];
    memcpy(target_ip_bytes, &target_ip, 4);

    int pkt_len = build_arp_packet(packet, local_mac, local_ip, 
                                   target_ip_bytes, config->broadcast);

    if (config->debug) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &target_ip, ip_str, sizeof(ip_str));
        printf("[DEBUG] Sending ARP request for %s\n", ip_str);
    }

    if (send_raw_l2_packet(sock_l2, packet, pkt_len, interface) < 0) return -1;

    struct timeval timeout = {1, 0};
    uint8_t recv_buffer[MAX_PACKET_SIZE];
    
    int recv_len = receive_response(sock_l2, recv_buffer, sizeof(recv_buffer), &timeout);
    
    if (recv_len <= 0) return -1;

    struct ethhdr *eth = (struct ethhdr *)recv_buffer;
    if (ntohs(eth->h_proto) != ETH_P_ARP) return -1;

    struct arp_header *arp = (struct arp_header *)(recv_buffer + sizeof(struct ethhdr));
    if (ntohs(arp->opcode) == 2) { 
        memcpy(mac, arp->sender_mac, 6);
        return 0;
    }

    return -1;
}

/**
 * @brief Standardized rendering of hop metrics.
 */
void print_hop(HopInfo *hop, AutopathConfig *config) {
    if (hop->hop_num <= 0) return;

    static uint32_t path_history[MAX_HOPS + 1];
    if (hop->hop_num == 1) {
        memset(path_history, 0, sizeof(path_history));
    }

    printf("%2d  ", hop->hop_num);

    if (hop->reached) {
        uint32_t last_ip = 0;
        int is_loop = 0;
        for (int i = 0; i < config->num_probes; i++) {
            if (hop->rtt_ms[i] >= 0) {
                // Visual routing loop detection
                if (hop->hop_num > 2) {
                    for (int h = 1; h < hop->hop_num - 1; h++) {
                        if (path_history[h] && path_history[h] == hop->ip_addr[i] && path_history[h+1] != hop->ip_addr[i]) {
                            is_loop = 1;
                            break;
                        }
                    }
                }

                if (hop->ip_addr[i] != last_ip) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &hop->ip_addr[i], ip_str, sizeof(ip_str));
                    printf("%-15s ", ip_str);
                    last_ip = hop->ip_addr[i];
                    path_history[hop->hop_num] = hop->ip_addr[i];
                }
                printf(" %7.3f ms ", hop->rtt_ms[i]);
            } else {
                printf("      *      ");
            }
        }
        if (is_loop) printf(" \033[1;33m[ROUTING LOOP]\033[0m");
        if (hop->error_msg[0]) printf("  %s", hop->error_msg);
    } else {
        for (int i = 0; i < config->num_probes; i++) printf("       *      ");
        if (hop->error_msg[0]) printf("  %s", hop->error_msg);
    }
    printf("\n");
}

int smart_mode_query(uint32_t router_ip, uint32_t target_ip, 
                     AutopathConfig *config) {
    return query_router_arp_table(router_ip, target_ip, config);
}
