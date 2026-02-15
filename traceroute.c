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

// Animation thread function for a high-speed, full-width "Laser Bouncer"
void *animation_thread_func(void *arg) {
    ThreadContext *ctx = (ThreadContext *)arg;
    struct winsize w;
    int col_width = 80; // Default
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
        
        usleep(8000); // 8ms - Ultra Smooth 125FPS
    }
    
    pthread_mutex_lock(&ctx->mutex);
    printf("\r\033[K");
    fflush(stdout);
    pthread_mutex_unlock(&ctx->mutex);
    return NULL;
}

// Thread function for sending probes
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
                // For UDP, we vary destination port for entropy 33434 + seq
                dest_addr.sin_port = htons(33434 + seq);
                pkt_len = build_udp_packet(packet, ctx->src_ip, ctx->dst_ip, 
                                          33434 + probe, 33434 + seq, ttl);
            } else {
                pkt_len = build_icmp_packet(packet, probe_id, seq, ctx->src_ip, ctx->dst_ip, ttl);
            }
            
            clock_gettime(CLOCK_MONOTONIC, &ctx->all_hops[ttl].start_times[probe]);
            
            if (sendto(ctx->sock_icmp, packet, pkt_len, 0, 
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            }
            // Controlled Stagger: 500us to balance speed and router response
            usleep(500); 
        }
    }
    return NULL;
}

// Thread function for receiving responses
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
                    // Extract original packet from ICMP quote
                    struct iphdr *orig_ip = (struct iphdr *)(recv_buffer + ip_hdr_len + 8);
                    int orig_ip_hdr_len = orig_ip->ihl * 4;
                    
                    if (is_udp) {
                        // Original UDP header is right after encapsulated IP header
                        uint16_t *orig_udp_ports = (uint16_t *)((uint8_t *)orig_ip + orig_ip_hdr_len);
                        // The sequence number was stored in the Destination Port (33434 + seq)
                        resp_seq = ntohs(orig_udp_ports[1]) - 33434;
                        // Probe ID logic for UDP relies on ports, but for now we skip ID match for UDP 
                        // as Port Range is our verification
                        resp_id = ctx->id + (ntohs(orig_udp_ports[0]) - 33434);
                    } else {
                        struct icmphdr *orig_icmp = (struct icmphdr *)((uint8_t *)orig_ip + orig_ip_hdr_len);
                        resp_seq = ntohs(orig_icmp->un.echo.sequence);
                        resp_id = ntohs(orig_icmp->un.echo.id);
                    }
                } else {
                    continue;
                }

                // Verify ID against our probe range (probe ID was varied [id, id+probes])
                if (resp_id < ctx->id || resp_id >= ctx->id + ctx->config->num_probes) continue;

                int h_idx = (resp_seq >> 8) & 0xFF;
                int p_idx = resp_seq & 0xFF;

                if (h_idx >= 1 && h_idx <= MAX_HOPS && p_idx >= 0 && p_idx < ctx->config->num_probes) {
                    pthread_mutex_lock(&ctx->mutex);
                    if (ctx->all_hops[h_idx].rtt_ms[p_idx] < 0) {
                        HopInfo temp_hop;
                        memset(&temp_hop, 0, sizeof(temp_hop));
                        
                        // Parse logic: Extract Source IP from ICMP error
                        temp_hop.ip_addr[0] = ip->saddr;
                        
                        double rtt = (end_time.tv_sec - ctx->all_hops[h_idx].start_times[p_idx].tv_sec) * 1000.0 +
                                     (end_time.tv_nsec - ctx->all_hops[h_idx].start_times[p_idx].tv_nsec) / 1000000.0;
                        
                        ctx->all_hops[h_idx].rtt_ms[p_idx] = rtt;
                        ctx->all_hops[h_idx].probes_received++;
                        ctx->all_hops[h_idx].ip_addr[p_idx] = ip->saddr;
                        ctx->all_hops[h_idx].reached = 1;
                        
                        // Check if this IP is the destination (Protocol Agnostic)
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
                        // Signal printer to wakeup instantly
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

    int sock_icmp = create_raw_socket_icmp();
    if (sock_icmp < 0) {
        fprintf(stderr, "Failed to create ICMP socket (need root/CAP_NET_RAW)\n");
        return -1;
    }
    
    // Set to non-blocking
    int flags = fcntl(sock_icmp, F_GETFL, 0);
    fcntl(sock_icmp, F_SETFL, flags | O_NONBLOCK);

    int sock_l2 = -1;
    if (config->layer2_enabled || config->use_arp) {
        sock_l2 = create_raw_socket_l2(interface);
    }

    // Optimization: Check for local subnet
    int is_local = 0;
    struct in_addr netmask;
    if (get_local_netmask(interface, &netmask) == 0) {
        if (is_same_subnet(src_ip, dst_ip, netmask.s_addr)) {
            is_local = 1;
        }
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
    ctx.show_animation = !config->debug; // Don't show if debug is on
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
            if (grace_elapsed > 400) ctx.done = 1; // 400ms grace for sub-0.6s performance
        }

        // Printer Loop: Zero-Lag Wait
        pthread_mutex_lock(&ctx.mutex);
        struct timespec wait_time;
        clock_gettime(CLOCK_REALTIME, &wait_time); 
        wait_time.tv_nsec += 1000000; // 1ms for micro-latency
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
                        // Use last valid IP for L2 resolution
                        uint32_t l2_ip = 0;
                        for (int p = 0; p < config->num_probes; p++) if (all_hops[h].ip_addr[p]) l2_ip = all_hops[h].ip_addr[p];
                        if (l2_ip && resolve_mac_l2(sock_l2, l2_ip, all_hops[h].mac_addr, config, interface) == 0) {
                            all_hops[h].has_mac = 1;
                        }
                        pthread_mutex_lock(&ctx.mutex);
                    }
                }
                if (ctx.show_animation) printf("\r\033[K"); // Instant clear
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
    pthread_cond_broadcast(&ctx.cond); // Wake up everyone for cleanup
    pthread_join(sender, NULL);
    pthread_join(receiver, NULL);
    if (ctx.show_animation) pthread_join(animation, NULL);
    pthread_mutex_destroy(&ctx.mutex);
    pthread_cond_destroy(&ctx.cond);

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

    if (sock_icmp >= 0) close(sock_icmp);
    if (sock_l2 >= 0) close(sock_l2);
    return 0;
}

int resolve_mac_l2(int sock_l2, uint32_t target_ip, uint8_t *mac,
                   AutopathConfig *config, const char *interface) {
    if (sock_l2 < 0 || !config || !interface) return -1;
    
    uint8_t packet[MAX_PACKET_SIZE];
    uint8_t local_mac[6];
    uint8_t local_ip[4];

    // Get local MAC and IP
    if (get_local_mac(interface, local_mac) < 0) {
        return -1;
    }

    struct in_addr local_ip_addr;
    if (get_local_ip(interface, &local_ip_addr) < 0) {
        return -1;
    }
    memcpy(local_ip, &local_ip_addr.s_addr, 4);

    uint8_t target_ip_bytes[4];
    memcpy(target_ip_bytes, &target_ip, 4);

    // Build ARP packet
    int pkt_len = build_arp_packet(packet, local_mac, local_ip, 
                                   target_ip_bytes, config->broadcast);

    if (config->debug) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &target_ip, ip_str, sizeof(ip_str));
        printf("[DEBUG] Sending ARP request for %s\n", ip_str);
    }

    // Send ARP request
    if (send_raw_l2_packet(sock_l2, packet, pkt_len, interface) < 0) {
        return -1;
    }

    // Wait for ARP reply
    struct timeval timeout = {1, 0};
    uint8_t recv_buffer[MAX_PACKET_SIZE];
    
    int recv_len = receive_response(sock_l2, recv_buffer, sizeof(recv_buffer), &timeout);
    
    if (recv_len <= 0) {
        return -1; // Timeout
    }

    // Parse ARP reply
    struct ethhdr *eth = (struct ethhdr *)recv_buffer;
    if (ntohs(eth->h_proto) != ETH_P_ARP) {
        return -1;
    }

    struct arp_header *arp = (struct arp_header *)(recv_buffer + sizeof(struct ethhdr));
    if (ntohs(arp->opcode) == 2) { // ARP Reply
        memcpy(mac, arp->sender_mac, 6);
        return 0;
    }

    return -1;
}

int parse_icmp_response(uint8_t *buffer, int len, uint16_t id, HopInfo *hop) {
    struct iphdr *ip = (struct iphdr *)buffer;
    int ip_hdr_len = ip->ihl * 4;
    
    if (len < ip_hdr_len + 8) return -1;

    struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_hdr_len);
    
    if (icmp->type == ICMP_TIME_EXCEEDED) {
        hop->ip_addr[0] = ip->saddr;
        return 1;
    }
    
    if (icmp->type == ICMP_ECHOREPLY) {
        hop->ip_addr[0] = ip->saddr;
        return 1;
    }

    if (icmp->type == ICMP_DEST_UNREACH) {
        hop->ip_addr[0] = ip->saddr;
        snprintf(hop->error_msg, sizeof(hop->error_msg), "Unreachable (%d)", icmp->code);
        return 1;
    }

    (void)id; // ID verification now handled in receiver thread
    return 0;
}

void print_hop(HopInfo *hop, AutopathConfig *config) {
    if (hop->hop_num <= 0) return;
    printf("%2d  ", hop->hop_num);

    if (hop->reached) {
        uint32_t last_ip = 0;
        for (int i = 0; i < config->num_probes; i++) {
            if (hop->rtt_ms[i] >= 0) {
                if (hop->ip_addr[i] != last_ip) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &hop->ip_addr[i], ip_str, sizeof(ip_str));
                    printf("%-15s ", ip_str);
                    last_ip = hop->ip_addr[i];
                }
                printf(" %7.3f ms ", hop->rtt_ms[i]);
            } else {
                printf("      *      ");
            }
        }
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
