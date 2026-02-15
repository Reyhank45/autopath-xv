#include "netutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

int get_local_mac(const char *interface, uint8_t *mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

int get_local_ip(const char *interface, struct in_addr *ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sock);
        return -1;
    }

    memcpy(ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(struct in_addr));
    close(sock);
    return 0;
}

int get_local_netmask(const char *interface, struct in_addr *mask) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl SIOCGIFNETMASK");
        close(sock);
        return -1;
    }

    memcpy(mask, &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr, sizeof(struct in_addr));
    close(sock);
    return 0;
}

int is_same_subnet(uint32_t ip1, uint32_t ip2, uint32_t mask) {
    return (ip1 & mask) == (ip2 & mask);
}

int build_arp_packet(uint8_t *buffer, const uint8_t *src_mac, 
                     const uint8_t *src_ip, const uint8_t *target_ip,
                     int is_broadcast) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ethhdr));

    // Ethernet header
    memcpy(eth->h_source, src_mac, 6);
    if (is_broadcast) {
        memset(eth->h_dest, 0xff, 6);
    } else {
        memset(eth->h_dest, 0x00, 6); // Unknown target
    }
    eth->h_proto = htons(ETH_P_ARP);

    // ARP header
    arp->hw_type = htons(1);        // Ethernet
    arp->proto_type = htons(0x0800); // IPv4
    arp->hw_addr_len = 6;
    arp->proto_addr_len = 4;
    arp->opcode = htons(1);          // ARP Request

    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_mac, 0x00, 6);
    memcpy(arp->target_ip, target_ip, 4);

    return sizeof(struct ethhdr) + sizeof(struct arp_header);
}

uint16_t calculate_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (uint16_t)(~sum);
}

int build_icmp_packet(uint8_t *buffer, uint16_t id, uint16_t seq, 
                      uint32_t src_ip, uint32_t dst_ip, uint8_t ttl) {
    struct ip_header *ip = (struct ip_header *)buffer;
    struct icmp_header *icmp = (struct icmp_header *)(buffer + sizeof(struct ip_header));
    
    // IP header
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(sizeof(struct ip_header) + sizeof(struct icmp_header));
    ip->id = htons(getpid() & 0xFFFF);
    ip->flags_offset = 0;
    ip->ttl = ttl;
    ip->protocol = IPPROTO_ICMP;
    ip->checksum = 0;
    ip->src_addr = src_ip;
    ip->dst_addr = dst_ip;
    ip->checksum = calculate_checksum((uint16_t *)ip, sizeof(struct ip_header));
    
    // ICMP header
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(seq);
    icmp->checksum = calculate_checksum((uint16_t *)icmp, sizeof(struct icmp_header));
    
    return sizeof(struct ip_header) + sizeof(struct icmp_header);
}

int build_icmp_only(uint8_t *buffer, uint16_t id, uint16_t seq) {
    struct icmp_header *icmp = (struct icmp_header *)buffer;
    
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(seq);
    icmp->checksum = calculate_checksum((uint16_t *)icmp, sizeof(struct icmp_header));
    
    return sizeof(struct icmp_header);
}

int build_udp_packet(uint8_t *buffer, uint32_t src_ip, uint32_t dst_ip, 
                     uint16_t src_port, uint16_t dst_port, uint8_t ttl) {
    struct ip_header *ip = (struct ip_header *)buffer;
    struct {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    } *udp = (void *)(buffer + sizeof(struct ip_header));

    // IP header
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(60); // Standard traceroute size
    ip->id = htons(getpid() & 0xFFFF);
    ip->flags_offset = 0;
    ip->ttl = ttl;
    ip->protocol = IPPROTO_UDP;
    ip->checksum = 0;
    ip->src_addr = src_ip;
    ip->dst_addr = dst_ip;
    ip->checksum = calculate_checksum((uint16_t *)ip, sizeof(struct ip_header));

    // UDP header
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(60 - sizeof(struct ip_header));
    udp->check = 0;
    
    // Optional: Fill payload with zeros/data
    memset(buffer + sizeof(struct ip_header) + 8, 0x42, 60 - sizeof(struct ip_header) - 8);

    return 60;
}

void mac_to_string(const uint8_t *mac, char *str) {
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_to_string(uint32_t ip, char *str) {
    struct in_addr addr;
    addr.s_addr = ip;
    strcpy(str, inet_ntoa(addr));
}

int parse_ip(const char *ip_str, uint8_t *ip_bytes) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    memcpy(ip_bytes, &addr.s_addr, 4);
    return 0;
}

int create_raw_socket_l2(const char *interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket AF_PACKET");
        return -1;
    }

    // Bind to specific interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind AF_PACKET");
        close(sock);
        return -1;
    }

    return sock;
}

int create_raw_socket_icmp(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket ICMP");
        return -1;
    }

    // Set IP_HDRINCL to include custom IP header for per-packet TTL precision
    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return -1;
    }

    return sock;
}

int send_raw_l2_packet(int sock, const uint8_t *packet, size_t len, 
                       const char *interface) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        return -1;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = ETH_ALEN;
    
    if (sendto(sock, packet, len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}

int receive_response(int sock, uint8_t *buffer, size_t len, 
                     struct timeval *timeout) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    int ret = select(sock + 1, &readfds, NULL, NULL, timeout);
    if (ret < 0) {
        perror("select");
        return -1;
    } else if (ret == 0) {
        return 0; // Timeout
    }

    ssize_t recv_len = recvfrom(sock, buffer, len, 0, NULL, NULL);
    if (recv_len < 0) {
        perror("recvfrom");
        return -1;
    }

    return recv_len;
}

int get_default_interface(char *iface, size_t len) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) {
        perror("fopen /proc/net/route");
        return -1;
    }

    char line[256];
    char iface_name[16];
    unsigned long dest, gateway, flags, mask;
    int found = 0;

    // Skip header line
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }

    // Find default route (destination = 00000000)
    while (fgets(line, sizeof(line), fp)) {
        int matches = sscanf(line, "%15s %lx %lx %lx %*d %*d %*d %lx",
                           iface_name, &dest, &gateway, &flags, &mask);
        
        if (matches >= 4 && dest == 0) {
            // Found default route
            strncpy(iface, iface_name, len - 1);
            iface[len - 1] = '\0';
            found = 1;
            break;
        }
    }

    fclose(fp);
    
    if (!found) {
        // Fallback: try to find any active interface
        fp = fopen("/proc/net/dev", "r");
        if (fp) {
            // Skip first two header lines
            fgets(line, sizeof(line), fp);
            fgets(line, sizeof(line), fp);
            
            while (fgets(line, sizeof(line), fp)) {
                char *colon = strchr(line, ':');
                if (colon) {
                    char *name_start = line;
                    while (*name_start == ' ' || *name_start == '\t') name_start++;
                    
                    size_t name_len = colon - name_start;
                    if (name_len > 0 && name_len < len) {
                        strncpy(iface_name, name_start, name_len);
                        iface_name[name_len] = '\0';
                        
                        // Skip loopback
                        if (strcmp(iface_name, "lo") != 0) {
                            strncpy(iface, iface_name, len - 1);
                            iface[len - 1] = '\0';
                            found = 1;
                            break;
                        }
                    }
                }
            }
            fclose(fp);
        }
    }

    return found ? 0 : -1;
}

