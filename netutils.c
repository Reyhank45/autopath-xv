/**
 * @file netutils.c
 * @brief Network utility functions for raw socket management and packet construction.
 */

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

/**
 * @brief Retrieves the hardware MAC address for a given interface.
 */
int get_local_mac(const char *interface, uint8_t *mac) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

/**
 * @brief Retrieves the local IPv4 address for a given interface.
 */
int get_local_ip(const char *interface, struct in_addr *ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return -1;
    }

    memcpy(ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(struct in_addr));
    close(sock);
    return 0;
}

/**
 * @brief Retrieves the netmask for a given interface.
 */
int get_local_netmask(const char *interface, struct in_addr *mask) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
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

/**
 * @brief Constructs a raw ARP packet.
 */
int build_arp_packet(uint8_t *buffer, const uint8_t *src_mac, 
                      const uint8_t *src_ip, const uint8_t *target_ip,
                      int is_broadcast) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ethhdr));

    memcpy(eth->h_source, src_mac, 6);
    if (is_broadcast) {
        memset(eth->h_dest, 0xff, 6);
    } else {
        memset(eth->h_dest, 0x00, 6); 
    }
    eth->h_proto = htons(ETH_P_ARP);

    arp->hw_type = htons(1);        
    arp->proto_type = htons(0x0800); 
    arp->hw_addr_len = 6;
    arp->proto_addr_len = 4;
    arp->opcode = htons(1);          

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
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/**
 * @brief Constructs a full ICMP Echo packet with custom IP header.
 */
int build_icmp_packet(uint8_t *buffer, uint16_t id, uint16_t seq, 
                      uint32_t src_ip, uint32_t dst_ip, uint8_t ttl) {
    struct ip_header *ip = (struct ip_header *)buffer;
    struct icmp_header *icmp = (struct icmp_header *)(buffer + sizeof(struct ip_header));
    
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
    
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = htons(id);
    icmp->sequence = htons(seq);
    icmp->checksum = calculate_checksum((uint16_t *)icmp, sizeof(struct icmp_header));
    
    return sizeof(struct ip_header) + sizeof(struct icmp_header);
}

/**
 * @brief Constructs a standard UDP traceroute probe.
 */
int build_udp_packet(uint8_t *buffer, uint32_t src_ip, uint32_t dst_ip, 
                      uint16_t src_port, uint16_t dst_port, uint8_t ttl) {
    struct ip_header *ip = (struct ip_header *)buffer;
    struct {
        uint16_t source;
        uint16_t dest;
        uint16_t len;
        uint16_t check;
    } *udp = (void *)(buffer + sizeof(struct ip_header));

    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(60); 
    ip->id = htons(getpid() & 0xFFFF);
    ip->flags_offset = 0;
    ip->ttl = ttl;
    ip->protocol = IPPROTO_UDP;
    ip->checksum = 0;
    ip->src_addr = src_ip;
    ip->dst_addr = dst_ip;
    ip->checksum = calculate_checksum((uint16_t *)ip, sizeof(struct ip_header));

    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(60 - sizeof(struct ip_header));
    udp->check = 0;
    
    memset(buffer + sizeof(struct ip_header) + 8, 0x42, 60 - sizeof(struct ip_header) - 8);
    return 60;
}

/**
 * @brief Creates a Layer 2 raw packet socket bound to a specific interface.
 */
int create_raw_socket_l2(const char *interface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * @brief Creates a raw ICMP socket with IP_HDRINCL for precise TTL control.
 */
int create_raw_socket_icmp(const char *interface) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return -1;

    if (interface) {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
            close(sock);
            return -1;
        }
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
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
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) return -1;

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = ETH_ALEN;
    
    if (sendto(sock, packet, len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;
    return 0;
}

int receive_response(int sock, uint8_t *buffer, size_t len, 
                      struct timeval *timeout) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    int ret = select(sock + 1, &readfds, NULL, NULL, timeout);
    if (ret <= 0) return ret; 

    ssize_t recv_len = recvfrom(sock, buffer, len, 0, NULL, NULL);
    return (int)recv_len;
}

/**
 * @brief Identifies the system's preferred default route interface.
 * Prioritizes physical hardware over virtual/loopback interfaces.
 */
int get_default_interface(char *iface, size_t len) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return -1;

    char line[256];
    char iface_name[16];
    unsigned long dest, gateway, flags, mask;
    int found = 0;

    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }

    char fallback_iface[16] = "";
    while (fgets(line, sizeof(line), fp)) {
        int matches = sscanf(line, "%15s %lx %lx %lx %*d %*d %*d %lx",
                           iface_name, &dest, &gateway, &flags, &mask);
        
        if (matches >= 4 && dest == 0) {
            if (strcmp(iface_name, "lo") == 0) {
                if (fallback_iface[0] == '\0') strcpy(fallback_iface, iface_name);
                continue; 
            }
            strncpy(iface, iface_name, len - 1);
            iface[len - 1] = '\0';
            found = 1;
            break;
        }
    }

    if (!found && fallback_iface[0] != '\0') {
        strncpy(iface, fallback_iface, len - 1);
        iface[len - 1] = '\0';
        found = 1;
    }

    fclose(fp);
    return found ? 0 : -1;
}

/**
 * @brief Enumerates all active network interfaces for Path Auditing.
 * Returns a list prioritized by hardware vs loopback status.
 */
int get_all_interfaces(char interfaces[][16], int max_ifaces) {
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp) return -1;

    char line[256];
    int count = 0;
    int has_lo = 0;

    fgets(line, sizeof(line), fp);
    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp) && count < max_ifaces) {
        char *colon = strchr(line, ':');
        if (colon) {
            char *name_start = line;
            while (*name_start == ' ' || *name_start == '\t') name_start++;
            
            size_t name_len = colon - name_start;
            if (name_len > 0 && name_len < 16) {
                char ifname[16];
                strncpy(ifname, name_start, name_len);
                ifname[name_len] = '\0';
                
                if (strcmp(ifname, "lo") == 0) {
                    has_lo = 1;
                    continue; 
                }

                snprintf(interfaces[count], 16, "%s", ifname);
                count++;
            }
        }
    }

    if (has_lo && count < max_ifaces) {
        strcpy(interfaces[count], "lo");
        count++;
    }

    fclose(fp);
    return count;
}

