#ifndef NETUTILS_H
#define NETUTILS_H

#include <stdint.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>

#define MAX_PACKET_SIZE 1514
#define ARP_PACKET_SIZE 42
#define ICMP_PACKET_SIZE 64

// ARP header structure
struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_addr_len;
    uint8_t proto_addr_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} __attribute__((packed));

// ICMP header structure
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

// IP header structure (simplified)
struct ip_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed));

// Network utility functions

/**
 * Get the MAC address of a network interface
 */
int get_local_mac(const char *interface, uint8_t *mac);

/**
 * Get the IP address of a network interface
 */
int get_local_ip(const char *interface, struct in_addr *ip);

/**
 * Build an ARP request packet
 */
int build_arp_packet(uint8_t *buffer, const uint8_t *src_mac, 
                     const uint8_t *src_ip, const uint8_t *target_ip,
                     int is_broadcast);

/**
 * Build an ICMP echo request packet
 */
int build_icmp_packet(uint8_t *buffer, uint16_t id, uint16_t seq, 
                      uint32_t src_ip, uint32_t dst_ip, uint8_t ttl);

/**
 * Build an ICMP echo request packet (ICMP header only)
 */
int build_icmp_only(uint8_t *buffer, uint16_t id, uint16_t seq);

/**
 * Calculate IP/ICMP checksum
 */
uint16_t calculate_checksum(uint16_t *buf, int len);

/**
 * Convert MAC address to string
 */
void mac_to_string(const uint8_t *mac, char *str);

/**
 * Convert IP address to string
 */
void ip_to_string(uint32_t ip, char *str);

/**
 * Parse IP address string to bytes
 */
int parse_ip(const char *ip_str, uint8_t *ip_bytes);

/**
 * Create and configure a raw socket for Layer 2
 */
int create_raw_socket_l2(const char *interface);

/**
 * Create and configure a raw socket for ICMP
 */
int create_raw_socket_icmp(void);

/**
 * Send a raw packet through Layer 2 socket
 */
int send_raw_l2_packet(int sock, const uint8_t *packet, size_t len, 
                       const char *interface);

/**
 * Receive and parse response with timeout
 */
int receive_response(int sock, uint8_t *buffer, size_t len, 
                     struct timeval *timeout);

/**
 * Get the netmask of a network interface
 */
int get_local_netmask(const char *interface, struct in_addr *mask);

/**
 * Check if two IP addresses are on the same subnet
 */
int is_same_subnet(uint32_t ip1, uint32_t ip2, uint32_t mask);

/**
 * Get the default network interface (one with default gateway)
 */
int get_default_interface(char *iface, size_t len);

/**
 * Build a UDP packet inside an IP packet
 */
int build_udp_packet(uint8_t *buffer, uint32_t src_ip, uint32_t dst_ip, 
                     uint16_t src_port, uint16_t dst_port, uint8_t ttl);

#endif // NETUTILS_H
