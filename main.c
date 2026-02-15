/**
 * @file main.c
 * @brief Entry point for autopath-xv advanced network discovery tool.
 * 
 * autopath-xv is a high-performance network diagnostic tool that bridges 
 * the gap between Layer 3 traceroute and Layer 2 link-layer analysis.
 * It is designed for sub-second, network-latency-bound execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "traceroute.h"
#include "netutils.h"

#define VERSION "1.0.0"

/**
 * @brief Print command-line usage information.
 */
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] -ipv4 <target_ip>\n\n", prog_name);
    printf("autopath-xv - Advanced network path discovery tool\n");
    printf("Combines Layer 3 traceroute with Layer 2 MAC-level path tracing\n\n");
    
    printf("OPTIONS:\n");
    printf("  -ipv4 <ip>    Target IPv4 address to trace (REQUIRED)\n");
    printf("  -q <n>        Number of probes per hop (default: 3)\n");
    printf("  -a            Use ARP for Layer 2 MAC resolution\n");
    printf("  -l2           Enable Layer 2 probing\n");
    printf("  -b            Use broadcast for ARP requests\n");
    printf("  -xv           Smart advanced mode (query router ARP tables)\n");
    printf("  -r            Repeat on timeout (without: stop on path invalid)\n");
    printf("  -u            Use UDP probes instead of ICMP Echo (matches standard traceroute)\n");
    printf("  -d            Enable debug output\n");
    printf("  -i <iface>    Network interface to use (default: auto-detect)\n");
    printf("  --help, -help Display this help message\n");
    printf("  --version     Display version information\n\n");
    
    printf("EXAMPLES:\n");
    printf("  # Basic traceroute to target (1s race)\n");
    printf("  %s -ipv4 8.8.8.8\n\n", prog_name);
    
    printf("  # High-speed single-probe trace (matched to standard traceroute)\n");
    printf("  %s -q 1 -ipv4 8.8.8.8\n\n", prog_name);
    
    printf("  # Traceroute with Layer 2 MAC discovery\n");
    printf("  %s -a -l2 -ipv4 10.0.0.1\n\n", prog_name);
    
    printf("NOTES:\n");
    printf("  - Requires root privileges or CAP_NET_RAW capability\n");
    printf("  - Smart mode (-xv) will attempt SNMP queries to routers\n");
    printf("  - Layer 2 mode shows MAC addresses at each hop\n\n");
    
    printf("Report bugs to: https://github.com/reyhank45/autopath-xv\n");
}

void print_version(void) {
    printf("autopath-xv version %s\n", VERSION);
    printf("Advanced network path discovery tool\n");
    printf("Copyright (C) 2026 - Licensed under GPL v3\n");
}

int main(int argc, char *argv[]) {
    AutopathConfig config = {0};
    config.num_probes = 3; // Default
    char interface[16] = "";
    int interface_specified = 0;
    
    // Check for no arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Command line argument parser
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        }
        if (strcmp(argv[i], "-a") == 0) {
            config.use_arp = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            config.debug = 1;
        } else if (strcmp(argv[i], "-b") == 0) {
            config.broadcast = 1;
        } else if (strcmp(argv[i], "-xv") == 0) {
            config.smart_mode = 1;
        } else if (strcmp(argv[i], "-l2") == 0) {
            config.layer2_enabled = 1;
        } else if (strcmp(argv[i], "-r") == 0) {
            config.repeat = 1;
        } else if (strcmp(argv[i], "-u") == 0) {
            config.use_udp = 1;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            config.num_probes = atoi(argv[++i]);
            if (config.num_probes < 1) config.num_probes = 1;
            if (config.num_probes > 10) config.num_probes = 10;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            strncpy(interface, argv[++i], 15);
            interface[15] = '\0';
            interface_specified = 1;
        } else if (strcmp(argv[i], "-ipv4") == 0 && i + 1 < argc) {
            strncpy(config.target_ip, argv[++i], 15);
            config.target_ip[15] = '\0';
        }
    }

    // Target IP is the only strictly required parameter
    if (config.target_ip[0] == '\0') {
        fprintf(stderr, "Error: Target IP address is required (-ipv4 <ip>)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // Path Audit: Auto-detection of network interfaces and reachability check
    char interfaces[16][16];
    int iface_count = 0;
    char target_iface[16] = "";

    if (!interface_specified) {
        iface_count = get_all_interfaces(interfaces, 16);
        if (iface_count <= 0) {
            fprintf(stderr, "Error: No network interfaces detected.\n");
            return 1;
        }

        char system_default[16] = "";
        get_default_interface(system_default, sizeof(system_default));

        printf(" \033[1;36m[*]\033[0m Path Audit: Probing %d candidate interfaces...\n", iface_count);
        
        for (int i = 0; i < iface_count; i++) {
            int is_default = (system_default[0] != '\0' && strcmp(interfaces[i], system_default) == 0);
            
            // Explicitly flag and bypass loopback traps (local routing redirects)
            if (strcmp(interfaces[i], "lo") == 0) {
                printf("  \033[1;31m[!]\033[0m Interface lo: \033[1;31mFAILED\033[0m (Loopback trap/redirect detected");
                if (is_default) printf(" - \033[1;31mSYSTEM DEFAULT\033[0m");
                printf(")\n");
                continue;
            }

            // Test hardware interface by attempting to open a raw socket
            int test_sock = create_raw_socket_icmp(interfaces[i]);
            if (test_sock < 0) {
                printf("  \033[1;31m[!]\033[0m Interface %s: \033[1;31mFAILED\033[0m (Socket creation failed", interfaces[i]);
                if (is_default) printf(" - \033[1;31mSYSTEM DEFAULT\033[0m");
                printf(")\n");
                continue;
            }
            close(test_sock);

            printf("  \033[1;32m[+]\033[0m Interface %s: \033[1;32mSUCCESS\033[0m (Hardware path active", interfaces[i]);
            if (is_default) printf(" - \033[1;32mSYSTEM DEFAULT\033[0m");
            printf(")\n");

            // Select the first working hardware interface if one isn't specified
            if (target_iface[0] == '\0') {
                strncpy(target_iface, interfaces[i], sizeof(target_iface) - 1);
                target_iface[sizeof(target_iface) - 1] = '\0';
            }
        }
        
        if (target_iface[0] == '\0') {
             fprintf(stderr, "\nError: All probed interfaces failed. No path to destination found.\n");
             return 1;
        }
        printf(" \033[1;36m[*]\033[0m Using \033[1;32m%s\033[0m for trace.\n", target_iface);
    } else {
        snprintf(target_iface, sizeof(target_iface), "%s", interface);
    }

    // Privilege check: Raw socket operations require CAP_NET_RAW or root
    if (geteuid() != 0) {
        fprintf(stderr, "\nWarning: This program requires root privileges or CAP_NET_RAW capability\n");
        fprintf(stderr, "Try: sudo %s or sudo setcap cap_net_raw+ep %s\n\n", argv[0], argv[0]);
    }

    if (config.debug) {
        printf("[DEBUG] Starting autopath-xv v%s\n", VERSION);
        printf("[DEBUG] Interface: %s\n", target_iface);
        printf("[DEBUG] Target: %s\n", config.target_ip);
    }
    
    // Execute the core traceroute engine
    int result = run_traceroute(&config, target_iface);
    
    if (result < 0) {
        fprintf(stderr, "Traceroute failed\n");
        return 1;
    }

    return 0;
}