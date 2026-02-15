#ifndef CONFIG_H
#define CONFIG_H

// Structure for the autopath-xv configuration
typedef struct {
    int use_arp;
    int debug;
    int broadcast;
    int smart_mode;
    int layer2_enabled;
    int repeat;
    int num_probes;
    int use_udp;
    char target_ip[16];
} AutopathConfig;

#endif // CONFIG_H
