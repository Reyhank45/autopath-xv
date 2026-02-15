#ifndef SNMP_QUERY_H
#define SNMP_QUERY_H

#include <stdint.h>
#include "config.h"

/**
 * Query router ARP table via SNMP
 * Returns 0 on success, -1 on failure
 */
int query_router_arp_table(uint32_t router_ip, uint32_t target_ip, 
                           AutopathConfig *config);

/**
 * Initialize SNMP library
 */
int snmp_init(void);

/**
 * Cleanup SNMP library
 */
void snmp_cleanup(void);

#endif // SNMP_QUERY_H
