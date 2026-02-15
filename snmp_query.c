#include "snmp_query.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef HAVE_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

int snmp_init(void) {
    init_snmp("autopath-xv");
    return 0;
}

void snmp_cleanup(void) {
    snmp_shutdown("autopath-xv");
}

int query_router_arp_table(uint32_t router_ip, uint32_t target_ip, 
                           AutopathConfig *config) {
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    
    char router_str[INET_ADDRSTRLEN];
    char target_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &router_ip, router_str, sizeof(router_str));
    inet_ntop(AF_INET, &target_ip, target_str, sizeof(target_str));
    
    if (config->debug) {
        printf("[DEBUG] SNMP query to %s for ARP entry of %s\n", 
               router_str, target_str);
    }
    
    // Initialize session
    snmp_sess_init(&session);
    session.peername = router_str;
    session.version = SNMP_VERSION_2c;
    session.community = (unsigned char *)"public";
    session.community_len = strlen((const char *)session.community);
    
    // Open session
    SOCK_STARTUP;
    ss = snmp_open(&session);
    
    if (!ss) {
        snmp_perror("snmp_open");
        SOCK_CLEANUP;
        return -1;
    }
    
    // Create PDU for GET request
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    
    // OID for ipNetToMediaTable (ARP table)
    // 1.3.6.1.2.1.4.22.1 = ipNetToMediaTable
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    
    // Start with ipNetToMediaTable OID
    if (!read_objid("1.3.6.1.2.1.4.22.1.2", anOID, &anOID_len)) {
        fprintf(stderr, "Error parsing OID\n");
        snmp_close(ss);
        SOCK_CLEANUP;
        return -1;
    }
    
    snmp_add_null_var(pdu, anOID, anOID_len);
    
    // Send request and get response
    int status = snmp_synch_response(ss, pdu, &response);
    
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        struct variable_list *vars;
        
        printf("   [SMART] ARP table from %s:\\n", router_str);
        
        for (vars = response->variables; vars; vars = vars->next_variable) {
            if (vars->type == ASN_OCTET_STR) {
                // This is the MAC address
                unsigned char *mac = vars->val.string;
                if (vars->val_len == 6) {
                    printf("   [SMART]   MAC: %02x:%02x:%02x:%02x:%02x:%02x\\n",
                           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                }
            }
        }
        
        if (response) {
            snmp_free_pdu(response);
        }
        
        snmp_close(ss);
        SOCK_CLEANUP;
        return 0;
    } else {
        if (status == STAT_SUCCESS) {
            fprintf(stderr, "SNMP Error: %s\n", 
                    snmp_errstring(response->errstat));
        } else {
            snmp_sess_perror("snmpget", ss);
        }
        
        if (response) {
            snmp_free_pdu(response);
        }
        
        snmp_close(ss);
        SOCK_CLEANUP;
        return -1;
    }
}

#else
// Stub implementation when SNMP is not available

int snmp_init(void) {
    return 0;
}

void snmp_cleanup(void) {
    // Nothing to do
}

int query_router_arp_table(uint32_t router_ip, uint32_t target_ip, 
                           AutopathConfig *config) {
    char router_str[INET_ADDRSTRLEN];
    char target_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &router_ip, router_str, sizeof(router_str));
    inet_ntop(AF_INET, &target_ip, target_str, sizeof(target_str));

    printf("   [SMART] SNMP not compiled in - would query %s for %s\n", 
           router_str, target_str);
    printf("   [SMART] Rebuild with libnetsnmp-dev and -DHAVE_SNMP flag\n");
    
    (void)config; // Suppress unused parameter warning
    return -1;
}

#endif
