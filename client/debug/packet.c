/**
 * @file client/debug/packet.c
 * @brief Simple Debug/Ping Packet Tester Implementation
 *
 * Extracted from client/main.c lines 1540-1565.
 */

#include <stdio.h>
#include <string.h>

#include "shared/types.h"
#include "shared/tui.h"
#include "client/dns/query.h"
#include "client/debug/packet.h"

/* ────────────────────────────────────────────── */
/*  Debug Packets                                 */
/* ────────────────────────────────────────────── */

void fire_debug_packet(const char *msg) {
    char payload[256];
    snprintf(payload, sizeof(payload), "%s%s", DNSTUN_DEBUG_PREFIX, msg);
    
    LOG_INFO("Firing debug packet: %s\n", payload);
    
    /* Fire as a chunk symbol on a dummy session (session 255) 
     * Signature: sid, seq, payloads, paylen, num_syms, total_syms, first_esi */
    const uint8_t *p[1] = { (const uint8_t*)payload };
    fire_dns_multi_symbols(255, 0, p, strlen(payload), 1, 1, 0);
}
