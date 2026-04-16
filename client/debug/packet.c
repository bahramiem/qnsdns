/**
 * @file client/debug/packet.c
 * @brief Simple Debug/Ping Packet Tester Implementation
 *
 * Extracted from client/main.c lines 1540-1565.
 */

#include <stdio.h>
#include <string.h>

#include "shared/types.h"
#include "client/dns/query.h"
#include "client/debug/packet.h"

extern int log_level(void);
#define LOG_INFO(...)  do { if (log_level() >= 1) { fprintf(stdout, "[INFO]  " __VA_ARGS__); } } while(0)

/* ────────────────────────────────────────────── */
/*  Debug Packets                                 */
/* ────────────────────────────────────────────── */

void fire_debug_packet(const char *msg) {
    char payload[256];
    snprintf(payload, sizeof(payload), "%s%s", DNSTUN_DEBUG_PREFIX, msg);
    
    LOG_INFO("Firing debug packet: %s\n", payload);
    
    /* Fire as a chunk symbol on a dummy session (session 255) */
    fire_dns_chunk_symbol(255, 0, (const uint8_t*)payload, strlen(payload), 0, 0, 0);
}
