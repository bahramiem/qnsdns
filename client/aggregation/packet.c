/**
 * @file client/aggregation/packet.c
 * @brief Packet Aggregation Implementation
 *
 * Extracted from client/main.c lines 1472-1538.
 */

#include <stdio.h>
#include <string.h>

#include "shared/config.h"
#include "shared/resolver_pool.h"

#include "client/aggregation/packet.h"

extern dnstun_config_t g_cfg;
extern resolver_pool_t g_pool;

extern int log_level(void);
#define LOG_INFO(...)  do { if (g_cfg.log_level >= 1) { fprintf(stdout, "[INFO]  " __VA_ARGS__); } } while(0)

/* ────────────────────────────────────────────── */
/*  Aggregation Helpers                           */
/* ────────────────────────────────────────────── */

int calc_symbols_per_packet(int mtu, int symbol_size) {
    if (symbol_size <= 0) return 1;
    // Assume 20 bytes overhead per DNS query
    int payload_capacity = mtu - 20; 
    // Need approx 1 byte overhead per symbol for length encoding
    int max_syms = payload_capacity / (symbol_size + 1);
    return max_syms > 0 ? max_syms : 1;
}

double calc_packing_efficiency(int mtu, size_t optimal_size) {
    if (optimal_size <= 0) return 0.0;
    // MTU is max bytes available
    if ((int)optimal_size > mtu) return 100.0; // Overpacked
    return (double)optimal_size / mtu * 100.0;
}

void log_aggregation_stats(void) {
    int total_mtu = 0;
    int active_resolvers = 0;
    
    for (int i=0; i<g_pool.count; i++) {
        if (g_pool.resolvers[i].state == RSV_ACTIVE) {
            total_mtu += g_pool.resolvers[i].upstream_mtu;
            active_resolvers++;
        }
    }
    
    if (active_resolvers > 0) {
        int avg_mtu = total_mtu / active_resolvers;
        int max_syms_16 = calc_symbols_per_packet(avg_mtu, 16);
        int max_syms_32 = calc_symbols_per_packet(avg_mtu, 32);
        
        LOG_INFO("Aggregation Capacity (avg MTU %d):\n", avg_mtu);
        LOG_INFO("  - 16-byte symbols: up to %d per packet\n", max_syms_16);
        LOG_INFO("  - 32-byte symbols: up to %d per packet\n", max_syms_32);
    }
}

int encode_aggregated_packet(uint8_t *out_buf, size_t out_cap, uint16_t seq,
                             uint8_t *symbols[], uint8_t sizes[], int count) {
    if (!out_buf || count <= 0) return 0;
    
    size_t pos = 0;
    // Sequence number (2 bytes)
    if (pos + 2 > out_cap) return 0;
    out_buf[pos++] = (seq >> 8) & 0xFF;
    out_buf[pos++] = seq & 0xFF;
    
    // Number of symbols (1 byte)
    if (pos + 1 > out_cap) return 0;
    out_buf[pos++] = count & 0xFF;
    
    for (int i = 0; i < count; i++) {
        // Size of this symbol (1 byte)
        if (pos + 1 > out_cap) return pos;
        out_buf[pos++] = sizes[i];
        
        // Symbol data
        if (pos + sizes[i] > out_cap) return pos;
        if (symbols[i] && sizes[i] > 0) {
            memcpy(out_buf + pos, symbols[i], sizes[i]);
        }
        pos += sizes[i];
    }
    
    return pos;
}

int decode_aggregated_packet(uint8_t *symbols[], uint8_t sizes[],
                             const uint8_t *packet, size_t packet_len,
                             int max_symbols) {
    if (!packet || packet_len < 3 || !symbols || !sizes) return 0;
    
    size_t pos = 2; // Skip sequence number
    int count = packet[pos++];
    if (count > max_symbols) count = max_symbols;
    
    int extracted = 0;
    for (int i = 0; i < count && pos < packet_len; i++) {
        sizes[i] = packet[pos++];
        if (pos + sizes[i] > packet_len) break; // Truncated packet
        
        symbols[i] = (uint8_t*)(packet + pos);
        pos += sizes[i];
        extracted++;
    }
    
    return extracted;
}
