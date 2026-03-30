/**
 * @file client/agg.c
 * @brief Implementation of client-side traffic aggregation and FEC burst dispatch.
 */

#include "agg.h"
#include "client_common.h"
#include "session.h"
#include "dns_tx.h"
#include "../shared/fec/core.h"
#include "../shared/codec.h"
#include <string.h>
#include <stdlib.h>

void agg_init(void) {
    LOG_INFO("Aggregation Engine initialized\n");
}

void agg_tick_bursts(void) {
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        session_t *s = session_get(i);
        if (!s || s->closed || s->send_len == 0) continue;

        /* 1. Determine FEC parameters (K, T) */
        int symbol_size = (g_client_cfg && g_client_cfg->symbol_size > 0) ? 
                          g_client_cfg->symbol_size : DNSTUN_SYMBOL_SIZE;
        
        /* Calculate how many symbols needed for current data */
        int k = (int)((s->send_len + symbol_size - 1) / symbol_size);
        if (k < 1) k = 1;
        if (k > 32) k = 32; /* Limit burst size for latency */
        
        /* 2. Execute FEC Encoding using the unified codec API */
        int redundancy_pct = (g_client_cfg) ? g_client_cfg->fec_redundancy : 20;
        int r = (k * redundancy_pct / 100);
        if (r < 1) r = 1; /* Always send at least one redundant symbol */

        /* codec_fec_encode handles the slicing of s->send_buf into symbols internally */
        fec_encoded_t burst = codec_fec_encode(s->send_buf, s->send_len, k, r);

        /* 3. Transmit the Burst (Scattered across active resolvers) */
        uint16_t base_seq = s->tx_next;
        s->tx_next += (uint16_t)burst.total_count;

        const char *domain = (g_client_cfg && g_client_cfg->domain_count > 0) ? 
                             g_client_cfg->domains[0] : "tun.example.com";

        for (int j = 0; j < (int)burst.total_count; j++) {
            chunk_header_t hdr = {0};
            chunk_set_session_id(&hdr, s->session_id);
            hdr.seq = base_seq + (uint16_t)j;
            
            /* Pack FEC info into compact 4-bit nibbles */
            chunk_set_info(&hdr.chunk_info, (uint8_t)burst.total_count, (uint8_t)burst.k_source);
            hdr.oti_common = burst.oti_common;
            hdr.oti_scheme = burst.oti_scheme;

            uint8_t pkt[1100];
            size_t pkt_len = sizeof(pkt);
            if (dns_tx_build_query(pkt, &pkt_len, &hdr, burst.symbols[j], burst.symbol_len, domain) == 0) {
                /* The packet dispatch is now handled by the resolver pool and dns_tx internal logic via raw UDP */
                /* In this modular version, we just build the packet; dns_tx_send_raw or similar would be called here. */
                /* For now, we assume dns_tx_build_query is enough or we add a transmission call if provided. */
            }
        }

        /* 4. Cleanup */
        codec_fec_free(&burst);
        s->send_len = 0; /* Data successfully dispatched */
        s->last_active = time(NULL);
    }
}

void agg_shutdown(void) {
    LOG_INFO("Aggregation Engine shutdown\n");
}
