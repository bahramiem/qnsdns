/**
 * @file client/agg.c
 * @brief Implementation of client-side traffic aggregation and FEC burst dispatch.
 */

#include "agg.h"
#include "client_common.h"
#include "session.h"
#include "dns_tx.h"
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

        /* 1. Add Nonce and Compress Data (Legacy Cache-Busting) */
        size_t nonce_len = s->send_len + 4;
        uint8_t *nonce_buf = malloc(nonce_len);
        if (!nonce_buf) { LOG_ERR("OOM for nonce_buf\n"); continue; }
        
        /* 4-byte random nonce prepended to data */
        for (int b = 0; b < 4; b++) nonce_buf[b] = (uint8_t)(rand() & 0xFF);
        memcpy(nonce_buf + 4, s->send_buf, s->send_len);

        /* Compress the data burst */
        codec_result_t cret = codec_compress(nonce_buf, nonce_len, 3);
        free(nonce_buf);
        if (cret.error) {
            LOG_ERR("Compression failed - skipping burst\n");
            continue;
        }

        /* 2. Execute FEC Encoding using the unified codec API */
        int symbol_size = (g_client_cfg && g_client_cfg->symbol_size > 0) ? 
                          g_client_cfg->symbol_size : DNSTUN_SYMBOL_SIZE;
        
        int k = (int)((cret.len + symbol_size - 1) / symbol_size);
        if (k < 1) k = 1;
        if (k > 32) k = 32;

        int redundancy_pct = (g_client_cfg) ? g_client_cfg->fec_redundancy : 20;
        int r = (k * redundancy_pct / 100);
        if (r < 1) r = 1; 

        fec_encoded_t burst = codec_fec_encode(cret.data, cret.len, k, r);
        codec_free_result(&cret);

        /* 3. Transmit the Burst (Scattered across active resolvers) */
        uint16_t base_seq = s->tx_next;
        s->tx_next += (uint16_t)burst.total_count;

        const char *domain = (g_client_cfg && g_client_cfg->domain_count > 0) ? 
                             g_client_cfg->domains[0] : "tun.example.com";

        for (int j = 0; j < (int)burst.total_count; j++) {
            chunk_header_t hdr = {0};
            chunk_set_session_id(&hdr, s->session_id);
            hdr.seq = base_seq + (uint16_t)j;
            
            chunk_set_info(&hdr.chunk_info, (uint8_t)burst.total_count, (uint8_t)burst.k_source);
            hdr.oti_common = burst.oti_common;
            hdr.oti_scheme = burst.oti_scheme;

            uint8_t pkt[1100];
            size_t pkt_len = sizeof(pkt);
            if (dns_tx_build_query(pkt, &pkt_len, &hdr, burst.symbols[j], burst.symbol_len, domain) == 0) {
                /* RESTORATION: Actually send the data packets! */
                dns_tx_send_raw(pkt, pkt_len);
            }
        }

        /* 4. Cleanup and reset queue */
        codec_fec_free(&burst);
        s->send_len = 0; 
        s->last_active = time(NULL);
    }
}

void agg_shutdown(void) {
    LOG_INFO("Aggregation Engine shutdown\n");
}
