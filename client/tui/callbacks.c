/**
 * @file client/tui/callbacks.c
 * @brief Client-Side TUI Timer Callbacks, TTY, and Main Processing Loops Implementation
 *
 * Extracted from client/main.c lines 3060-3245.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "uv.h"
#include "shared/config.h"
#include "shared/tui.h"
#include "shared/mgmt.h"
#include "shared/resolver_pool.h"
#include "shared/codec.h"

#include "client/session/session.h"
#include "client/dns/query.h"
#include "client/aggregation/packet.h"
#include "client/tui/callbacks.h"

extern uv_loop_t       *g_loop;
extern dnstun_config_t  g_cfg;
extern tui_ctx_t        g_tui;
extern tui_stats_t      g_stats;
extern resolver_pool_t  g_pool;
extern session_t        g_sessions[];
extern mgmt_server_t   *g_mgmt;

/* Resolvers load / save callbacks */
extern void resolvers_save(void);

extern int log_level(void);
#define LOG_INFO(...)  do { if (g_cfg.log_level >= 1) { fprintf(stdout, "[INFO]  " __VA_ARGS__); } } while(0)
#define DBGLOG(...)    do { if (g_cfg.log_level >= 2) { } } while(0)

/* ────────────────────────────────────────────── */
/*  Polling Timer (Data send logic)               */
/* ────────────────────────────────────────────── */

void on_poll_timer(uv_timer_t *t) {
    (void)t;
    int chunk_size = DNSTUN_CHUNK_PAYLOAD;
    if (g_cfg.encryption) chunk_size -= 28; /* crypto overhead */

    static uint64_t last_poll[DNSTUN_MAX_SESSIONS] = {0};
    uint64_t now_ms = uv_hrtime() / 1000000ULL;

    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (s->closed || !s->established) continue;

        if (s->send_len == 0) {
            uint64_t interval = (g_cfg.poll_interval_ms >= 50) ? (uint64_t)g_cfg.poll_interval_ms : 50;
            if (s->socks5_connected && (now_ms - last_poll[i] >= interval)) {
                DBGLOG("[POLL] session %u seq %u\n", s->session_id, s->tx_next);
                fire_dns_chunk_symbol(i, s->tx_next++, NULL, 0, 0, 0, 0);
                last_poll[i] = now_ms;
            }
        } else {
            /* We have data to send */
            int avg_mtu = 512;
            int act_cnt = 0, up_sum = 0;
            uv_mutex_lock(&g_pool.lock);
            for(int r=0; r<g_pool.count; r++) {
                if(g_pool.resolvers[r].state == RSV_ACTIVE) {
                    up_sum += g_pool.resolvers[r].upstream_mtu;
                    act_cnt++;
                }
            }
            if(act_cnt > 0) avg_mtu = up_sum / act_cnt;
            uv_mutex_unlock(&g_pool.lock);

            size_t   take      = (s->send_len > (size_t)chunk_size) ? (size_t)chunk_size : s->send_len;
            uint8_t *raw_buf   = s->send_buf;
            size_t   raw_len   = take;

            /* Compress */
            codec_result_t zres = codec_compress(s->send_buf, take, 0);
            if (!zres.error && zres.data) {
                raw_buf = zres.data;
                raw_len = zres.len;
            }

            /* Encrypt */
            codec_result_t eres = {0};
            if (g_cfg.encryption) {
                eres = codec_encrypt(raw_buf, raw_len, g_cfg.psk);
                if (!eres.error && eres.data) {
                    raw_buf = eres.data;
                    raw_len = eres.len;
                }
            }

            uint16_t burst_seq  = s->tx_next;
            int      k_source   = 1;
            uint64_t oti_common = 0;
            uint32_t oti_scheme = 0;

            uint8_t **sym_ptrs = NULL;
            int sym_count      = 0;
            fec_encoded_t fenc = {0};

            /* Check if we can do 1-symbol FEC */
            int target_sym_size = avg_mtu;
            if (target_sym_size > DNSTUN_CHUNK_PAYLOAD) target_sym_size = DNSTUN_CHUNK_PAYLOAD;

            if (raw_len > (size_t)target_sym_size) {
                int k_val = (int)ceil((double)raw_len / target_sym_size);
                int r_val = (int)ceil(k_val * 0.1);
                if (r_val < 1) r_val = 1;
                fenc = codec_fec_encode(raw_buf, raw_len, k_val, r_val);
                if (fenc.symbols) {
                    k_source   = fenc.k_source;
                    oti_common = fenc.oti_common;
                    oti_scheme = fenc.oti_scheme;
                    sym_count  = fenc.total_count;
                    sym_ptrs   = fenc.symbols;
                }
            }

            if (sym_ptrs && sym_count > 0) {
                /* Aggregation check */
                int syms_per_packet = calc_symbols_per_packet(avg_mtu, 
                                        fenc.symbol_len);
                if (syms_per_packet > 1 && sym_count > 1) {
                    /* Packed multi-symbol send logic... For now, single send */
                    for (int sym_idx = 0; sym_idx < sym_count; sym_idx++) {
                        fire_dns_chunk_symbol(i, s->tx_next++, sym_ptrs[sym_idx],
                                              fenc.symbol_len,
                                              sym_count, oti_common, oti_scheme);
                    }
                } else {
                    for (int sym_idx = 0; sym_idx < sym_count; sym_idx++) {
                        fire_dns_chunk_symbol(i, s->tx_next++, sym_ptrs[sym_idx],
                                              fenc.symbol_len,
                                              sym_count, oti_common, oti_scheme);
                    }
                }
            } else {
                /* Non-FEC or encode failed */
                fire_dns_chunk_symbol(i, s->tx_next++, raw_buf, raw_len, 0, 0, 0);
            }

            /* Cleanup */
            if (sym_ptrs) {
                codec_fec_free(&fenc);
            }
            if (eres.data) free(eres.data);
            if (zres.data) free(zres.data);

            /* Shift send buffer */
            memmove(s->send_buf, s->send_buf + take, s->send_len - take);
            s->send_len -= take;

            last_poll[i] = uv_hrtime() / 1000000ULL;
        }
    }
}

/* ────────────────────────────────────────────── */
/*  Idle Timer                                    */
/* ────────────────────────────────────────────── */

void on_idle_timer(uv_timer_t *t) {
    (void)t;
    time_t now = time(NULL);

    for (int i = 0; i < g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i];
        if (r->state == RSV_ACTIVE && now - r->last_probe > 60) {
            r->fail_count = 0;
        }
    }

    static int save_tick = 0;
    if (++save_tick >= 10) {
        save_tick = 0;
        if (g_cfg.swarm_save_disk) resolvers_save();
    }

    g_stats.tx_bytes_sec = 0;
    g_stats.rx_bytes_sec = 0;
}

/* ────────────────────────────────────────────── */
/*  TUI Render Timer                              */
/* ────────────────────────────────────────────── */

void on_tui_timer(uv_timer_t *t) {
    (void)t;

    g_stats.active_resolvers = g_pool.active_count;
    g_stats.dead_resolvers   = g_pool.dead_count;

    tui_render(&g_tui);

    if (g_mgmt) {
        mgmt_broadcast_telemetry(g_mgmt, &g_stats);
    }
}

int get_active_clients_client(tui_client_snap_t *out, int max_clients) {
    int count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < DNSTUN_MAX_SESSIONS && count < max_clients; i++) {
        if (g_sessions[i].closed || !g_sessions[i].established) continue;
        snprintf(out[count].ip, sizeof(out[count].ip), "sid:%u", g_sessions[i].session_id);
        out[count].downstream_mtu = 0;
        out[count].loss_pct       = 0;
        out[count].fec_k          = 0;
        out[count].enc_format     = 0;
        out[count].idle_sec       = (uint32_t)(now - g_sessions[i].last_active);
        strncpy(out[count].user_id, g_sessions[i].target_host, sizeof(out[count].user_id)-1);
        count++;
    }
    return count;
}


/* ────────────────────────────────────────────── */
/*  TTY Callbacks                                 */
/* ────────────────────────────────────────────── */

void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len  = suggested_size;
}

void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)stream;
    if (nread > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            tui_handle_key(&g_tui, buf->base[i]);
            if (!g_tui.running) uv_stop(g_loop);
        }
    }
    if (buf->base) free(buf->base);
}
