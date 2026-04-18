/**
 * @file client/tui/callbacks.c
 * @brief Client-Side TUI Timer Callbacks, TTY, and Main Processing Loops Implementation
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

extern void resolvers_save(void);

/* ────────────────────────────────────────────── */
/*  Polling Timer (Data send logic)               */
/* ────────────────────────────────────────────── */

void on_poll_timer(uv_timer_t *t) {
    (void)t;
    int chunk_size = g_cfg.chunk_payload;
    if (g_cfg.encryption) chunk_size -= 28;

    static uint64_t last_poll[DNSTUN_MAX_SESSIONS] = {0};
    uint64_t now_ms = uv_hrtime() / 1000000ULL;
    time_t now = time(NULL);

    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (s->closed || !s->established) continue;

        static uint64_t last_poll_log = 0;
        if (s->send_len > 0 && (now - last_poll_log > 1000)) {
            LOG_INFO("Session %u: Poll (buf=%zu est=%d sync=%d next=%u acked=%u prog=%d)\n",
                     s->session_id, s->send_len, s->established, s->fec_synced, 
                     s->tx_next, s->tx_acked, s->tx_burst_esi);
            last_poll_log = now;
        }

        /* Retransmission Rewind */
        if (s->send_len > 0 && s->tx_next > s->tx_acked) {
            if (s->last_ack_time > 0 && (now - s->last_ack_time > 5)) {
                LOG_WARN("Session %u: ACK stalled, rewinding...\n", s->session_id);
                s->tx_next = s->tx_acked; s->last_ack_time = now;
            }
        }

        /* Handshake Retransmit */
        if (!s->fec_synced && (now - s->last_handshake >= 2)) {
            send_mtu_handshake(i); s->last_handshake = now;
        }

        if (s->send_len == 0) {
            uint64_t interval = (g_cfg.poll_interval_ms >= 50) ? (uint64_t)g_cfg.poll_interval_ms : 50;
            if (s->fast_poll) interval = 0;
            if (s->socks5_connected && (now_ms - last_poll[i] >= interval)) {
                int dummy = 0;
                if (fire_dns_multi_symbols(i, 0, NULL, 0, 0, &dummy, false) > 0) s->fast_poll = false;
                last_poll[i] = now_ms;
            }
        } else {
            /* Data Burst (Resume Logic) */
            int K = (s->cl_fec_k > 0) ? (int)s->cl_fec_k : 10;
            int N = (s->cl_fec_n > 0) ? (int)s->cl_fec_n : 15;
            size_t sym_size = (s->cl_symbol_size > 0) ? (size_t)s->cl_symbol_size : (size_t)g_cfg.chunk_payload;

            /* Check if we need to encode a new burst */
            if (!s->tx_fec_active) {
                size_t take = (s->send_len > sym_size) ? sym_size : s->send_len;
                if (g_cfg.log_level >= 2) {
                    LOG_INFO("Session %u: Encoding new FEC burst for %zu bytes (K=%d N=%d)\n", 
                             s->session_id, take, K, N);
                }
                s->tx_fec = codec_fec_encode(s->send_buf, take, K, N - K, (uint16_t)sym_size);
                if (s->tx_fec.total_count == 0 || !s->tx_fec.symbols) {
                    LOG_ERR("Session %u: FEC fail (take=%zu K=%d)\n", s->session_id, take, K);
                    continue;
                }
                s->tx_fec_active = true;
                s->tx_fec_len = take;
                s->tx_burst_esi = 0;
                s->tx_burst_total = (uint16_t)N;
            }

            int prev_esi = (int)s->tx_burst_esi;
            int esi_prog = prev_esi;
            int sent = fire_dns_multi_symbols(i, s->tx_next, (const uint8_t **)s->tx_fec.symbols, sym_size, N, &esi_prog, false);
            s->tx_burst_esi = (uint16_t)esi_prog;

            if (sent > 0) {
                if (g_cfg.log_level >= 1) {
                    LOG_INFO("Session %u: Fired burst symbols (progress %d -> %d/%d)\n", 
                             s->session_id, prev_esi, s->tx_burst_esi, N);
                }
                
                /* Only advance once EVERY symbol in the burst has been fired */
                if (s->tx_burst_esi >= N) {
                    LOG_INFO("Session %u: Burst seq=%u complete. Advancing...\n", s->session_id, s->tx_next);
                    
                    /* Map the current seq to the offset in the buffer for potential retransmits */
                    s->tx_offset_map[s->tx_next % 256] = (uint32_t)s->tx_fec_len;
                    
                    /* Prune the send buffer */
                    if (s->tx_fec_len < s->send_len) {
                        memmove(s->send_buf, s->send_buf + s->tx_fec_len, s->send_len - s->tx_fec_len);
                    }
                    s->send_len -= s->tx_fec_len;
                    
                    /* Clean up persistent FEC state */
                    codec_fec_free(&s->tx_fec);
                    s->tx_fec_active = false;
                    s->tx_fec_len = 0;
                    
                    /* Advance sequence */
                    s->tx_next++; 
                    s->tx_burst_esi = 0; 
                    s->tx_burst_total = 0;
                }
            }
            last_poll[i] = now_ms;
        }
    }
}

/* ────────────────────────────────────────────── */
/*  Outside IP Detection                          */
/* ────────────────────────────────────────────── */

static void on_outside_ip_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
    if (status == 0 && res) {
        char addr[46]; uv_ip4_name((struct sockaddr_in *)res->ai_addr, addr, sizeof(addr));
        strncpy(g_stats.outside_ip, addr, sizeof(g_stats.outside_ip)-1);
    }
    if (res) uv_freeaddrinfo(res); free(req);
}

void detect_outside_ip(void) {
    static uint64_t last = 0; uint64_t now = uv_hrtime()/1000000ULL;
    if (g_stats.outside_ip[0] == 'd' || now - last > 300000) {
        last = now; uv_getaddrinfo_t *req = malloc(sizeof(uv_getaddrinfo_t));
        if (req) {
            struct addrinfo hints; memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
            if (uv_getaddrinfo(g_loop, req, on_outside_ip_resolved, "whoami.akamai.net", NULL, &hints) != 0) free(req);
        }
    }
}

void on_idle_timer(uv_timer_t *t) {
    (void)t; time_t now = time(NULL);
    for (int i=0; i<g_pool.count; i++) {
        resolver_t *r = &g_pool.resolvers[i]; if (r->state == RSV_ACTIVE && now - r->last_probe > 60) r->fail_count = 0;
    }
    static int save_tick = 0; if (++save_tick >= 10) { save_tick = 0; if (g_cfg.swarm_save_disk) resolvers_save(); }
    g_stats.tx_bytes_sec = 0; g_stats.rx_bytes_sec = 0;
    
    /* Session Watchdog (SOCKS5 Idle Timeout) */
    for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (s->closed || !s->established) continue;
        
        uint32_t idle_sec = (uint32_t)(now - s->last_active);
        uint32_t timeout = (g_cfg.socks5_idle_timeout > 0) ? (uint32_t)g_cfg.socks5_idle_timeout : 60;
        
        if (idle_sec > timeout) {
            LOG_INFO("Session %u: Idle timeout reached (%us > %us). Closing...\n", 
                     s->session_id, idle_sec, timeout);
            if (s->client_ptr) {
                socks5_client_t *c = (socks5_client_t*)s->client_ptr;
                if (!uv_is_closing((uv_handle_t*)&c->tcp)) {
                    uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
                }
            } else {
                s->closed = true;
            }
        }
    }

    if (strcmp(g_stats.mode, "CLIENT") == 0) detect_outside_ip();
}

void on_tui_timer(uv_timer_t *t) {
    (void)t; g_stats.active_resolvers = g_pool.active_count; g_stats.dead_resolvers = g_pool.dead_count;
    tui_render(&g_tui); if (g_mgmt) mgmt_broadcast_telemetry(g_mgmt, &g_stats);
}

int get_active_clients_client(tui_client_snap_t *out, int max_clients) {
    int count = 0; time_t now = time(NULL);
    for (int i=0; i<DNSTUN_MAX_SESSIONS && count < max_clients; i++) {
        if (g_sessions[i].closed || !g_sessions[i].established) continue;
        snprintf(out[count].ip, sizeof(out[count].ip), "sid:%u", g_sessions[i].session_id);
        out[count].downstream_mtu = 0; out[count].loss_pct = 0; out[count].fec_k = 0; out[count].enc_format = 0;
        out[count].idle_sec = (uint32_t)(now - g_sessions[i].last_active);
        strncpy(out[count].user_id, g_sessions[i].target_host, sizeof(out[count].user_id)-1); count++;
    }
    return count;
}

void on_tty_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) { (void)h; buf->base = malloc(sz); buf->len = sz; }
void on_tty_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    (void)s; if (nread > 0) {
        for (ssize_t i=0; i<nread; i++) { tui_handle_key(&g_tui, buf->base[i]); if (!g_tui.running) uv_stop(g_loop); }
    }
    if (buf->base) free(buf->base);
}
