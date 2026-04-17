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

        /* ── RETRANSMISSION LOGIC: Rewind tx_next if ACK stalled ── */
        if (s->send_len > 0 && s->tx_next > s->tx_acked) {
            time_t now = time(NULL);
            if (s->last_ack_time > 0 && (now - s->last_ack_time > 5)) {
                LOG_WARN("Session %u: ACK stalled (tx_next=%u tx_acked=%u), rewinding for retransmission...\n", 
                         s->session_id, s->tx_next, s->tx_acked);
                s->tx_next = s->tx_acked;
                s->last_ack_time = now; /* Avoid immediate double rewind */
            }
        }

        /* RETRANSMIT HANDSHAKE if not yet synced */
        time_t now = time(NULL);
        if (s->established && !s->fec_synced) {
            if (now - s->last_handshake >= 2) {
                LOG_DEBUG("[UPSTREAM] Session %u: Retransmitting Handshake (waiting for sync)\n", s->session_id);
                send_mtu_handshake(i);
                s->last_handshake = now;
            }
        }

        if (s->send_len == 0) {
            uint64_t interval = (g_cfg.poll_interval_ms >= 50) ? (uint64_t)g_cfg.poll_interval_ms : 50;
            if (s->socks5_connected && (now_ms - last_poll[i] >= interval)) {
                /* Don't increment tx_next for empty polls; they don't carry sequence-sensitive data */
                fire_dns_multi_symbols(i, 0, NULL, 0, 0, 0, 0, false);
                last_poll[i] = now_ms;
            }
        } else {
            size_t   take      = (s->send_len > (size_t)chunk_size) ? (size_t)chunk_size : s->send_len;
            uint8_t *raw_buf   = s->send_buf;
            size_t   raw_len   = take;

            DBGLOG("[POLL_DATA] taking %zu bytes from send_buf (total %zu)\n", take, s->send_len);

            /* ANTI-CACHE NONCE: Only needed if encryption is OFF. 
             * If encryption is ON, the ChaCha20 random nonce already makes every packet unique. */
            uint8_t *comp_buf = s->send_buf;
            size_t   comp_len = take;
            uint8_t *nonce_buf = NULL;

            if (!g_cfg.encryption) {
                size_t nlen = take + 4;
                nonce_buf = malloc(nlen);
                if (nonce_buf) {
                    nonce_buf[0] = (uint8_t)(rand() & 0xFF);
                    nonce_buf[1] = (uint8_t)(rand() & 0xFF);
                    nonce_buf[2] = (uint8_t)(rand() & 0xFF);
                    nonce_buf[3] = (uint8_t)(rand() & 0xFF);
                    memcpy(nonce_buf + 4, s->send_buf, take);
                    comp_buf = nonce_buf;
                    comp_len = nlen;
                }
            }

            /* Compress */
            codec_result_t zres = codec_compress(comp_buf, comp_len, 0);
            if (nonce_buf) free(nonce_buf);

            bool is_compressed = false;
            if (!zres.error && zres.data) {
                raw_buf = zres.data;
                raw_len = zres.len;
                is_compressed = true;
            } else {
                DBGLOG("[POLL_DATA] compression failed, dropping packet\n");
                continue;
            }

            /* Encrypt */
            codec_result_t eres = {0};
            if (g_cfg.encryption) {
                eres = codec_encrypt(raw_buf, raw_len, g_cfg.psk);
                if (!eres.error && eres.data) {
                    raw_buf = eres.data;
                    raw_len = eres.len;
                } else if (eres.error) {
                    DBGLOG("[POLL_DATA] encryption failed\n");
                }
            }

            uint16_t burst_seq  = s->tx_next;
            uint8_t **sym_ptrs = NULL;
            int sym_count      = 0;
            fec_encoded_t fenc = {0};

            /* Use negotiated FEC parameters from handshake or config defaults */
            int k_val = (s->cl_fec_k > 0) ? (int)s->cl_fec_k : g_cfg.fec_k;
            int r_val = (s->cl_fec_n > s->cl_fec_k) ? (int)(s->cl_fec_n - s->cl_fec_k) : 2;

            if (raw_len > 0) {
                fenc = codec_fec_encode(raw_buf, raw_len, k_val, r_val);
                if (fenc.symbols) {
                    sym_count  = fenc.total_count;
                    sym_ptrs   = fenc.symbols;
                }
            }

            /* Update offset map for this sequence */
            s->tx_offset_map[s->tx_next % 256] = (uint32_t)take;

            if (sym_ptrs && sym_count > 0) {
                if (fire_dns_multi_symbols(i, burst_seq, (const uint8_t**)sym_ptrs, fenc.symbol_len, sym_count, sym_count, 0, is_compressed)) {
                    s->tx_next++; /* Increment sequence number only if actually sent */
                }
            } else {
                /* Non-FEC or encode failed: Send as 1-symbol burst */
                const uint8_t *payload_ptr[1] = { raw_buf };
                if (fire_dns_multi_symbols(i, burst_seq, payload_ptr, raw_len, 1, 1, 0, is_compressed)) {
                    s->tx_next++;
                }
            }

            /* Cleanup */
            if (sym_ptrs) {
                codec_fec_free(&fenc);
            }
            if (eres.data) codec_free_result(&eres);
            if (zres.data) codec_free_result(&zres);

            last_poll[i] = uv_hrtime() / 1000000ULL;
        }
    }
}

/* ────────────────────────────────────────────── */
/*  Outside IP Detection (DNS-friendly)           */
/* ────────────────────────────────────────────── */

static void on_outside_ip_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
    if (status == 0 && res) {
        char addr[46];
        uv_ip4_name((struct sockaddr_in *)res->ai_addr, addr, sizeof(addr));
        strncpy(g_stats.outside_ip, addr, sizeof(g_stats.outside_ip)-1);
    }
    if (res) uv_freeaddrinfo(res);
    free(req);
}

void detect_outside_ip(void) {
    static uint64_t last_check = 0;
    uint64_t now = uv_hrtime() / 1000000ULL;
    
    /* Detect every 5 minutes, or immediately if still "detecting..." */
    if (g_stats.outside_ip[0] == 'd' || now - last_check > 300000) {
        last_check = now;
        uv_getaddrinfo_t *req = malloc(sizeof(uv_getaddrinfo_t));
        if (req) {
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            /* whoami.akamai.net returns the query's source IP as an A record response.
               This is perfect for DNS-transparent IP detection. */
            if (uv_getaddrinfo(g_loop, req, on_outside_ip_resolved, "whoami.akamai.net", NULL, &hints) != 0) {
                free(req);
            }
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

    if (strcmp(g_stats.mode, "CLIENT") == 0) {
        void detect_outside_ip(void);
        detect_outside_ip();
    }
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
