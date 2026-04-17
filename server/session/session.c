/**
 * @file server/session/session.c
 * @brief Server Session Lifecycle and Upstream TCP Connection Implementation
 *
 * Extracted from server/main.c lines 234-590.
 *
 * Responsibilities:
 *   - Maintain the global session table (g_sessions[]).
 *   - Allocate/free session slots by 8-bit session ID.
 *   - Manage upstream TCP connections (connect, read, write, close).
 *   - Queue SOCKS5 status bytes for downstream delivery.
 *
 * Example:
 *   1. Client DNS query arrives → server calls session_find_by_id(sid).
 *   2. If -1 → session_alloc_by_id(sid).
 *   3. After FEC decode call upstream_write_and_read(sidx, payload, len).
 *   4. on_upstream_read() appends data to upstream_buf for DNS TXT delivery.
 *   5. On cleanup: session_close(sidx).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "uv.h"
#include "shared/types.h"
#include "shared/config.h"
#include "server/session/session.h"
#include "shared/tui.h"

/* ── Global session table (exported via extern in session.h) ── */
srv_session_t g_sessions[SRV_MAX_SESSIONS];

/* ── Externals from main.c ── */
extern uv_loop_t    *g_loop;
extern dnstun_config_t g_cfg;
extern tui_stats_t   g_stats;

/* Internal logging — routes to shared log infrastructure from main.c */


/* ────────────────────────────────────────────── */
/*  Session lookup / alloc                        */
/* ────────────────────────────────────────────── */

int session_find_by_id(uint8_t id) {
    for (int i = 0; i < SRV_MAX_SESSIONS; i++)
        if (g_sessions[i].used && g_sessions[i].session_id == id)
            return i;
    return -1;
}

int session_alloc_by_id(uint8_t id) {
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        if (!g_sessions[i].used) {
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].session_id  = id;
            g_sessions[i].used        = true;
            g_sessions[i].last_active = time(NULL);
            g_sessions[i].pending_tx_buf = NULL;
            g_sessions[i].pending_tx_len = 0;
            g_sessions[i].pending_tx_cap = 0;
            g_sessions[i].tcp_connecting = false;
            g_sessions[i].rx_next = 0;
            memset(&g_sessions[i].upstream_reorder_buf, 0, sizeof(g_sessions[i].upstream_reorder_buf));
            g_stats.active_sessions++;
            return i;
        }
    }
    return -1;
}

void session_close(int idx) {
    srv_session_t *s = &g_sessions[idx];
    if (!s->used) return;

    if (s->tcp_connected && !uv_is_closing((uv_handle_t *)&s->upstream_tcp))
        uv_close((uv_handle_t *)&s->upstream_tcp, NULL);

    free(s->upstream_buf);
    s->upstream_buf = NULL;
    free(s->pending_tx_buf);
    s->pending_tx_buf = NULL;

    if (s->burst_symbols) {
        for (int i = 0; i < s->burst_count_needed; i++)
            free(s->burst_symbols[i]);
        free(s->burst_symbols);
        s->burst_symbols = NULL;
    }

    /* Free upstream reorder buffer slots */
    for (int i = 0; i < RX_REORDER_WINDOW; i++) {
        if (s->upstream_reorder_buf.slots[i].data) {
            free(s->upstream_reorder_buf.slots[i].data);
            s->upstream_reorder_buf.slots[i].data = NULL;
            s->upstream_reorder_buf.slots[i].valid = false;
        }
    }

    s->used = false;
    if (g_stats.active_sessions > 0)
        g_stats.active_sessions--;
}

void session_clear_burst(srv_session_t *s) {
    if (s->burst_symbols) {
        for (int i = 0; i < s->burst_count_needed; i++) {
            if (s->burst_symbols[i]) free(s->burst_symbols[i]);
        }
        free(s->burst_symbols);
        s->burst_symbols = NULL;
    }
    s->burst_count_needed = 0;
    s->burst_received     = 0;
    s->burst_decoded      = false;
    s->burst_has_oti      = false;
}

/* ────────────────────────────────────────────── */
/*  SOCKS5 Status Byte                            */
/* ────────────────────────────────────────────── */

void session_send_status(int sidx, uint8_t status) {
    srv_session_t *sess = &g_sessions[sidx];
    if (sess->status_sent) return;

    size_t need = sess->upstream_len + 1;
    if (need > sess->upstream_cap) {
        sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
        sess->upstream_cap = need + 8192;
    }

    if (sess->upstream_buf) {
        /* Prepend status byte before any already-buffered data */
        if (sess->upstream_len > 0)
            memmove(sess->upstream_buf + 1, sess->upstream_buf, sess->upstream_len);
        sess->upstream_buf[0] = status;
        sess->upstream_len++;
        sess->status_sent = true;
        LOG_DEBUG("Session %d: queued SOCKS5 status %02x at downstream_seq=%u\n",
                  sidx, status, sess->downstream_seq);
    }
}

/* ────────────────────────────────────────────── */
/*  Upstream TCP — Write + Read                   */
/* ────────────────────────────────────────────── */

void on_upstream_write(uv_write_t *w, int status) {
    free(w->data);
    (void)status;
}

void upstream_write_and_read(int session_idx, const uint8_t *data, size_t len) {
    srv_session_t *s = &g_sessions[session_idx];
    if (!s->tcp_connected) {
        LOG_DEBUG("Session %d: upstream_write dropped, tcp not connected len=%zu\n", session_idx, len);
        return;
    }

    uv_write_t *w = malloc(sizeof(*w) + len);
    if (!w) {
        LOG_DEBUG("Session %d: upstream_write alloc failed len=%zu\n", session_idx, len);
        return;
    }

    uint8_t *copy = (uint8_t *)(w + 1);
    memcpy(copy, data, len);
    w->data = w;

    uint8_t b0 = len > 0 ? data[0] : 0;
    uint8_t b1 = len > 1 ? data[1] : 0;
    uint8_t b2 = len > 2 ? data[2] : 0;
    uint8_t b3 = len > 3 ? data[3] : 0;
    LOG_DEBUG("Session %d: upstream_write len=%zu first=%02x %02x %02x %02x\n",
              session_idx, len, b0, b1, b2, b3);

    uv_buf_t buf = uv_buf_init((char *)copy, (unsigned)len);
    uv_write(w, (uv_stream_t *)&s->upstream_tcp, &buf, 1, on_upstream_write);

    g_stats.tx_total      += len;
    g_stats.tx_bytes_sec  += len;
}

void on_upstream_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    /* Allocate a fresh 8 KB block per read; on_upstream_read appends it into
     * the session's persistent buffer and frees this temporary block. */
    (void)sz;
    int *sidx_ptr = h->data;
    int sidx = sidx_ptr ? *sidx_ptr : -1;
    if (sidx < 0 || !g_sessions[sidx].used) {
        buf->base = NULL;
        buf->len  = 0;
        return;
    }
    buf->base = (char *)malloc(8192);
    buf->len  = buf->base ? 8192 : 0;
}

void on_upstream_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    int *sidx_ptr = s->data;
    int sidx = sidx_ptr ? *sidx_ptr : -1;
    if (sidx < 0) { free(buf->base); return; }

    srv_session_t *sess = &g_sessions[sidx];

    if (nread <= 0) {
        free(buf->base);
        /* Upstream TCP closed. Queue a SOCKS5 failure reply. */
        if (sess->tcp_connected) {
            uint8_t socks5_fail[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            size_t new_len = sess->upstream_len + sizeof(socks5_fail);
            uint8_t *new_buf = realloc(sess->upstream_buf, new_len);
            if (new_buf) {
                sess->upstream_buf = new_buf;
                memmove(sess->upstream_buf + sizeof(socks5_fail),
                        sess->upstream_buf, sess->upstream_len);
                memcpy(sess->upstream_buf, socks5_fail, sizeof(socks5_fail));
                sess->upstream_len = new_len;
            }
            if (!uv_is_closing((uv_handle_t *)&sess->upstream_tcp))
                uv_close((uv_handle_t *)&sess->upstream_tcp, NULL);
            LOG_DEBUG("Session %d: Upstream socket closed by host\n", sidx);
            sess->tcp_connected = false;
        }
        return;
    }

    /* Normal path: append target response data to the upstream polling buffer */
    LOG_DEBUG("Session %d: received %zd bytes from target host\n", sidx, nread);
    size_t need = sess->upstream_len + (size_t)nread;
    if (need > sess->upstream_cap) {
        size_t new_cap = need + 8192;
        sess->upstream_buf = realloc(sess->upstream_buf, new_cap);
        sess->upstream_cap = new_cap;
    }
    if (sess->upstream_buf) {
        memcpy(sess->upstream_buf + sess->upstream_len, buf->base, (size_t)nread);
        sess->upstream_len += (size_t)nread;
    }

    free(buf->base);
    g_stats.rx_total     += (size_t)nread;
    g_stats.rx_bytes_sec += (size_t)nread;
}

/* ────────────────────────────────────────────── */
/*  Async DNS resolution + TCP connect            */
/* ────────────────────────────────────────────── */

void on_upstream_resolve(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    connect_req_t *cr = (connect_req_t *)resolver->data;
    int sidx = cr->session_idx;
    srv_session_t *sess = &g_sessions[sidx];

    /* Guard: session may have been reused while resolution was pending */
    if (sess->tcp_connected) {
        LOG_DEBUG("Session %d: stale DNS resolution (session reused), ignoring\n", sidx);
        free(cr->payload);
        free(cr);
        free(resolver);
        if (res) uv_freeaddrinfo(res);
        return;
    }

    if (status != 0 || res == NULL) {
        LOG_ERR("DNS resolution failed for session %d (%s:%d): %s\n",
                sidx, cr->target_host, cr->target_port, uv_strerror(status));
        uint8_t socks_err = (status == UV_EAI_NONAME) ? 0x04 : 0x04;
        session_send_status(sidx, socks_err);
        free(cr->payload);
        free(cr);
        free(resolver);
        return;
    }

    char ip[INET6_ADDRSTRLEN];
    if (res->ai_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, ip, sizeof(ip));
    } else {
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, ip, sizeof(ip));
    }

    LOG_INFO("Session %d: resolved %s to %s\n", sidx, cr->target_host, ip);
    
    uv_tcp_init(g_loop, &sess->upstream_tcp);
    uv_tcp_nodelay(&sess->upstream_tcp, 1);
    sess->upstream_tcp.data = (void*)(uintptr_t)sidx;

    int r = uv_tcp_connect(&cr->connect, &sess->upstream_tcp, res->ai_addr, on_upstream_connect);
    if (r != 0) {
        LOG_ERR("Session %d: uv_tcp_connect failed: %s\n", sidx, uv_strerror(r));
        session_send_status(sidx, 0x01);
        free(cr->payload); free(cr);
    }

    uv_freeaddrinfo(res);
    free(resolver);
}

void on_upstream_connect(uv_connect_t *req, int status) {
    connect_req_t *cr = (connect_req_t *)req;
    int sidx = cr->session_idx;
    srv_session_t *sess = &g_sessions[sidx];

    if (status != 0) {
        LOG_ERR("Upstream connect failed for session %d: %s\n",
                sidx, uv_strerror(status));
        uint8_t socks_err = 0x01;
        if (status == UV_ECONNREFUSED) socks_err = 0x05;
        else if (status == UV_ETIMEDOUT) socks_err = 0x04;
        else if (status == UV_ENETUNREACH) socks_err = 0x03;
        session_send_status(sidx, socks_err);
        free(cr->payload);
        free(cr);
        return;
    }
    LOG_INFO("Upstream connected for session %d\n", sidx);

    /* Guard: session could have been reused */
    if (sess->tcp_connected) {
        LOG_DEBUG("Session %d: stale upstream connect (session reused), ignoring\n", sidx);
        free(cr->payload);
        free(cr);
        return;
    }

    sess->tcp_connected = true;
    sess->tcp_connecting = false;

    /* Store per-session index for the stream handle's data pointer */
    static int sidx_store[SRV_MAX_SESSIONS];
    sidx_store[sidx] = sidx;
    sess->upstream_tcp.data = &sidx_store[sidx];

    uv_read_start((uv_stream_t *)&sess->upstream_tcp, on_upstream_alloc, on_upstream_read);

    /* 1. Flush initial data from the SOCKS CONNECT chunk handled at connection start */
    if (cr->payload && cr->payload_len > 0) {
        LOG_INFO("Session %d: flushing %zu initial payload bytes\n", sidx, cr->payload_len);
        upstream_write_and_read(sidx, cr->payload, cr->payload_len);
    }

    /* 2. Flush any data that arrived in subsequent chunks while we were connecting */
    if (sess->pending_tx_buf && sess->pending_tx_len > 0) {
        LOG_INFO("Session %d: flushing %zu buffered bytes to upstream\n",
                 sidx, sess->pending_tx_len);
        upstream_write_and_read(sidx, sess->pending_tx_buf, sess->pending_tx_len);
        free(sess->pending_tx_buf);
        sess->pending_tx_buf = NULL;
        sess->pending_tx_len = 0;
        sess->pending_tx_cap = 0;
    }

    session_send_status(sidx, 0x00); /* SOCKS5 success */

    free(cr->payload);
    free(cr);
}

void session_process_data_direct(int sidx, const uint8_t *data, size_t len) {
    srv_session_t *sess = &g_sessions[sidx];
    size_t consumed = 0;

    while (consumed < len) {
        const uint8_t *p = data + consumed;
        size_t l = len - consumed;

        LOG_DEBUG("Session %d: process_direct len=%zu connected=%d connecting=%d hex=%02x%02x%02x%02x\n",
                  sidx, l, sess->tcp_connected, sess->tcp_connecting,
                  l > 0 ? p[0] : 0, l > 1 ? p[1] : 0, l > 2 ? p[2] : 0, l > 3 ? p[3] : 0);

        if (sess->tcp_connected) {
            upstream_write_and_read(sidx, p, l);
            return;
        }

        if (sess->tcp_connecting) {
            size_t need = sess->pending_tx_len + l;
            if (need > sess->pending_tx_cap) {
                size_t new_cap = need + 8192;
                uint8_t *new_buf = realloc(sess->pending_tx_buf, new_cap);
                if (new_buf) {
                    sess->pending_tx_buf = new_buf;
                    sess->pending_tx_cap = new_cap;
                }
            }
            if (sess->pending_tx_buf) {
                memcpy(sess->pending_tx_buf + sess->pending_tx_len, p, l);
                sess->pending_tx_len += l;
                LOG_DEBUG("Session %d: buffered %zu bytes while connecting (total=%zu)\n",
                          sidx, l, sess->pending_tx_len);
            }
            return;
        }

        if (l >= 10 && p[0] == 0x05 && p[1] == 0x01) {
            /* ... SOCKS5 CONNECT logic ... */
            char     target_host[256] = {0};
            uint16_t target_port      = 0;
            uint8_t  atype            = p[3];

            if (atype == 0x01) {
                snprintf(target_host, sizeof(target_host), "%d.%d.%d.%d", p[4], p[5], p[6], p[7]);
                target_port = (uint16_t)((p[8] << 8) | p[9]);
            } else if (atype == 0x03) {
                uint8_t dlen = p[4];
                if ((size_t)(5 + dlen + 2) <= l && dlen < 255) {
                    memcpy(target_host, p + 5, dlen);
                    target_host[dlen] = '\0';
                    target_port = (uint16_t)((p[5 + dlen] << 8) | p[6 + dlen]);
                }
            } else if (atype == 0x04 && l >= 22) {
                inet_ntop(AF_INET6, p + 4, target_host, sizeof(target_host));
                target_port = (uint16_t)((p[20] << 8) | p[21]);
            }

            if (target_host[0] && target_port > 0) {
                LOG_INFO("Session %d: SOCKS CONNECT request target=%s:%u\n", sidx, target_host, target_port);
                sess->tcp_connecting = true;

                connect_req_t *cr = calloc(1, sizeof(*cr));
                if (!cr) { sess->tcp_connecting = false; return; }
                cr->session_idx = sidx;
                strncpy(cr->target_host, target_host, sizeof(cr->target_host) - 1);
                cr->target_port = target_port;

                size_t hdr_sz = (atype == 0x01) ? 10 : (atype == 0x03) ? (size_t)(7 + p[4]) : (atype == 0x04) ? 22 : l;
                if (l > hdr_sz) {
                    cr->payload_len = l - hdr_sz;
                    cr->payload = malloc(cr->payload_len);
                    if (cr->payload) memcpy(cr->payload, p + hdr_sz, cr->payload_len);
                }

                uv_tcp_init(g_loop, &sess->upstream_tcp);
                uv_tcp_nodelay(&sess->upstream_tcp, 1);
                struct addrinfo hints = {0};
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_family   = (atype == 0x04) ? AF_INET6 : (atype == 0x01) ? AF_INET : AF_UNSPEC;
                char port_str[6]; snprintf(port_str, sizeof(port_str), "%d", target_port);
                uv_getaddrinfo_t *rr = malloc(sizeof(*rr));
                if (rr) {
                    rr->data = cr;
                    if (uv_getaddrinfo(g_loop, rr, on_upstream_resolve, target_host, port_str, &hints) != 0) {
                        free(rr); free(cr->payload); free(cr); sess->tcp_connecting = false;
                    }
                } else { free(cr->payload); free(cr); sess->tcp_connecting = false; }
                return;
            }
        }
        break;
    }
}

void session_handle_data(int sidx, const uint8_t *data, size_t len, uint16_t seq) {
    if (!data || len == 0) return;
    
    srv_session_t *sess = &g_sessions[sidx];

    /* 1. Sequence check */
    LOG_DEBUG("Session %d: handle_data seq=%u (expected=%u) len=%zu\n", 
              sidx, seq, sess->rx_next, len);

    if (seq < sess->rx_next) {
        LOG_DEBUG("Session %d: ignoring duplicate upstream seq=%u (expected=%u)\n", 
                  sidx, seq, sess->rx_next);
        return;
    }

    if (seq > sess->rx_next) {
        /* Store in reorder buffer */
        int slot = seq % RX_REORDER_WINDOW;
        if (sess->upstream_reorder_buf.slots[slot].valid) {
            LOG_DEBUG("Session %d: upstream reorder buffer collision at seq=%u\n", sidx, seq);
            return;
        }
        sess->upstream_reorder_buf.slots[slot].data = malloc(len);
        if (sess->upstream_reorder_buf.slots[slot].data) {
            memcpy(sess->upstream_reorder_buf.slots[slot].data, data, len);
            sess->upstream_reorder_buf.slots[slot].len = len;
            sess->upstream_reorder_buf.slots[slot].seq = seq;
            sess->upstream_reorder_buf.slots[slot].valid = true;
            LOG_DEBUG("Session %d: buffered out-of-order upstream seq=%u (expected=%u)\n", 
                      sidx, seq, sess->rx_next);
        }
        return;
    }

    /* seq == rx_next: process it */
    session_process_data_direct(sidx, data, len);
    sess->rx_next++;

    /* 2. Drain reorder buffer */
    while (true) {
        int slot = sess->rx_next % RX_REORDER_WINDOW;
        if (!sess->upstream_reorder_buf.slots[slot].valid || 
            sess->upstream_reorder_buf.slots[slot].seq != sess->rx_next) {
            break;
        }

        LOG_DEBUG("Session %d: draining sequential upstream seq=%u from reorder buffer\n", 
                  sidx, sess->rx_next);
        session_process_data_direct(sidx, 
                                   sess->upstream_reorder_buf.slots[slot].data, 
                                   sess->upstream_reorder_buf.slots[slot].len);
        
        free(sess->upstream_reorder_buf.slots[slot].data);
        sess->upstream_reorder_buf.slots[slot].data = NULL;
        sess->upstream_reorder_buf.slots[slot].valid = false;
        sess->rx_next++;
    }
}
