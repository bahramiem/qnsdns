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

    if (s->burst_symbols) {
        for (int i = 0; i < s->burst_count_needed; i++)
            free(s->burst_symbols[i]);
        free(s->burst_symbols);
    }

    s->used = false;
    if (g_stats.active_sessions > 0)
        g_stats.active_sessions--;
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
        /* Upstream TCP closed. Queue a SOCKS5 failure reply so curl knows
         * the connection is gone. Do NOT call session_close() — any remaining
         * data in upstream_buf must still be polled and delivered. */
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
            sess->tcp_connected = false;
        }
        return;
    }

    /* Skip SOCKS5 reply header (VER=0x05 REP=0x00 RSV=0x00 ATYP=0x01) */
    if (nread >= 4 && buf->base[0] == 0x05 && buf->base[1] == 0x00 &&
        buf->base[2] == 0x00 && buf->base[3] == 0x01) {
        LOG_DEBUG("Session %d: Received SOCKS5 reply (%zd bytes) — skipping\n",
                  sidx, nread);
        /* If there's HTTP data after the SOCKS5 reply, buffer only that part */
        if (nread > 10) {
            size_t http_len = (size_t)nread - 10;
            size_t need = sess->upstream_len + http_len;
            if (need > sess->upstream_cap) {
                sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
                sess->upstream_cap = need + 8192;
            }
            if (sess->upstream_buf) {
                memcpy(sess->upstream_buf + sess->upstream_len,
                       buf->base + 10, http_len);
                sess->upstream_len += http_len;
            }
        }
        free(buf->base);
        g_stats.rx_total     += (size_t)nread;
        g_stats.rx_bytes_sec += (size_t)nread;
        return;
    }

    /* Normal path: append HTTP response data */
    size_t need = sess->upstream_len + (size_t)nread;
    if (need > sess->upstream_cap) {
        sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
        sess->upstream_cap = need + 8192;
    }
    memcpy(sess->upstream_buf + sess->upstream_len, buf->base, (size_t)nread);
    sess->upstream_len += (size_t)nread;

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

    char addr_str[INET6_ADDRSTRLEN];
    if (res->ai_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
                  addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
                  addr_str, sizeof(addr_str));

    LOG_INFO("DNS resolved %s:%d to %s for session %d\n",
             cr->target_host, cr->target_port, addr_str, sidx);

    uv_tcp_connect(&cr->connect, &sess->upstream_tcp, res->ai_addr, on_upstream_connect);

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

    /* Store per-session index for the stream handle's data pointer */
    static int sidx_store[SRV_MAX_SESSIONS];
    sidx_store[sidx] = sidx;
    sess->upstream_tcp.data = &sidx_store[sidx];

    uv_read_start((uv_stream_t *)&sess->upstream_tcp, on_upstream_alloc, on_upstream_read);

    if (cr->payload && cr->payload_len > 0)
        upstream_write_and_read(sidx, cr->payload, cr->payload_len);

    session_send_status(sidx, 0x00); /* SOCKS5 success */

    free(cr->payload);
    free(cr);
}

void session_handle_data(int sidx, const uint8_t *data, size_t len) {
    srv_session_t *sess = &g_sessions[sidx];
    uint8_t b0 = len > 0 ? data[0] : 0;
    uint8_t b1 = len > 1 ? data[1] : 0;
    uint8_t b2 = len > 2 ? data[2] : 0;
    uint8_t b3 = len > 3 ? data[3] : 0;
    LOG_DEBUG("Session %d: handle_data len=%zu tcp_connected=%d first=%02x %02x %02x %02x\n",
              sidx, len, sess->tcp_connected ? 1 : 0, b0, b1, b2, b3);
    if (sess->tcp_connected) {
        LOG_DEBUG("Session %d: forwarding %zu bytes to upstream socket\n", sidx, len);
        upstream_write_and_read(sidx, data, len);
        return;
    }

    /* Handle SOCKS5 greeting when not connected */
    if (len >= 3 && data[0] == 0x05) {
        uint8_t nmethods = data[1];
        if (len >= 2 + nmethods) {
            /* Check if client offered no authentication (0x00) */
            bool has_no_auth = false;
            for (uint8_t i = 0; i < nmethods; i++) {
                if (data[2 + i] == 0x00) {
                    has_no_auth = true;
                    break;
                }
            }

            LOG_DEBUG("Session %d: SOCKS greeting detected nmethods=%u has_no_auth=%d\n",
                      sidx, nmethods, has_no_auth ? 1 : 0);
            if (has_no_auth) {
                /* Respond with no authentication */
                session_send_status(sidx, 0x00);
                return;
            } else {
                /* No acceptable methods */
                session_send_status(sidx, 0xFF);
                /* TODO: Close connection after sending response */
                return;
            }
        }
    }

    /* Not connected: parse as SOCKS5 CONNECT */
    if (len >= 10 && data[0] == 0x05 && data[1] == 0x01) {
        char     target_host[256] = {0};
        uint16_t target_port      = 0;
        uint8_t  atype            = data[3];

        if (atype == 0x01) {
            snprintf(target_host, sizeof(target_host),
                     "%d.%d.%d.%d", data[4], data[5], data[6], data[7]);
            target_port = (uint16_t)((data[8] << 8) | data[9]);
        } else if (atype == 0x03) {
            uint8_t dlen = data[4];
            if ((size_t)(5 + dlen + 2) <= len && dlen < 255) {
                memcpy(target_host, data + 5, dlen);
                target_host[dlen] = '\0';
                target_port = (uint16_t)((data[5 + dlen] << 8) | data[6 + dlen]);
            }
        } else if (atype == 0x04 && len >= 22) {
            inet_ntop(AF_INET6, data + 4, target_host, sizeof(target_host));
            target_port = (uint16_t)((data[20] << 8) | data[21]);
        }

        if (target_host[0] && target_port > 0) {
            LOG_INFO("Session %d: SOCKS CONNECT request target=%s:%u atype=0x%02x len=%zu\n",
                     sidx, target_host, target_port, atype, len);
            connect_req_t *cr = calloc(1, sizeof(*cr));
            if (!cr) return;
            cr->session_idx = sidx;
            strncpy(cr->target_host, target_host, sizeof(cr->target_host) - 1);
            cr->target_port = target_port;

            size_t hdr_sz = (atype == 0x01) ? 10 :
                            (atype == 0x03) ? (size_t)(7 + data[4]) :
                            (atype == 0x04) ? 22 : len;
            if (len > hdr_sz) {
                cr->payload_len = len - hdr_sz;
                cr->payload = malloc(cr->payload_len);
                if (cr->payload) memcpy(cr->payload, data + hdr_sz, cr->payload_len);
            }

            uv_tcp_init(g_loop, &sess->upstream_tcp);
            uv_tcp_nodelay(&sess->upstream_tcp, 1);

            struct addrinfo hints = {0};
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_family   = (atype == 0x04) ? AF_INET6 :
                                (atype == 0x01) ? AF_INET  : AF_UNSPEC;
            char port_str[6];
            snprintf(port_str, sizeof(port_str), "%d", target_port);
            uv_getaddrinfo_t *resolver_req = malloc(sizeof(*resolver_req));
            if (resolver_req) {
                resolver_req->data = cr;
                if (uv_getaddrinfo(g_loop, resolver_req, on_upstream_resolve,
                                   target_host, port_str, &hints) != 0) {
                    free(resolver_req); free(cr->payload); free(cr);
                }
            } else {
                free(cr->payload); free(cr);
            }
        }
    }
}
