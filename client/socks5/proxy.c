/**
 * @file client/socks5/proxy.c
 * @brief SOCKS5 Proxy Server Implementation (Client Side)
 *
 * Extracted from client/main.c lines 1986-2501.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "uv.h"
#include "shared/config.h"
#include "shared/types.h"

#include "client/session/session.h"
#include "client/dns/query.h"
#include "client/socks5/proxy.h"
#include "shared/tui.h"

/* ── Externals from client/main.c ── */
extern uv_loop_t       *g_loop;
extern dnstun_config_t  g_cfg;
extern tui_stats_t      g_stats;
extern session_t        g_sessions[];

/* Logging helpers */
extern int log_level(void);



/* Helper */
static uint8_t get_unused_session_id(void) {
    static uint8_t next_id = 1;
    uint8_t start = next_id;
        do {
            uint8_t cand = next_id++;
            if (cand == 0) cand = next_id++;
            bool in_use = false;
            for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
                if (!g_sessions[i].closed && g_sessions[i].established &&
                    g_sessions[i].session_id == cand) {
                    in_use = true; break;
                }
            }
        if (!in_use) return cand;
    } while (next_id != start);
    return (uint8_t)(rand() % 255 + 1);
}

/* ────────────────────────────────────────────── */
/*  SOCKS5 Implementation                         */
/* ────────────────────────────────────────────── */

void on_socks5_close(uv_handle_t *h) {
    socks5_client_t *c = h->data;
    if (c && c->session_idx >= 0 && c->session_idx < DNSTUN_MAX_SESSIONS) {
        session_t *s = &g_sessions[c->session_idx];
        DBGLOG("[CLOSE] session_idx=%d session_id=%u target=%s:%u tx_next=%u\n",
               c->session_idx, s->session_id,
               s->target_host, s->target_port, s->tx_next);
        s->closed    = true;
        s->client_ptr = NULL;
        if (g_stats.active_sessions > 0)
            g_stats.active_sessions--;
    }
    free(c);
}

static void on_socks5_write_done(uv_write_t *w, int status) {
    (void)status;
    free(w);
}

void socks5_send(socks5_client_t *c, const uint8_t *data, size_t len) {
    uint8_t first = (len > 0) ? data[0] : 0;
    DBGLOG("[SOCKS5_SEND] state=%d session_idx=%d len=%zu first=0x%02x\n",
           c ? c->state : -1, c ? c->session_idx : -1, len, first);
    uv_write_t *w = malloc(sizeof(*w) + len);
    if (!w) return;
    uint8_t *copy = (uint8_t*)(w + 1);
    memcpy(copy, data, len);
    uv_buf_t buf = uv_buf_init((char*)copy, (unsigned)len);
    uv_write(w, (uv_stream_t*)&c->tcp, &buf, 1, on_socks5_write_done);
}

void socks5_flush_recv_buf(socks5_client_t *c) {
    if (c->session_idx < 0 || c->session_idx >= DNSTUN_MAX_SESSIONS) {
        LOG_DEBUG("[SOCKS5_FLUSH_SKIP] invalid session_idx=%d\n", c->session_idx);
        return;
    }
    session_t *s = &g_sessions[c->session_idx];
    if (s->closed || s->recv_len == 0) {
        LOG_DEBUG("[SOCKS5_FLUSH_SKIP] sid=%u closed=%d recv_len=%zu\n",
                  s->session_id, s->closed ? 1 : 0, s->recv_len);
        return;
    }

    LOG_DEBUG("[SOCKS5_FLUSH] sid=%u state=%d recv_len=%zu\n",
              s->session_id, c->state, s->recv_len);
    socks5_send(c, s->recv_buf, s->recv_len);
    s->recv_len = 0;
}

static size_t socks5_handle_data(socks5_client_t *c, const uint8_t *data, size_t len) {
    if (c->state == 0) {
        if (len >= 2 && data[0] == 0x05) {
            uint8_t nmethods = data[1];
            size_t greeting_len = 2 + nmethods;
            if (len >= greeting_len) {
                bool no_auth_supported = false;
                for (int i = 0; i < nmethods; i++) {
                    if (data[2 + i] == 0x00) { no_auth_supported = true; break; }
                }
                if (no_auth_supported) {
                    uint8_t reply[2] = {0x05, 0x00};
                    socks5_send(c, reply, 2);
                    c->state = 1;
                } else {
                    uint8_t reply[2] = {0x05, 0xFF};
                    socks5_send(c, reply, 2);
                    uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
                }
                return greeting_len;
            }
        }
        return 0;
    }

    if (c->state == 1) {
        uint8_t atype = (len >= 4) ? data[3] : 0;
        size_t min_len;
        
        if (atype == 0x01) { min_len = 10; }
        else if (atype == 0x03) {
            if (len < 5) return 0;
            min_len = 5 + data[4] + 2;
        }
        else if (atype == 0x04) { min_len = 22; }
        else {
            uint8_t err[10] = {0x05, 0x08, 0x00, 0x01, 0,0,0,0,0,0};
            socks5_send(c, err, 10);
            uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
            return len;
        }
        
        if (len < min_len) return 0;
        
        if (data[0] != 0x05) return 0;
        if (data[1] != 0x01) {
            uint8_t err[10] = {0x05, 0x07, 0x00, 0x01, 0,0,0,0,0,0};
            socks5_send(c, err, 10);
            uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
            return min_len;
        }

        int session_idx = -1;
        for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
            if (g_sessions[i].closed || !g_sessions[i].established) {
                session_idx = i;
                break;
            }
        }
        if (session_idx < 0) {
            uint8_t err[10] = {0x05,0x05,0x00,0x01,0,0,0,0,0,0};
            socks5_send(c, err, 10);
            return min_len;
        }

        session_t *sess = &g_sessions[session_idx];
        if (sess->send_buf) { free(sess->send_buf); }
        if (sess->recv_buf) { free(sess->recv_buf); }
        memset(sess, 0, sizeof(*sess));
        sess->session_id  = get_unused_session_id();
        sess->established = true;
        sess->closed      = false;
        sess->last_active = time(NULL);

        reorder_buffer_init(&sess->reorder_buf);

        if (atype == 0x01) {
            snprintf(sess->target_host, sizeof(sess->target_host),
                     "%d.%d.%d.%d", data[4],data[5],data[6],data[7]);
            sess->target_port = (uint16_t)((data[8]<<8)|data[9]);
        } else if (atype == 0x03) {
            uint8_t dlen = data[4];
            if (dlen >= sizeof(sess->target_host)) return min_len;
            memcpy(sess->target_host, data+5, dlen);
            sess->target_host[dlen] = '\0';
            sess->target_port = (uint16_t)((data[5+dlen]<<8)|data[6+dlen]);
        } else if (atype == 0x04) {
            char ipv6_str[46];
            inet_ntop(AF_INET6, data + 4, ipv6_str, sizeof(ipv6_str));
            strncpy(sess->target_host, ipv6_str, sizeof(sess->target_host) - 1);
            sess->target_port = (uint16_t)((data[20]<<8)|data[21]);
        }

        c->session_idx = session_idx;
        c->state = 2;
        sess->client_ptr = c;
        sess->socks5_connected = false;

        g_stats.socks5_total_conns++;
        snprintf(g_stats.socks5_last_target, sizeof(g_stats.socks5_last_target),
                 "%s:%d", sess->target_host, sess->target_port);
        g_stats.active_sessions++;

        send_mtu_handshake(session_idx);

        reorder_buffer_free(&sess->reorder_buf);
        sess->reorder_buf.expected_seq = 0;

        if (min_len > 0) {
            size_t new_cap = min_len + 4096;
            if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
            uint8_t *new_buf = realloc(sess->send_buf, new_cap);
            if (new_buf) {
                sess->send_buf = new_buf;
                sess->send_cap = new_cap;
                memcpy(sess->send_buf, data, min_len);
                sess->send_len = min_len;
            }
        }

        uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0};
        socks5_send(c, reply, 10);
        sess->socks5_connected = true;
        
        return min_len;
    }

    if (c->state == 2) {
        session_t *sess = &g_sessions[c->session_idx];
        sess->last_active = time(NULL);

        size_t new_len = sess->send_len + len;
        if (new_len > sess->send_cap) {
            if (sess->send_len >= MAX_SESSION_BUFFER) {
                size_t drop_len = (len > sess->send_len) ? sess->send_len : len;
                memmove(sess->send_buf, sess->send_buf + drop_len, sess->send_len - drop_len);
                sess->send_len -= drop_len;
                new_len = sess->send_len + len;
            }
            size_t new_cap = new_len + 4096;
            if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
            uint8_t *new_buf = realloc(sess->send_buf, new_cap);
            if (new_buf) {
                sess->send_buf = new_buf;
                sess->send_cap = new_cap;
            } else {
                return 0;
            }
        }
        memcpy(sess->send_buf + sess->send_len, data, len);
        sess->send_len += len;
        LOG_DEBUG("[SOCKS5_BUF] sid=%u state=2 added=%zu total=%zu\n",
                  sess->session_id, len, sess->send_len);
        g_stats.tx_total += len;
        g_stats.tx_bytes_sec += len;
        return len;
    }
    
    return 0;
}

static void on_socks5_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    socks5_client_t *c = s->data;

    if (nread < 0) {
        DBGLOG("[SOCKS5_READ] error nread=%zd state=%d session_idx=%d\n",
               nread, c ? c->state : -1, c ? c->session_idx : -1);
        if (!uv_is_closing((uv_handle_t*)s))
            uv_close((uv_handle_t*)s, on_socks5_close);
        return;
    }

    if (nread == 0) {
        if (c->state == 2 && !uv_is_closing((uv_handle_t*)s))
            uv_close((uv_handle_t*)s, on_socks5_close);
        return;
    }

    size_t incoming = (size_t)nread;
    if (c->buf_len + incoming > sizeof(c->buf)) {
        DBGLOG("[SOCKS5_READ] buffer overflow incoming=%zd buf_len=%zu -> resetting\n",
               incoming, c->buf_len);
        c->buf_len = 0;
    } else {
        DBGLOG("[SOCKS5_READ] incoming=%zd buf_len before=%zu after=%zu",
               incoming, c->buf_len, c->buf_len + incoming);
        c->buf_len += incoming;
    }

    DBGLOG("[SOCKS5_READ] processing buf_len=%zu state=%d session_idx=%d\n",
           c->buf_len, c ? c->state : -1, c ? c->session_idx : -1);
    while (c->buf_len > 0) {
        size_t consumed = socks5_handle_data(c, c->buf, c->buf_len);
        DBGLOG("[SOCKS5_HANDLE_DATA] consumed=%zu buf_len before=%zu after=%zu\n",
               consumed, c->buf_len, c->buf_len - consumed);
        if (consumed == 0) break;
        if (consumed < c->buf_len) {
            memmove(c->buf, c->buf + consumed, c->buf_len - consumed);
        }
        c->buf_len -= consumed;
    }
}

static void on_socks5_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    socks5_client_t *c = h->data;
    (void)sz;
    buf->base = (char*)(c->buf + c->buf_len);
    buf->len  = sizeof(c->buf) - c->buf_len;
}

void on_socks5_connection(uv_stream_t *server, int status) {
    if (status < 0) return;

    socks5_client_t *c = calloc(1, sizeof(*c));
    if (!c) return;
    c->session_idx = -1;
    c->state = 0;

    uv_tcp_init(g_loop, &c->tcp);
    c->tcp.data = c;
    uv_tcp_nodelay(&c->tcp, 1);

    if (uv_accept(server, (uv_stream_t*)&c->tcp) == 0) {
        uv_read_start((uv_stream_t*)&c->tcp, on_socks5_alloc, on_socks5_read);
    } else {
        uv_close((uv_handle_t*)&c->tcp, on_socks5_close);
    }
}
