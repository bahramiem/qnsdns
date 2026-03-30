/**
 * @file client/socks5.c
 * @brief Implementation of the local SOCKS5 server.
 */

#include "socks5.h"
#include "client_common.h"
#include "session.h"
#include "dns_tx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Internal structure for each SOCKS5 client connection */
typedef struct {
    uv_tcp_t tcp;
    int      session_idx;
    int      state; /* 0=Methods, 1=Request, 2=TunnelData */
    uint8_t  buf[4096];
    size_t   busy;
} socks5_client_t;

static void on_socks5_close(uv_handle_t *h) {
    socks5_client_t *c = h->data;
    if (c->session_idx >= 0) {
        session_close(c->session_idx);
    }
    free(c);
}

static void on_socks5_write_done(uv_write_t *req, int status) {
    if (req->data) free(req->data);
    free(req);
    (void)status;
}

static void socks5_send_reply(socks5_client_t *c, const uint8_t *data, size_t len) {
    uv_write_t *req = malloc(sizeof(uv_write_t));
    if (!req) return;
    
    uint8_t *copy = malloc(len);
    if (!copy) { free(req); return; }
    memcpy(copy, data, len);
    req->data = copy;
    
    uv_buf_t buf = uv_buf_init((char *)copy, (unsigned int)len);
    uv_write(req, (uv_stream_t *)&c->tcp, &buf, 1, on_socks5_write_done);
}

static void on_socks5_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_socks5_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    socks5_client_t *c = stream->data;
    if (nread <= 0) {
        if (buf->base) free(buf->base);
        if (!uv_is_closing((uv_handle_t *)stream)) {
            uv_close((uv_handle_t *)stream, on_socks5_close);
        }
        return;
    }

    const uint8_t *data = (const uint8_t *)buf->base;
    size_t len = (size_t)nread;

    if (c->state == 0) { /* SOCKS5 Methods Selection */
        if (len >= 3 && data[0] == 0x05) {
            uint8_t reply[2] = {0x05, 0x00}; /* NO AUTH */
            socks5_send_reply(c, reply, 2);
            c->state = 1;
        }
    } else if (c->state == 1) { /* SOCKS5 CONNECT Request */
        if (len >= 10 && data[0] == 0x05 && data[1] == 0x01) {
            uint8_t atype = data[3];
            int sidx = session_alloc();
            if (sidx >= 0) {
                session_t *s = session_get(sidx);
                s->session_id = session_get_unused_id();
                c->session_idx = sidx;
                s->client_ptr = c;
                
                /* Parse target host/port for logging */
                if (atype == 0x01) { /* IPv4 */
                    snprintf(s->target_host, sizeof(s->target_host), "%d.%d.%d.%d", 
                             data[4], data[5], data[6], data[7]);
                    s->target_port = (uint16_t)((data[8] << 8) | data[9]);
                } else if (atype == 0x03) { /* Domain */
                    uint8_t dlen = data[4];
                    if (dlen < sizeof(s->target_host)) {
                        memcpy(s->target_host, data + 5, dlen);
                        s->target_host[dlen] = '\0';
                        s->target_port = (uint16_t)((data[5 + dlen] << 8) | data[6 + dlen]);
                    }
                }
                
                LOG_INFO("SOCKS5 CONNECT: %s:%d (Sess %d, wire %u)\n", 
                         s->target_host, s->target_port, sidx, s->session_id);

                /* Replying success to SOCKS5 client optimistically */
                uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                socks5_send_reply(c, reply, 10);
                c->state = 2; /* Move to tunnel data mode */

                /* Send initial handshake to server to start the session */
                dns_tx_send_handshake(sidx);
            } else {
                /* Server busy */
                uint8_t reply[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                socks5_send_reply(c, reply, 10);
                uv_close((uv_handle_t *)stream, on_socks5_close);
            }
        }
    } else if (c->state == 2) { /* Tunneling Data */
        session_t *s = session_get(c->session_idx);
        if (s && !s->closed) {
            /* Append data to session's outbound buffer */
            size_t need = s->send_len + len;
            if (need > s->send_cap) {
                s->send_buf = realloc(s->send_buf, need + 8192);
                s->send_cap = need + 8192;
            }
            if (s->send_buf) {
                memcpy(s->send_buf + s->send_len, data, len);
                s->send_len += len;
                s->last_active = time(NULL);
            }
            if (g_client_stats) {
                g_client_stats->tx_total += len;
                g_client_stats->tx_bytes_sec += len;
            }
        }
    }

    if (buf->base) free(buf->base);
}

static void on_socks5_connection(uv_stream_t *server, int status) {
    if (status < 0) return;

    socks5_client_t *c = calloc(1, sizeof(socks5_client_t));
    if (!c) return;

    c->session_idx = -1;
    uv_tcp_init(server->loop, &c->tcp);
    c->tcp.data = c;

    if (uv_accept(server, (uv_stream_t *)&c->tcp) == 0) {
        uv_read_start((uv_stream_t *)&c->tcp, on_socks5_alloc, on_socks5_read);
    } else {
        uv_close((uv_handle_t *)&c->tcp, on_socks5_close);
    }
}

/* ── Public API Implementation ────────────────────────────────────────────── */

static uv_tcp_t g_socks_listener;

void socks5_server_init(uv_loop_t *loop, const char *bind_addr, int port) {
    if (!loop) return;

    struct sockaddr_in addr;
    uv_ip4_addr(bind_addr, port, &addr);

    uv_tcp_init(loop, &g_socks_listener);
    uv_tcp_bind(&g_socks_listener, (const struct sockaddr *)&addr, 0);

    int r = uv_listen((uv_stream_t *)&g_socks_listener, 128, on_socks5_connection);
    if (r != 0) {
        LOG_ERR("SOCKS5 Listener failed on %s:%d: %s\n", bind_addr, port, uv_strerror(r));
    } else {
        LOG_INFO("SOCKS5 Server listening on %s:%d\n", bind_addr, port);
    }
}

void socks5_server_shutdown(void) {
    if (!uv_is_closing((uv_handle_t *)&g_socks_listener)) {
        uv_close((uv_handle_t *)&g_socks_listener, NULL);
    }
}
