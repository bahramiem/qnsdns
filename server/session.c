/**
 * @file server/session.c
 * @brief Implementation of upstream session management.
 */

#include "session.h"
#include "server_common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Global pointers (accessible to handlers) */
static uv_loop_t     *g_session_loop = NULL;
static srv_session_t  g_sessions[SRV_MAX_SESSIONS];
static int            g_sidx_store[SRV_MAX_SESSIONS];

/**
 * @brief Connection request context for async DNS/TCP setup.
 */
typedef struct {
    uv_connect_t connect;
    int          session_idx;
    uint8_t     *payload;
    size_t       payload_len;
    char         target_host[256];
    uint16_t     target_port;
} connect_req_t;

/* ── Upstream TCP Handlers ────────────────────────────────────────────────── */

static void on_upstream_write(uv_write_t *w, int status) {
    if (w->data) free(w->data);
    (void)status;
}

static void on_upstream_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    int *sidx_ptr = h->data;
    int sidx = sidx_ptr ? *sidx_ptr : -1;
    if (sidx < 0 || sidx >= SRV_MAX_SESSIONS || !g_sessions[sidx].used) {
        buf->base = NULL;
        buf->len = 0;
        return;
    }
    buf->base = (char *)malloc(8192);
    buf->len = buf->base ? 8192 : 0;
}

static void on_upstream_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    int *sidx_ptr = s->data;
    int sidx = sidx_ptr ? *sidx_ptr : -1;
    if (sidx < 0 || sidx >= SRV_MAX_SESSIONS) {
        if (buf->base) free(buf->base);
        return;
    }
    srv_session_t *sess = &g_sessions[sidx];

    if (nread <= 0) {
        if (buf->base) free(buf->base);
        if (sess->tcp_connected) {
            /* Upstream closed - signal client with SOCKS5 failure if still connected */
            uint8_t socks5_fail[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            session_send_status(sess, 0x01); /* Prepend error */
            
            if (!uv_is_closing((uv_handle_t *)&sess->upstream_tcp))
                uv_close((uv_handle_t *)&sess->upstream_tcp, NULL);
            sess->tcp_connected = false;
        }
        return;
    }

    /* SOCKS5 Filter: Don't forward the successful handshake reply (10-byte success) to the client.
     * The client's optimistic protocol already assumes success once the TCP connects. */
    if (nread >= 4 && buf->base[0] == 0x05 && buf->base[1] == 0x00 && 
        buf->base[2] == 0x00 && buf->base[3] == 0x01) {
        LOG_DEBUG("Sess %d: SOCKS5 success filtered\n", sidx);
        
        /* If there's following data (e.g. HTTP response header), buffer it */
        if (nread > 10) {
            size_t http_len = (size_t)nread - 10;
            size_t need = sess->upstream_len + http_len;
            if (need > sess->upstream_cap) {
                sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
                sess->upstream_cap = need + 8192;
            }
            if (sess->upstream_buf) {
                memcpy(sess->upstream_buf + sess->upstream_len, buf->base + 10, http_len);
                sess->upstream_len += http_len;
            }
        }
    } else {
        /* Standard Data: Append to session buffer for DNS tunnel delivery */
        size_t need = sess->upstream_len + (size_t)nread;
        if (need > sess->upstream_cap) {
            sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
            sess->upstream_cap = need + 8192;
        }
        if (sess->upstream_buf) {
            memcpy(sess->upstream_buf + sess->upstream_len, buf->base, (size_t)nread);
            sess->upstream_len += (size_t)nread;
        }
    }

    if (g_server_stats) {
        g_server_stats->rx_total += (size_t)nread;
        g_server_stats->rx_bytes_sec += (size_t)nread;
    }
    
    if (buf->base) free(buf->base);
}

static void on_upstream_connect(uv_connect_t *req, int status) {
    connect_req_t *cr = (connect_req_t *)req;
    srv_session_t *sess = &g_sessions[cr->session_idx];

    if (status != 0) {
        LOG_ERR("Connect failed for sess %d: %s\n", cr->session_idx, uv_strerror(status));
        session_send_status(sess, 0x01); /* General failure */
        if (cr->payload) free(cr->payload);
        free(cr);
        return;
    }

    if (sess->tcp_connected) {
        /* Stale connection (session was reused) */
        if (cr->payload) free(cr->payload);
        free(cr);
        return;
    }

    sess->tcp_connected = true;
    sess->upstream_tcp.data = &g_sidx_store[cr->session_idx];
    uv_read_start((uv_stream_t *)&sess->upstream_tcp, on_upstream_alloc, on_upstream_read);

    /* Send initial payload if present */
    if (cr->payload && cr->payload_len > 0) {
        session_upstream_write(sess, cr->payload, cr->payload_len);
    }

    /* Signal success to client Proxy */
    session_send_status(sess, 0x00);

    if (cr->payload) free(cr->payload);
    free(cr);
}

static void on_upstream_resolve(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    connect_req_t *cr = (connect_req_t *)resolver->data;
    srv_session_t *sess = &g_sessions[cr->session_idx];

    if (status != 0 || !res) {
        LOG_ERR("DNS Resolution failed for sess %d: %s\n", cr->session_idx, uv_strerror(status));
        session_send_status(sess, 0x04); /* Host unreachable */
        if (cr->payload) free(cr->payload);
        free(cr);
        free(resolver);
        if (res) uv_freeaddrinfo(res);
        return;
    }

    /* Start the TCP connection */
    uv_tcp_connect(&cr->connect, &sess->upstream_tcp, res->ai_addr, on_upstream_connect);

    uv_freeaddrinfo(res);
    free(resolver);
}

/* ── Public API Implementation ────────────────────────────────────────────── */

void session_manager_init(uv_loop_t *loop) {
    g_session_loop = loop;
    memset(g_sessions, 0, sizeof(g_sessions));
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        g_sidx_store[i] = i;
    }
    LOG_INFO("Session Manager initialized (%d max slots)\n", SRV_MAX_SESSIONS);
}

srv_session_t* session_find_by_id(uint8_t id) {
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        if (g_sessions[i].used && g_sessions[i].session_id == id) {
            return &g_sessions[i];
        }
    }
    return NULL;
}

srv_session_t* session_alloc_by_id(uint8_t id) {
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        if (!g_sessions[i].used) {
            memset(&g_sessions[i], 0, sizeof(srv_session_t));
            g_sessions[i].session_id = id;
            g_sessions[i].used = true;
            g_sessions[i].last_active = time(NULL);
            if (g_server_stats) g_server_stats->active_sessions++;
            return &g_sessions[i];
        }
    }
    return NULL;
}

void session_close(srv_session_t *s) {
    if (!s || !s->used) return;
    
    if (s->tcp_connected && !uv_is_closing((uv_handle_t *)&s->upstream_tcp)) {
        uv_close((uv_handle_t *)&s->upstream_tcp, NULL);
    }
    
    if (s->upstream_buf) free(s->upstream_buf);

    if (s->burst_symbols) {
        for (int i = 0; i < s->burst_count_needed; i++) {
            if (s->burst_symbols[i]) free(s->burst_symbols[i]);
        }
        free(s->burst_symbols);
    }

    s->used = false;
    if (g_server_stats && g_server_stats->active_sessions > 0) {
        g_server_stats->active_sessions--;
    }
}

void session_manager_tick_idle(int timeout_sec) {
    time_t now = time(NULL);
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        if (g_sessions[i].used && (now - g_sessions[i].last_active > timeout_sec)) {
            LOG_INFO("Session %d (ID %u) idle timeout\n", i, g_sessions[i].session_id);
            session_close(&g_sessions[i]);
        }
    }
}

void session_upstream_write(srv_session_t *s, const uint8_t *data, size_t len) {
    if (!s || !s->tcp_connected || !data || len == 0) return;

    uv_write_t *w = malloc(sizeof(uv_write_t) + len);
    if (!w) return;
    
    uint8_t *copy = (uint8_t *)(w + 1);
    memcpy(copy, data, len);
    w->data = w; /* Save pointer for freeing in callback */
    
    uv_buf_t buf = uv_buf_init((char *)copy, (unsigned int)len);
    uv_write(w, (uv_stream_t *)&s->upstream_tcp, &buf, 1, on_upstream_write);

    if (g_server_stats) {
        g_server_stats->tx_total += len;
        g_server_stats->tx_bytes_sec += len;
    }
}

void session_send_status(srv_session_t *s, uint8_t status) {
    if (!s || s->status_sent) return;

    size_t need = s->upstream_len + 1;
    if (need > s->upstream_cap) {
        s->upstream_buf = realloc(s->upstream_buf, need + 8192);
        s->upstream_cap = need + 8192;
    }

    if (s->upstream_buf) {
        if (s->upstream_len > 0) {
            memmove(s->upstream_buf + 1, s->upstream_buf, s->upstream_len);
        }
        s->upstream_buf[0] = status;
        s->upstream_len++;
        s->status_sent = true;
        LOG_DEBUG("Sess ID %u: queued status %02x at seq %u\n", 
                  s->session_id, status, s->downstream_seq);
    }
}

void session_upstream_connect(srv_session_t *s, const char *target_host, uint16_t target_port, 
                              const uint8_t *payload, size_t payload_len) {
    if (!s || s->tcp_connected) return;

    connect_req_t *cr = calloc(1, sizeof(connect_req_t));
    if (!cr) return;

    /* Calculate session index */
    cr->session_idx = (int)(s - g_sessions);
    strncpy(cr->target_host, target_host, sizeof(cr->target_host) - 1);
    cr->target_port = target_port;

    if (payload && payload_len > 0) {
        cr->payload = malloc(payload_len);
        if (cr->payload) {
            memcpy(cr->payload, payload, payload_len);
            cr->payload_len = payload_len;
        }
    }

    uv_tcp_init(g_session_loop, &s->upstream_tcp);
    uv_tcp_nodelay(&s->upstream_tcp, 1);

    /* Resolve address and connect */
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", target_port);
    
    uv_getaddrinfo_t *resolver = malloc(sizeof(uv_getaddrinfo_t));
    if (!resolver) { free(cr); return; }
    
    resolver->data = cr;
    int r = uv_getaddrinfo(g_session_loop, resolver, on_upstream_resolve, target_host, port_str, &hints);
    if (r != 0) {
        LOG_ERR("Failed to start name resolution for %s\n", target_host);
        free(resolver);
        free(cr);
    }
}

int session_get_snapshots(tui_client_snap_t *out, int max_clients) {
    int count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < SRV_MAX_SESSIONS && count < max_clients; i++) {
        if (g_sessions[i].used) {
            uv_ip4_name(&g_sessions[i].client_addr, out[count].ip, sizeof(out[count].ip));
            out[count].downstream_mtu = g_sessions[i].cl_downstream_mtu;
            out[count].loss_pct       = g_sessions[i].cl_loss_pct;
            out[count].fec_k          = g_sessions[i].cl_fec_k;
            out[count].enc_format     = g_sessions[i].cl_enc_format;
            out[count].idle_sec       = (uint32_t)(now - g_sessions[i].last_active);
            strncpy(out[count].user_id, g_sessions[i].user_id, sizeof(out[count].user_id) - 1);
            count++;
        }
    }
    return count;
}
void session_upstream_write_to_buffer(srv_session_t *s, const uint8_t *data, size_t len) {
    if (!s || !s->used || !data || len == 0) return;
    
    size_t need = s->upstream_len + len;
    if (need > s->upstream_cap) {
        size_t new_cap = need + 8192;
        uint8_t *new_buf = realloc(s->upstream_buf, new_cap);
        if (!new_buf) return;
        s->upstream_buf = new_buf;
        s->upstream_cap = new_cap;
    }
    
    if (s->upstream_buf) {
        memcpy(s->upstream_buf + s->upstream_len, data, len);
        s->upstream_len += len;
    }
}
