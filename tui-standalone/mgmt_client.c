/*
 * DNSTUN Management Client - Standalone TUI
 * 
 * Connects to dnstun-core via TCP socket and receives telemetry updates.
 */

#include "mgmt_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────────────────────────
   Internal Structures
 ────────────────────────────────────────────── */

struct mgmt_client {
    uv_loop_t         *loop;
    uv_tcp_t           socket;
    uv_timer_t         reconnect_timer;
    
    /* Connection state */
    mgmt_client_state_t state;
    char               host[64];
    int                port;
    
    /* Read buffer */
    uint8_t           *read_buf;
    size_t             read_buf_len;
    size_t             read_buf_cap;
    
    /* Cached telemetry */
    mgmt_telemetry_frame_t cached_telemetry;
    
    /* Callbacks */
    mgmt_telemetry_cb  telemetry_cb;
    void               *user_data;
    
    /* Reconnection */
    bool               reconnect_enabled;
    int                reconnect_attempts;
    int                max_reconnect_attempts;
};

/* ──────────────────────────────────────────────
   Frame Building Helpers
 ────────────────────────────────────────────── */

static void build_hello_frame(uint8_t *buf, uint32_t seq) {
    mgmt_write_be32(buf, MGMT_MAGIC);
    mgmt_write_be16(buf + 4, MGMT_PROTOCOL_VERSION);
    mgmt_write_be16(buf + 6, MGMT_FRAME_HELLO);
    mgmt_write_be32(buf + 8, 0);  /* No payload */
    mgmt_write_be32(buf + 12, seq);
}

static mgmt_telemetry_frame_t *parse_telemetry_frame(const uint8_t *data, size_t len) {
    if (len < MGMT_FRAME_HEADER_SIZE + sizeof(mgmt_telemetry_frame_t) - sizeof(uint8_t)) {
        return NULL;
    }
    return (mgmt_telemetry_frame_t*)data;
}

/* ──────────────────────────────────────────────
   Internal Functions
 ────────────────────────────────────────────── */

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    mgmt_client_t *client = (mgmt_client_t*)handle->data;
    (void)suggested_size;
    
    if (client->read_buf_cap < 8192) {
        client->read_buf = realloc(client->read_buf, 8192);
        client->read_buf_cap = 8192;
    }
    
    buf->base = (char*)client->read_buf + client->read_buf_len;
    buf->len = client->read_buf_cap - client->read_buf_len;
}

static void process_read_buffer(mgmt_client_t *client) {
    size_t pos = 0;
    
    while (pos + MGMT_FRAME_HEADER_SIZE <= client->read_buf_len) {
        /* Parse header */
        uint32_t magic = mgmt_read_be32(client->read_buf + pos);
        uint16_t version = mgmt_read_be16(client->read_buf + pos + 4);
        uint16_t frame_type = mgmt_read_be16(client->read_buf + pos + 6);
        uint32_t length = mgmt_read_be32(client->read_buf + pos + 8);
        
        /* Validate */
        if (magic != MGMT_MAGIC) {
            fprintf(stderr, "[MGMT] Invalid magic: 0x%08x\n", magic);
            return;
        }
        
        /* Check if we have complete frame */
        size_t frame_size = MGMT_FRAME_HEADER_SIZE + length;
        if (pos + frame_size > client->read_buf_len) {
            break;  /* Wait for more data */
        }
        
        /* Process frame */
        switch (frame_type) {
            case MGMT_FRAME_TELEMETRY: {
                mgmt_telemetry_frame_t *frame = parse_telemetry_frame(
                    client->read_buf + pos, frame_size);
                if (frame) {
                    /* Cache telemetry */
                    memcpy(&client->cached_telemetry, frame, 
                           sizeof(client->cached_telemetry));
                    
                    /* Invoke callback */
                    if (client->telemetry_cb) {
                        client->telemetry_cb(frame, client->user_data);
                    }
                }
                break;
            }
            
            case MGMT_FRAME_PING:
                /* Send PONG */
                {
                    uint8_t pong[MGMT_FRAME_HEADER_SIZE];
                    uint32_t seq = mgmt_read_be32(client->read_buf + pos + 12);
                    mgmt_write_be32(pong, MGMT_MAGIC);
                    mgmt_write_be16(pong + 4, MGMT_PROTOCOL_VERSION);
                    mgmt_write_be16(pong + 6, MGMT_FRAME_PONG);
                    mgmt_write_be32(pong + 8, 0);
                    mgmt_write_be32(pong + 12, seq);
                    uv_write_t *req = malloc(sizeof(*req));
                    if (req) {
                        uv_buf_t buf = uv_buf_init((char*)pong, sizeof(pong));
                        uv_write(req, (uv_stream_t*)&client->socket, &buf, 1, NULL);
                    }
                }
                break;
                
            default:
                break;
        }
        
        /* Move to next frame */
        pos += frame_size;
    }
    
    /* Compact buffer */
    if (pos > 0 && pos < client->read_buf_len) {
        memmove(client->read_buf, client->read_buf + pos, 
                client->read_buf_len - pos);
    }
    client->read_buf_len -= pos;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    mgmt_client_t *client = (mgmt_client_t*)stream->data;
    
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "[MGMT] Read error: %s\n", uv_strerror(nread));
        }
        
        client->state = MGMT_STATE_DISCONNECTED;
        
        /* Attempt reconnection */
        if (client->reconnect_enabled && 
            client->reconnect_attempts < client->max_reconnect_attempts) {
            client->state = MGMT_STATE_RECONNECTING;
            uint64_t delay = (1ULL << client->reconnect_attempts) * 1000;  /* Exponential backoff */
            if (delay > 30000) delay = 30000;  /* Cap at 30 seconds */
            uv_timer_start(&client->reconnect_timer, 
                          (uv_timer_cb)mgmt_client_connect, delay, 0);
        }
        return;
    }
    
    if (nread == 0) return;
    
    client->read_buf_len += nread;
    process_read_buffer(client);
}

static void on_connect(uv_connect_t *req, int status) {
    mgmt_client_t *client = (mgmt_client_t*)req->data;
    free(req);
    
    if (status < 0) {
        fprintf(stderr, "[MGMT] Connection failed: %s\n", uv_strerror(status));
        
        client->state = MGMT_STATE_DISCONNECTED;
        
        /* Attempt reconnection */
        if (client->reconnect_enabled && 
            client->reconnect_attempts < client->max_reconnect_attempts) {
            client->state = MGMT_STATE_RECONNECTING;
            uint64_t delay = (1ULL << client->reconnect_attempts) * 1000;
            if (delay > 30000) delay = 30000;
            client->reconnect_attempts++;
            uv_timer_start(&client->reconnect_timer, 
                          (uv_timer_cb)mgmt_client_connect, delay, 0);
        }
        return;
    }
    
    fprintf(stderr, "[MGMT] Connected to %s:%d\n", client->host, client->port);
    client->state = MGMT_STATE_CONNECTED;
    client->reconnect_attempts = 0;
    
    /* Send HELLO frame */
    uint8_t hello[MGMT_FRAME_HEADER_SIZE];
    build_hello_frame(hello, 0);
    uv_write_t *wreq = malloc(sizeof(*wreq));
    if (wreq) {
        uv_buf_t buf = uv_buf_init((char*)hello, sizeof(hello));
        uv_write(wreq, (uv_stream_t*)&client->socket, &buf, 1, NULL);
    }
    
    /* Start reading */
    uv_read_start((uv_stream_t*)&client->socket, on_alloc, on_read);
}

static void on_reconnect(uv_timer_t *timer) {
    mgmt_client_t *client = (mgmt_client_t*)timer->data;
    if (client && client->state == MGMT_STATE_RECONNECTING) {
        fprintf(stderr, "[MGMT] Reconnecting (attempt %d)...\n", 
                client->reconnect_attempts + 1);
        mgmt_client_connect(client, client->host, client->port);
    }
}

/* ──────────────────────────────────────────────
   Public API
 ────────────────────────────────────────────── */

mgmt_client_t *mgmt_client_create(uv_loop_t *loop) {
    mgmt_client_t *client = calloc(1, sizeof(*client));
    if (!client) return NULL;
    
    client->loop = loop;
    client->state = MGMT_STATE_DISCONNECTED;
    client->read_buf_cap = 4096;
    client->read_buf = malloc(client->read_buf_cap);
    client->reconnect_enabled = true;
    client->max_reconnect_attempts = 10;
    
    uv_tcp_init(loop, &client->socket);
    client->socket.data = client;
    
    uv_timer_init(loop, &client->reconnect_timer);
    client->reconnect_timer.data = client;
    
    return client;
}

void mgmt_client_destroy(mgmt_client_t *client) {
    if (!client) return;
    
    if (!uv_is_closing((uv_handle_t*)&client->socket)) {
        uv_close((uv_handle_t*)&client->socket, NULL);
    }
    uv_timer_stop(&client->reconnect_timer);
    uv_close((uv_handle_t*)&client->reconnect_timer, NULL);
    
    free(client->read_buf);
    free(client);
}

int mgmt_client_connect(mgmt_client_t *client, const char *host, int port) {
    if (!client) return -1;
    
    /* Stop any pending reconnect */
    uv_timer_stop(&client->reconnect_timer);
    
    /* Reset socket */
    if (uv_is_active((uv_handle_t*)&client->socket)) {
        uv_close((uv_handle_t*)&client->socket, NULL);
    }
    uv_tcp_init(client->loop, &client->socket);
    client->socket.data = client;
    
    strncpy(client->host, host, sizeof(client->host) - 1);
    client->port = port;
    client->state = MGMT_STATE_CONNECTING;
    
    /* Resolve and connect */
    struct sockaddr_in addr;
    uv_ip4_addr(host, port, &addr);
    
    uv_connect_t *req = malloc(sizeof(*req));
    if (!req) return -1;
    req->data = client;
    
    return uv_tcp_connect(req, &client->socket, 
                         (const struct sockaddr*)&addr, on_connect);
}

void mgmt_client_disconnect(mgmt_client_t *client) {
    if (!client) return;
    
    client->reconnect_enabled = false;
    uv_timer_stop(&client->reconnect_timer);
    
    if (!uv_is_closing((uv_handle_t*)&client->socket)) {
        uv_close((uv_handle_t*)&client->socket, NULL);
    }
    
    client->state = MGMT_STATE_DISCONNECTED;
}

mgmt_client_state_t mgmt_client_get_state(mgmt_client_t *client) {
    return client ? client->state : MGMT_STATE_DISCONNECTED;
}

const mgmt_telemetry_frame_t *mgmt_client_get_stats(mgmt_client_t *client) {
    return client ? &client->cached_telemetry : NULL;
}

void mgmt_client_set_callback(mgmt_client_t *client, 
                              mgmt_telemetry_cb callback, 
                              void *user_data) {
    if (client) {
        client->telemetry_cb = callback;
        client->user_data = user_data;
    }
}

int mgmt_client_send_command(mgmt_client_t *client, 
                             uint32_t command_type,
                             const void *payload,
                             size_t payload_len) {
    if (!client || client->state != MGMT_STATE_CONNECTED) {
        return -1;
    }
    
    size_t total = MGMT_FRAME_HEADER_SIZE + sizeof(uint32_t) * 2 + payload_len;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    
    static uint32_t cmd_id = 0;
    cmd_id++;
    
    mgmt_write_be32(buf, MGMT_MAGIC);
    mgmt_write_be16(buf + 4, MGMT_PROTOCOL_VERSION);
    mgmt_write_be16(buf + 6, MGMT_FRAME_COMMAND);
    mgmt_write_be32(buf + 8, sizeof(uint32_t) * 2 + payload_len);
    mgmt_write_be32(buf + 12, cmd_id);
    mgmt_write_be32(buf + 16, command_type);
    mgmt_write_be32(buf + 20, cmd_id);
    
    if (payload && payload_len > 0) {
        memcpy(buf + 24, payload, payload_len);
    }
    
    uv_write_t *req = malloc(sizeof(*req));
    if (!req) {
        free(buf);
        return -1;
    }
    
    uv_buf_t uvbuf = uv_buf_init((char*)buf, total);
    uv_write(req, (uv_stream_t*)&client->socket, &uvbuf, 1, NULL);
    
    return 0;
}

void mgmt_client_enable_reconnect(mgmt_client_t *client, bool enable) {
    if (client) {
        client->reconnect_enabled = enable;
        if (!enable) {
            uv_timer_stop(&client->reconnect_timer);
        }
    }
}

int mgmt_client_get_reconnect_attempts(mgmt_client_t *client) {
    return client ? client->reconnect_attempts : 0;
}
