/*
 * DNSTUN Management Server
 * 
 * Provides a headless management interface for decoupled TUI architecture.
 * Uses libuv for async I/O and supports multiple simultaneous TUI clients.
 */

#ifdef _WIN32
/* Include winsock2.h BEFORE any headers that might include windows.h */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "mgmt.h"
#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

/* ──────────────────────────────────────────────
   Internal Structures
 ────────────────────────────────────────────── */

struct mgmt_client {
    uv_tcp_t           handle;
    mgmt_server_t     *server;
    
    /* Read state */
    uint8_t           *read_buf;
    size_t             read_buf_len;
    size_t             read_buf_cap;
    size_t             frame_body_remaining;  /* bytes remaining in current frame */
    int                in_header;             /* currently reading header vs body */
    
    /* Connection info */
    char               ip[64];
    uint16_t           port;
    
    /* Client info from HELLO */
    uint8_t            client_type;
    uint32_t           capabilities;
    
    /* Write queue */
    struct mgmt_client *next_write;
    uv_buf_t           write_buf;
    int                write_pending;
    
    /* Link list */
    struct mgmt_client *next;
    struct mgmt_client *prev;
};

struct mgmt_server {
    uv_loop_t         *loop;
    uv_timer_t         telemetry_timer;
    
    /* Listening socket */
    union {
        uv_tcp_t       tcp;
        int            unix_fd;  /* Unix domain socket fd */
    } listener;
    int               using_unix_socket;
    char               socket_path[256];
    
    /* Configuration */
    mgmt_config_t      config;
    
    /* Connected clients */
    mgmt_client_t     *clients;
    uint32_t           client_count;
    
    /* Statistics */
    mgmt_server_stats_t stats;
    
    /* Sequence counter for frames */
    uint32_t           sequence;
    
    /* State */
    int                running;
};

/* ──────────────────────────────────────────────
   Static Variables
 ────────────────────────────────────────────── */
static mgmt_server_t *g_server = NULL;

/* ──────────────────────────────────────────────
   Client Management
 ────────────────────────────────────────────── */

static mgmt_client_t *client_create(mgmt_server_t *server, uv_tcp_t *handle) {
    mgmt_client_t *client = calloc(1, sizeof(*client));
    if (!client) return NULL;
    
    client->server = server;
    client->read_buf_cap = server->config.read_buffer_size;
    client->read_buf = malloc(client->read_buf_cap);
    if (!client->read_buf) {
        free(client);
        return NULL;
    }
    
    /* Initialize libuv handle */
    client->handle.data = client;
    uv_tcp_init(server->loop, &client->handle);
    uv_tcp_keepalive(&client->handle, 1, 60);  /* 60s keepalive */
    
    /* Get peer address */
    struct sockaddr_in6 addr;
    int addrlen = sizeof(addr);
    if (uv_tcp_getpeername(handle, (struct sockaddr*)&addr, &addrlen) == 0) {
        if (addr.sin6_family == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in*)&addr;
            uv_inet_ntop(AF_INET, &a->sin_addr, client->ip, sizeof(client->ip));
            client->port = ntohs(a->sin_port);
        } else {
            uv_inet_ntop(AF_INET6, &addr.sin6_addr, client->ip, sizeof(client->ip));
            client->port = ntohs(addr.sin6_port);
        }
    }
    
    /* Add to client list */
    client->next = server->clients;
    if (server->clients) server->clients->prev = client;
    server->clients = client;
    server->client_count++;
    server->stats.total_connections++;
    
    return client;
}

static void client_destroy(mgmt_client_t *client) {
    if (!client) return;
    
    mgmt_server_t *server = client->server;
    
    /* Remove from list */
    if (client->prev) client->prev->next = client->next;
    else server->clients = client->next;
    if (client->next) client->next->prev = client->prev;
    server->client_count--;
    
    /* Close handle */
    if (!uv_is_closing((uv_handle_t*)&client->handle)) {
        uv_close((uv_handle_t*)&client->handle, NULL);
    }
    
    /* Free buffers */
    free(client->read_buf);
    if (client->write_buf.base) free(client->write_buf.base);
    
    /* Call disconnect callback */
    if (server->config.callbacks.on_disconnect) {
        server->config.callbacks.on_disconnect(client, server->config.callbacks.user_data);
    }
    
    free(client);
}

static void client_close(mgmt_client_t *client) {
    client_destroy(client);
}

/* ──────────────────────────────────────────────
   Frame Building Helpers
 ────────────────────────────────────────────── */

static void build_header(uint8_t *buf, uint16_t frame_type, uint32_t payload_len, uint32_t seq) {
    mgmt_write_be32(buf, MGMT_MAGIC);
    mgmt_write_be16(buf + 4, MGMT_PROTOCOL_VERSION);
    mgmt_write_be16(buf + 6, frame_type);
    mgmt_write_be32(buf + 8, payload_len);
    mgmt_write_be32(buf + 12, seq);
}

static mgmt_telemetry_frame_t *build_telemetry_frame(const tui_stats_t *stats) {
    static uint8_t frame_buf[sizeof(mgmt_telemetry_frame_t) + 256];
    mgmt_telemetry_frame_t *frame = (mgmt_telemetry_frame_t*)frame_buf;
    
    memset(frame, 0, sizeof(*frame));
    
    frame->header.magic = MGMT_MAGIC;
    frame->header.version = MGMT_PROTOCOL_VERSION;
    frame->header.frame_type = MGMT_FRAME_TELEMETRY;
    frame->header.length = sizeof(*frame) - MGMT_FRAME_HEADER_SIZE;
    
    /* Timestamp */
    frame->timestamp_ns = uv_hrtime();
    
    /* Throughput */
    frame->tx_bytes_sec = stats->tx_bytes_sec;
    frame->rx_bytes_sec = stats->rx_bytes_sec;
    frame->tx_total = stats->tx_total;
    frame->rx_total = stats->rx_total;
    
    /* Sessions */
    frame->active_sessions = stats->active_sessions;
    frame->max_sessions = DNSTUN_MAX_SESSIONS;
    
    /* Resolvers */
    frame->active_resolvers = stats->active_resolvers;
    frame->dead_resolvers = stats->dead_resolvers;
    frame->penalty_resolvers = stats->penalty_resolvers;
    
    /* DNS Stats */
    frame->queries_sent = stats->queries_sent;
    frame->queries_recv = stats->queries_recv;
    frame->queries_lost = stats->queries_lost;
    frame->queries_dropped = stats->queries_dropped;
    
    /* Server-specific */
    frame->server_connected = stats->server_connected;
    frame->last_server_rx_ms = stats->last_server_rx_ms;
    
    /* Flags */
    frame->encryption_enabled = 0;  /* TODO: get from config */
    frame->jitter_enabled = 0;
    frame->padding_enabled = 0;
    frame->chaffing_enabled = 0;
    
    /* Mode */
    strncpy(frame->mode, stats->mode, sizeof(frame->mode) - 1);
    
    return frame;
}

static mgmt_response_frame_t *build_response(uint32_t command_id, uint32_t status,
                                             const void *payload, size_t payload_len,
                                             uint32_t seq) {
    size_t total = sizeof(mgmt_response_frame_t) + payload_len;
    mgmt_response_frame_t *frame = malloc(total);
    if (!frame) return NULL;
    
    frame->header.magic = MGMT_MAGIC;
    frame->header.version = MGMT_PROTOCOL_VERSION;
    frame->header.frame_type = MGMT_FRAME_RESPONSE;
    frame->header.length = sizeof(*frame) - MGMT_FRAME_HEADER_SIZE + payload_len;
    frame->header.sequence = seq;
    
    frame->command_id = command_id;
    frame->status = status;
    frame->error_code = 0;
    frame->payload_len = payload_len;
    
    if (payload && payload_len > 0) {
        memcpy(frame->payload, payload, payload_len);
    }
    
    return frame;
}

/* ──────────────────────────────────────────────
   Write Queue Management
 ────────────────────────────────────────────── */

static void on_write_complete(uv_write_t *req, int status) {
    mgmt_client_t *client = (mgmt_client_t*)req->data;
    if (status < 0) {
        fprintf(stderr, "[MGMT] Write error: %s\n", uv_strerror(status));
        client_close(client);
        return;
    }
    
    client->server->stats.bytes_sent += client->write_buf.len;
    free(client->write_buf.base);
    client->write_buf.base = NULL;
    client->write_buf.len = 0;
    client->write_pending = 0;
}

static int queue_write(mgmt_client_t *client, const void *data, size_t len) {
    if (client->write_pending) {
        fprintf(stderr, "[MGMT] Client already has pending write\n");
        return -1;
    }
    
    uint8_t *buf = malloc(len);
    if (!buf) return -1;
    memcpy(buf, data, len);
    
    uv_write_t *req = malloc(sizeof(*req));
    if (!req) {
        free(buf);
        return -1;
    }
    
    client->write_buf.base = (char*)buf;
    client->write_buf.len = len;
    client->write_pending = 1;
    req->data = client;
    
    uv_write(req, (uv_stream_t*)&client->handle, &client->write_buf, 1, on_write_complete);
    return 0;
}

/* ──────────────────────────────────────────────
   Command Handling
 ────────────────────────────────────────────── */

static void handle_command(mgmt_client_t *client, const mgmt_command_frame_t *cmd) {
    mgmt_server_t *server = client->server;
    uint32_t cmd_type = cmd->header.frame_type;
    uint32_t cmd_id = cmd->command_id;
    
    server->stats.commands_received++;
    
    /* Send OK response by default */
    mgmt_response_frame_t *resp = build_response(cmd_id, MGMT_OK, NULL, 0, 
                                                  server->sequence++);
    if (resp) {
        queue_write(client, resp, MGMT_FRAME_HEADER_SIZE + resp->header.length);
        free(resp);
    }
    
    /* Invoke callback for additional processing */
    if (server->config.callbacks.on_command) {
        server->config.callbacks.on_command(
            client,
            cmd_type,
            cmd->payload,
            cmd->header.length - sizeof(cmd->command_type) - sizeof(cmd->command_id),
            server->config.callbacks.user_data
        );
    }
}

/* ──────────────────────────────────────────────
   Read Handling
 ────────────────────────────────────────────── */

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    mgmt_client_t *client = (mgmt_client_t*)handle->data;
    (void)suggested_size;
    
    /* Ensure buffer is large enough for header + largest payload */
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
        uint32_t seq = mgmt_read_be32(client->read_buf + pos + 12);
        
        /* Validate */
        if (magic != MGMT_MAGIC) {
            fprintf(stderr, "[MGMT] Invalid magic: 0x%08x\n", magic);
            client_close(client);
            return;
        }
        
        if (version > MGMT_PROTOCOL_VERSION) {
            fprintf(stderr, "[MGMT] Unsupported protocol version: %d\n", version);
            client_close(client);
            return;
        }
        
        /* Check if we have complete frame */
        size_t frame_size = MGMT_FRAME_HEADER_SIZE + length;
        if (pos + frame_size > client->read_buf_len) {
            break;  /* Wait for more data */
        }
        
        /* Process frame */
        switch (frame_type) {
            case MGMT_FRAME_HELLO:
                fprintf(stderr, "[MGMT] Client connected: %s:%d\n", 
                        client->ip, client->port);
                if (client->server->config.callbacks.on_connect) {
                    client->server->config.callbacks.on_connect(client, 
                        client->server->config.callbacks.user_data);
                }
                break;
                
            case MGMT_FRAME_COMMAND:
                handle_command(client, (mgmt_command_frame_t*)(client->read_buf + pos));
                break;
                
            case MGMT_FRAME_GOODBYE:
                fprintf(stderr, "[MGMT] Client disconnected: %s:%d\n", 
                        client->ip, client->port);
                client_close(client);
                return;
                
            case MGMT_FRAME_PING:
                /* Send PONG */
                {
                    uint8_t pong[MGMT_FRAME_HEADER_SIZE];
                    build_header(pong, MGMT_FRAME_PONG, 0, seq);
                    queue_write(client, pong, sizeof(pong));
                }
                break;
                
            default:
                fprintf(stderr, "[MGMT] Unknown frame type: %d\n", frame_type);
                break;
        }
        
        /* Move to next frame */
        pos += frame_size;
    }
    
    /* Compact buffer if needed */
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
        client_close(client);
        return;
    }
    
    if (nread == 0) return;
    
    client->read_buf_len += nread;
    process_read_buffer(client);
}

/* ──────────────────────────────────────────────
   Server Implementation
 ────────────────────────────────────────────── */

static void on_telemetry_timer(uv_timer_t *timer) {
    mgmt_server_t *server = (mgmt_server_t*)timer->data;
    
    /* Build telemetry frame with default stats */
    tui_stats_t stats = {0};
    mgmt_telemetry_frame_t *frame = build_telemetry_frame(&stats);
    
    /* Broadcast to all clients */
    for (mgmt_client_t *c = server->clients; c; c = c->next) {
        queue_write(c, frame, MGMT_FRAME_HEADER_SIZE + frame->header.length);
    }
}

static void on_client_connect(uv_stream_t *server_handle, int status) {
    if (status < 0) {
        fprintf(stderr, "[MGMT] Accept error: %s\n", uv_strerror(status));
        return;
    }
    
    mgmt_server_t *server = (mgmt_server_t*)server_handle->data;
    
    if (server->client_count >= server->config.max_clients) {
        fprintf(stderr, "[MGMT] Max clients reached, rejecting connection\n");
        return;
    }
    
    uv_tcp_t *client_handle = malloc(sizeof(*client_handle));
    if (!client_handle) return;
    
    uv_tcp_init(server->loop, client_handle);
    
    if (uv_accept(server_handle, (uv_stream_t*)client_handle) != 0) {
        uv_close((uv_handle_t*)client_handle, NULL);
        return;
    }
    
    mgmt_client_t *client = client_create(server, client_handle);
    if (!client) {
        uv_close((uv_handle_t*)client_handle, NULL);
        return;
    }
    
    /* Copy the handle into the client */
    memcpy(&client->handle, client_handle, sizeof(uv_tcp_t));
    client->handle.data = client;
    free(client_handle);
    
    uv_read_start((uv_stream_t*)&client->handle, on_alloc, on_read);
}

mgmt_server_t *mgmt_server_create(uv_loop_t *loop, const mgmt_config_t *config) {
    mgmt_server_t *server = calloc(1, sizeof(*server));
    if (!server) return NULL;
    
    server->loop = loop;
    server->config = *config;
    
    /* Set defaults */
    if (server->config.telemetry_interval_ms == 0)
        server->config.telemetry_interval_ms = 1000;
    if (server->config.max_clients == 0)
        server->config.max_clients = MGMT_MAX_CLIENTS;
    if (server->config.read_buffer_size == 0)
        server->config.read_buffer_size = 4096;
    
    /* Initialize listener */
    if (server->config.bind_addr[0] == '/') {
        /* Unix domain socket */
        server->using_unix_socket = 1;
        strncpy(server->socket_path, server->config.bind_addr, sizeof(server->socket_path) - 1);
    } else {
        /* TCP socket */
        server->using_unix_socket = 0;
        uv_tcp_init(loop, &server->listener.tcp);
        server->listener.tcp.data = server;
    }
    
    /* Initialize telemetry timer */
    uv_timer_init(loop, &server->telemetry_timer);
    server->telemetry_timer.data = server;
    
    g_server = server;
    return server;
}

int mgmt_server_start(mgmt_server_t *server) {
    int ret;
    
    if (server->using_unix_socket) {
#ifdef _WIN32
        fprintf(stderr, "[MGMT] Unix sockets not supported on Windows\n");
        return -1;
#else
        /* Remove existing socket file */
        unlink(server->socket_path);
        
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, server->socket_path, sizeof(addr.sun_path) - 1);
        
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        
        if (listen(fd, server->config.max_clients) < 0) {
            close(fd);
            return -1;
        }
        
        /* TODO: integrate with libuv for Unix sockets */
        server->listener.unix_fd = fd;
#endif
    } else {
        /* TCP binding */
        struct sockaddr_in addr;
        uv_ip4_addr(server->config.bind_addr, server->config.port, &addr);
        
        ret = uv_tcp_bind(&server->listener.tcp, (const struct sockaddr*)&addr, 0);
        if (ret != 0) {
            fprintf(stderr, "[MGMT] Bind error: %s\n", uv_strerror(ret));
            return ret;
        }
        
        ret = uv_listen((uv_stream_t*)&server->listener.tcp, 
                        server->config.max_clients, on_client_connect);
        if (ret != 0) {
            fprintf(stderr, "[MGMT] Listen error: %s\n", uv_strerror(ret));
            return ret;
        }
    }
    
    /* Start telemetry timer */
    uv_timer_start(&server->telemetry_timer, on_telemetry_timer,
                   server->config.telemetry_interval_ms,
                   server->config.telemetry_interval_ms);
    
    server->running = 1;
    fprintf(stderr, "[MGMT] Server started on %s:%d\n",
            server->config.bind_addr, server->config.port);
    
    return 0;
}

void mgmt_server_destroy(mgmt_server_t *server) {
    if (!server) return;
    
    server->running = 0;
    
    /* Stop timer */
    uv_timer_stop(&server->telemetry_timer);
    
    /* Close all clients */
    while (server->clients) {
        client_destroy(server->clients);
    }
    
    /* Close listener */
    if (server->using_unix_socket) {
#ifndef _WIN32
        close(server->listener.unix_fd);
        unlink(server->socket_path);
#endif
    } else {
        uv_close((uv_handle_t*)&server->listener.tcp, NULL);
    }
    
    if (g_server == server) g_server = NULL;
    free(server);
}

int mgmt_server_is_running(mgmt_server_t *server) {
    return server && server->running;
}

void mgmt_broadcast_telemetry(mgmt_server_t *server, const tui_stats_t *stats) {
    if (!server || !server->running) return;
    
    mgmt_telemetry_frame_t *frame = build_telemetry_frame(stats);
    
    for (mgmt_client_t *c = server->clients; c; c = c->next) {
        queue_write(c, frame, MGMT_FRAME_HEADER_SIZE + frame->header.length);
    }
}

int mgmt_send_response(mgmt_server_t *server, mgmt_client_t *client,
                       uint32_t command_id, uint32_t status,
                       const void *payload, size_t payload_len) {
    mgmt_response_frame_t *resp = build_response(command_id, status, 
                                                  payload, payload_len,
                                                  server->sequence++);
    if (!resp) return -1;
    
    int ret = queue_write(client, resp, MGMT_FRAME_HEADER_SIZE + resp->header.length);
    free(resp);
    return ret;
}

void mgmt_get_stats(mgmt_server_t *server, mgmt_server_stats_t *out_stats) {
    if (server && out_stats) {
        *out_stats = server->stats;
        out_stats->active_clients = server->client_count;
    }
}

const char *mgmt_client_get_addr(mgmt_client_t *client) {
    return client ? client->ip : "";
}

void mgmt_client_close(mgmt_client_t *client) {
    if (client) client_close(client);
}

mgmt_server_t *mgmt_init_default(uv_loop_t *loop) {
    mgmt_config_t config = {0};
    strncpy(config.bind_addr, "127.0.0.1", sizeof(config.bind_addr) - 1);
    config.port = MGMT_DEFAULT_PORT;
    config.telemetry_interval_ms = 1000;
    config.max_clients = MGMT_MAX_CLIENTS;
    
    return mgmt_server_create(loop, &config);
}

void mgmt_broadcast(const tui_stats_t *stats) {
    if (g_server) {
        mgmt_broadcast_telemetry(g_server, stats);
    }
}
