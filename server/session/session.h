/**
 * @file server/session/session.h
 * @brief Server Session Lifecycle and Upstream TCP Connection Management
 *
 * Each tunnel client connection is tracked as an `srv_session_t`. The session
 * stores:
 *   - The 8-bit session ID agreed with the client
 *   - The upstream TCP handle to the real destination (e.g., google.com:80)
 *   - A buffer of undelivered upstream data (queued for DNS-TXT delivery)
 *   - FEC burst reassembly state
 *
 * Example flow:
 *   1. Client sends DNS query → server calls session_find_by_id().
 *   2. If not found, server calls session_alloc_by_id().
 *   3. After FEC decode, call upstream_connect() to reach the target host.
 *   4. When upstream closes, call session_close().
 */

#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "uv.h"
#include "shared/types.h"
#include "shared/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum simultaneous tunnel sessions the server handles */
#define SRV_MAX_SESSIONS 1024

/**
 * @brief Per-session state on the server side.
 *
 * One of these exists for every active client SOCKS5 tunnel.
 * Indexed by session_id (0-255) but stored in a flat array of SRV_MAX_SESSIONS.
 */
typedef struct srv_session {
    bool used;

    /** 8-bit session identifier chosen by the client */
    uint8_t session_id;

    /** libuv TCP handle for the upstream connection */
    uv_tcp_t upstream_tcp;
    bool tcp_connected;

    /** Heap-allocated buffer of bytes received from upstream, not yet delivered */
    uint8_t *upstream_buf;
    size_t upstream_len;
    size_t upstream_cap;

    /** Last known client address (the DNS resolver that sent this packet) */
    struct sockaddr_in client_addr;

    /* Client-reported capabilities (from capability_header_t or handshake_packet_t) */
    uint16_t cl_upstream_mtu;
    uint16_t cl_downstream_mtu;
    uint8_t  cl_enc_format;
    uint8_t  cl_loss_pct;
    uint8_t  cl_fec_k;
    char     user_id[16];

    /* FEC burst reassembly state */
    uint16_t  burst_seq_start;
    int       burst_count_needed;
    int       burst_received;
    uint8_t **burst_symbols;
    size_t    burst_symbol_len;
    uint64_t  burst_oti_common;
    uint32_t  burst_oti_scheme;
    bool      burst_has_oti;
    bool      burst_decoded;

    /**
     * Set true once the client sends a capability/MTU handshake.
     * After this, downstream_seq is used for ALL replies so the client's
     * reorder buffer receives a gapless monotonic stream.
     */
    bool handshake_done;

    /** Next sequence number to assign for downstream packets (server → client) */
    uint16_t downstream_seq;

    bool      status_sent;
    time_t    last_active;

    /**
     * Retransmit slot: last sent downstream payload.
     * Re-sent on every poll until new upstream data arrives.
     */
    uint8_t  retx_buf[4096];
    size_t   retx_len;
    uint16_t retx_seq;
    int      retx_count; /* Number of fragments in the burst */
} srv_session_t;

/* ── Session table (extern — defined in session.c) ── */
extern srv_session_t g_sessions[SRV_MAX_SESSIONS];

/* ── Session lookup ─────────────────────────────── */

/**
 * @brief Find a session by its 8-bit session ID.
 * @return  Array index [0, SRV_MAX_SESSIONS), or -1 if not found.
 */
int session_find_by_id(uint8_t id);

/**
 * @brief Allocate a new session slot for the given 8-bit session ID.
 * @return  Array index [0, SRV_MAX_SESSIONS), or -1 if the table is full.
 */
int session_alloc_by_id(uint8_t id);

/**
 * @brief Close and free a session at the given array index.
 *
 * Closes the upstream TCP handle, frees upstream_buf, and resets the slot.
 */
void session_close(int idx);

/**
 * @brief Queue a SOCKS5 status byte for delivery to the client.
 *
 * Places a single status byte at the beginning of the upstream_buf so it is
 * delivered in the next DNS TXT reply. Only sent once per session (status_sent).
 *
 * @param sidx    Session array index.
 * @param status  0x00 = success, 0x01..0x08 = SOCKS5 error codes.
 */
void session_send_status(int sidx, uint8_t status);

/**
 * @brief Clear pending FEC burst reassembly state.
 */
void session_clear_burst(srv_session_t *s);

void session_handle_data(int sidx, const uint8_t *data, size_t len);

/* ── Upstream TCP helpers ─────────────────────────────── */

/**
 * @brief Write payload to the upstream TCP stream and start reading responses.
 */
void upstream_write_and_read(int session_idx, const uint8_t *data, size_t len);

/* libuv callback declarations (needed by protocol.c to start the TCP flow) */
void on_upstream_resolve(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res);
void on_upstream_connect(uv_connect_t *req, int status);
void on_upstream_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf);
void on_upstream_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf);
void on_upstream_write(uv_write_t *w, int status);

/**
 * @brief Heap-allocated connection request for async upstream connect.
 *
 * Passed through libuv callbacks to carry target host/port and initial payload.
 */
typedef struct connect_req {
    uv_connect_t connect;
    int          session_idx;
    uint8_t     *payload;
    size_t       payload_len;
    char         target_host[256];
    uint16_t     target_port;
} connect_req_t;

#ifdef __cplusplus
}
#endif

#endif /* SERVER_SESSION_H */
