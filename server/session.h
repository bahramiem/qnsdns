/**
 * @file server/session.h
 * @brief Upstream session management and TCP bridging.
 *
 * Example Usage:
 * @code
 *   session_manager_init(g_loop);
 *   srv_session_t *s = session_find_by_id(42);
 *   if (!s) s = session_alloc_by_id(42);
 *   session_upstream_connect(s, "google.com", 80, NULL, 0);
 *   session_upstream_write(s, (uint8_t*)"GET / HTTP/1.1\r\n\r\n", 18);
 * @endcode
 */

#ifndef QNS_SERVER_SESSION_H
#define QNS_SERVER_SESSION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "../uv.h"
#include "../shared/types.h"
#include "../shared/tui/core.h"

#define SRV_MAX_SESSIONS 1024

/**
 * @brief Server-side upstream session state.
 *
 * Each session tracks:
 * 1. The upstream TCP connection to target (e.g. google.com).
 * 2. Downstream sequencing for data delivered via DNS polls.
 * 3. Burst reassembly for incoming FEC symbols.
 * 4. Retransmission buffer for the most recent reply.
 */
typedef struct srv_session {
    bool used;
    uint8_t session_id;    /**< 8-bit ID (0-255) */

    /* Upstream TCP Bridge */
    uv_tcp_t  upstream_tcp;
    bool      tcp_connected;
    uint8_t  *upstream_buf; /**< Receive buffer from target */
    size_t    upstream_len;
    size_t    upstream_cap;

    /* Client Target Mapping */
    struct sockaddr_in client_addr; /**< Last seen client address (reply destination) */
    char user_id[16];

    /* Client Capabilities (Handshake) */
    uint16_t cl_downstream_mtu;
    uint8_t  cl_enc_format;
    uint8_t  cl_loss_pct;
    uint8_t  cl_fec_k;
    bool     handshake_done;

    /* FEC Burst Reassembly (Incoming Client -> Server) */
    uint16_t burst_seq_start;
    int      burst_count_needed;
    int      burst_received;
    uint8_t **burst_symbols;
    size_t   burst_symbol_len;
    uint64_t burst_oti_common;
    uint32_t burst_oti_scheme;
    bool     burst_has_oti;
    bool     burst_decoded;

    /* Sequencing (Server -> Client) */
    uint16_t downstream_seq;
    bool     status_sent;
    time_t   last_active;

    /* Retransmission (ACK mechanism) */
    uint8_t  retx_buf[4096];
    size_t   retx_len;
    uint16_t retx_seq;
} srv_session_t;

/**
 * @brief Initialize the session manager.
 * @param loop The libuv loop to use for TCP connections.
 */
void session_manager_init(uv_loop_t *loop);

/**
 * @brief Find an existing session by its 8-bit ID.
 */
srv_session_t* session_find_by_id(uint8_t id);

/**
 * @brief Allocate a new session slot.
 */
srv_session_t* session_alloc_by_id(uint8_t id);

/**
 * @brief Close and cleanup a session.
 */
void session_close(srv_session_t *s);

/**
 * @brief Periodically check for idle sessions and close them.
 * @param timeout_sec Seconds of inactivity before closing.
 */
void session_manager_tick_idle(int timeout_sec);

/**
 * @brief Bridge: Write data from DNS tunnel to upstream TCP.
 */
void session_upstream_write(srv_session_t *s, const uint8_t *data, size_t len);

/**
 * @brief Send a SOCKS5 status/ACK byte (0x00=success) to client.
 */
void session_send_status(srv_session_t *s, uint8_t status);

/**
 * @brief Initiate upstream TCP connection (supports DNS resolution).
 * @param s The session.
 * @param target_host Hostname or IP.
 * @param target_port TCP port.
 * @param payload Initial payload to send after connection (optional).
 * @param payload_len Size of initial payload.
 */
void session_upstream_connect(srv_session_t *s, const char *target_host, uint16_t target_port, 
                              const uint8_t *payload, size_t payload_len);

/**
 * @brief Snapshot active client sessions for TUI.
 * @return Number of active sessions found.
 */
int session_get_snapshots(tui_client_snap_t *out, int max_clients);

#endif /* QNS_SERVER_SESSION_H */
