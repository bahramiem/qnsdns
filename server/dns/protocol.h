/**
 * @file server/dns/protocol.h
 * @brief DNS TXT Reply Building and Main UDP Receive Handler
 *
 * This module handles everything related to DNS protocol on the server side:
 *   1. Building TXT reply packets from downstream data.
 *   2. Receiving and dispatching incoming DNS queries (on_server_recv).
 *   3. Sending UDP replies back to resolvers.
 *
 * Example usage:
 *   // Build a TXT reply:
 *   uint8_t reply[4096];
 *   size_t rlen = sizeof(reply);
 *   build_txt_reply_with_seq(reply, &rlen, query_id, qname,
 *                            data, data_len, mtu, seq, session_id, true);
 *   send_udp_reply(&client_addr, reply, rlen);
 */

#ifndef SERVER_DNS_PROTOCOL_H
#define SERVER_DNS_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "uv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Build a DNS TXT response with an embedded sequence number.
 *
 * Encodes `data` using the configured downstream encoding (base64 by default),
 * prepends a `server_response_header_t`, and packages the result as a DNS TXT
 * record in a full DNS response packet.
 *
 * @param outbuf     Output buffer for the raw DNS response bytes.
 * @param outlen     In: buffer size. Out: actual bytes written.
 * @param query_id   DNS transaction ID to echo in the response.
 * @param qname      Query name string to echo in the response.
 * @param data       Payload to embed (may be NULL for empty reply).
 * @param data_len   Length of payload.
 * @param mtu        Maximum packet size to respect (caps data_len if needed).
 * @param seq        Downstream sequence number for the client's reorder buffer.
 * @param session_id Client session identifier echoed in the response header.
 * @param has_seq    If true, sets RESP_FLAG_HAS_SEQ in the response header.
 * @return  0 on success, -1 on failure (dns_encode error or buffer too small).
 */
int build_txt_reply_with_seq(uint8_t *outbuf, size_t *outlen,
                             uint16_t query_id, const char *qname,
                             const uint8_t *data, size_t data_len,
                             uint16_t mtu, uint16_t seq,
                             uint8_t session_id, bool has_seq);

/**
 * @brief Send a raw UDP reply to the given destination.
 *
 * Allocates a heap-allocated udp_reply_t, copies `data`, and calls
 * uv_udp_send(). Memory is freed in the on_udp_send_done callback.
 *
 * @param dest  Destination address (resolver that sent the query).
 * @param data  Raw DNS packet bytes to send.
 * @param len   Number of bytes to send.
 */
void send_udp_reply(const struct sockaddr_in *dest, const uint8_t *data, size_t len);

/**
 * @brief libuv receive buffer allocator for the UDP server socket.
 */
void on_server_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf);

/**
 * @brief Main UDP receive callback — parses incoming DNS queries and drives
 *        session state, FEC reassembly, upstream forwarding, and DNS replies.
 */
void on_server_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_DNS_PROTOCOL_H */
