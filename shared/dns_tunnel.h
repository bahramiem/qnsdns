#pragma once
#ifndef DNSTUN_DNS_TUNNEL_H
#define DNSTUN_DNS_TUNNEL_H

#include <stdint.h>
#include <stdbool.h>
#include <uv.h>
#include "types.h"

/* DNS Tunnel Module - Handles encoding/decoding of data through DNS */

/* Tunnel direction */
typedef enum {
    TUNNEL_CLIENT_TO_SERVER,  /* Client encoding data to server */
    TUNNEL_SERVER_TO_CLIENT   /* Server encoding data to client */
} tunnel_direction_t;

/* DNS tunnel configuration */
typedef struct dns_tunnel_config {
    tunnel_direction_t direction;
    uint16_t session_id;
    char domain[256];
    int mtu;
    bool use_fec;
    int fec_k;
    bool use_compression;
    bool use_encryption;
} dns_tunnel_config_t;

/* DNS tunnel session state */
typedef struct dns_tunnel_session {
    uint16_t session_id;
    tunnel_direction_t direction;
    dns_tunnel_config_t config;
    uv_udp_t *udp_handle;

    /* Encoding state */
    uint8_t *encode_buffer;
    size_t encode_len;
    size_t encode_cap;
    uint16_t next_seq;

    /* Decoding state */
    uint8_t *decode_buffer;
    size_t decode_len;
    size_t decode_cap;

    /* FEC state */
    void *fec_encoder;
    void *fec_decoder;

    /* Callbacks */
    void (*on_data_received)(struct dns_tunnel_session *session,
                           const uint8_t *data, size_t len);
    void (*on_error)(struct dns_tunnel_session *session, int error_code);
} dns_tunnel_session_t;

/* Tunnel statistics */
typedef struct tunnel_stats {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t packets_lost;
    double avg_rtt_ms;
    time_t created_time;
    time_t last_active;
} tunnel_stats_t;

/* API Functions */

/* Initialize DNS tunnel module */
int dns_tunnel_init(uv_loop_t *loop);

/* Cleanup DNS tunnel module */
void dns_tunnel_cleanup(void);

/* Create a new tunnel session */
dns_tunnel_session_t* dns_tunnel_session_create(const dns_tunnel_config_t *config);

/* Destroy a tunnel session */
void dns_tunnel_session_destroy(dns_tunnel_session_t *session);

/* Send data through the tunnel */
int dns_tunnel_send(dns_tunnel_session_t *session, const uint8_t *data, size_t len);

/* Process incoming DNS query/response */
int dns_tunnel_process_packet(dns_tunnel_session_t *session,
                            const uint8_t *packet, size_t len);

/* Get tunnel statistics */
void dns_tunnel_get_stats(dns_tunnel_session_t *session, tunnel_stats_t *stats);

#endif /* DNSTUN_DNS_TUNNEL_H */