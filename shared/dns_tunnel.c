#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dns_tunnel.h"
#include "types.h"
#include "codec.h"
#include "config.h"

/* DNS Tunnel Implementation */

/* Internal DNS tunnel state */
typedef struct dns_tunnel_state {
    uv_loop_t *loop;
    dns_tunnel_session_t *sessions[DNSTUN_MAX_SESSIONS];
    size_t active_sessions;
} dns_tunnel_state_t;

static dns_tunnel_state_t g_dns_state;

/* Forward declarations */
static void on_dns_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                       const struct sockaddr *addr, unsigned flags);
static void build_dns_query(uint8_t *buffer, size_t *len, const dns_tunnel_config_t *config,
                           const uint8_t *payload, size_t payload_len);
static void build_dns_response(uint8_t *buffer, size_t *len, uint16_t query_id,
                              const uint8_t *payload, size_t payload_len);

/* Initialize DNS tunnel module */
int dns_tunnel_init(uv_loop_t *loop) {
    memset(&g_dns_state, 0, sizeof(g_dns_state));
    g_dns_state.loop = loop;
    return 0;
}

/* Cleanup DNS tunnel module */
void dns_tunnel_cleanup(void) {
    for (size_t i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
        if (g_dns_state.sessions[i]) {
            dns_tunnel_session_destroy(g_dns_state.sessions[i]);
        }
    }
    memset(&g_dns_state, 0, sizeof(g_dns_state));
}

/* Create a new tunnel session */
dns_tunnel_session_t* dns_tunnel_session_create(const dns_tunnel_config_t *config) {
    dns_tunnel_session_t *session = calloc(1, sizeof(*session));
    if (!session) return NULL;

    session->session_id = config->session_id;
    session->direction = config->direction;
    memcpy(&session->config, config, sizeof(*config));

    /* Allocate buffers */
    session->encode_buffer = malloc(65536);
    session->decode_buffer = malloc(65536);
    if (!session->encode_buffer || !session->decode_buffer) {
        free(session->encode_buffer);
        free(session->decode_buffer);
        free(session);
        return NULL;
    }
    session->encode_cap = 65536;
    session->decode_cap = 65536;

    /* Initialize UDP handle */
    session->udp_handle = malloc(sizeof(uv_udp_t));
    if (!session->udp_handle) {
        free(session->encode_buffer);
        free(session->decode_buffer);
        free(session);
        return NULL;
    }

    uv_udp_init(g_dns_state.loop, session->udp_handle);
    session->udp_handle->data = session;

    /* Store session reference */
    g_dns_state.sessions[session->session_id] = session;
    g_dns_state.active_sessions++;

    return session;
}

/* Destroy a tunnel session */
void dns_tunnel_session_destroy(dns_tunnel_session_t *session) {
    if (!session) return;

    /* Stop receiving */
    if (session->udp_handle) {
        uv_udp_recv_stop(session->udp_handle);
        uv_close((uv_handle_t*)session->udp_handle, NULL);
        free(session->udp_handle);
    }

    /* Free buffers */
    free(session->encode_buffer);
    free(session->decode_buffer);

    /* Remove from global state */
    if (g_dns_state.sessions[session->session_id] == session) {
        g_dns_state.sessions[session->session_id] = NULL;
        g_dns_state.active_sessions--;
    }

    free(session);
}

/* Send data through the tunnel */
int dns_tunnel_send(dns_tunnel_session_t *session, const uint8_t *data, size_t len) {
    if (!session || !data || len == 0) return -1;

    /* For now, simple implementation - just send raw data */
    /* TODO: Implement proper DNS query encoding with FEC, compression, etc. */

    uint8_t buffer[4096];
    size_t buffer_len;

    if (session->direction == TUNNEL_SERVER_TO_CLIENT) {
        /* Server to client: build DNS query */
        build_dns_query(buffer, &buffer_len, &session->config, data, len);
    } else {
        /* Client to server: build DNS response */
        build_dns_response(buffer, &buffer_len, session->next_seq++, data, len);
    }

    /* Send UDP packet */
    /* TODO: Implement resolver pool selection and sending logic */

    return 0;
}

/* Process incoming DNS packet */
int dns_tunnel_process_packet(dns_tunnel_session_t *session,
                            const uint8_t *packet, size_t len) {
    if (!session || !packet || len == 0) return -1;

    /* TODO: Parse DNS packet and extract payload */
    /* TODO: Handle FEC decoding, decompression, etc. */
    /* TODO: Call session callback with extracted data */

    uint8_t dummy_payload[] = {0x01, 0x02, 0x03}; /* Placeholder */
    if (session->on_data_received) {
        session->on_data_received(session, dummy_payload, sizeof(dummy_payload));
    }

    return 0;
}

/* Get tunnel statistics */
void dns_tunnel_get_stats(dns_tunnel_session_t *session, tunnel_stats_t *stats) {
    if (!session || !stats) return;

    memset(stats, 0, sizeof(*stats));
    /* TODO: Implement proper statistics collection */
}

/* Build DNS query with encoded payload */
static void build_dns_query(uint8_t *buffer, size_t *len, const dns_tunnel_config_t *config,
                           const uint8_t *payload, size_t payload_len) {
    /* TODO: Implement proper DNS query building */
    /* This should encode the payload into DNS QNAME format */

    *len = payload_len;
    memcpy(buffer, payload, payload_len);
}

/* Build DNS response with encoded payload */
static void build_dns_response(uint8_t *buffer, size_t *len, uint16_t query_id,
                              const uint8_t *payload, size_t payload_len) {
    /* TODO: Implement proper DNS response building */
    /* This should encode the payload into DNS TXT record format */

    *len = payload_len;
    memcpy(buffer, payload, payload_len);
}

/* UDP receive callback */
static void on_dns_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                       const struct sockaddr *addr, unsigned flags) {
    dns_tunnel_session_t *session = handle->data;
    if (!session) return;

    if (nread < 0) {
        if (session->on_error) {
            session->on_error(session, nread);
        }
        return;
    }

    if (nread > 0) {
        dns_tunnel_process_packet(session, (const uint8_t*)buf->base, nread);
    }
}