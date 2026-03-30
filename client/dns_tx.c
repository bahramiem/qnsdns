/**
 * @file client/dns_tx.c
 * @brief Implementation of DNS query construction and transmission.
 */

#include "dns_tx.h"
#include "client_common.h"
#include "session.h"
#include "../shared/types.h"
#include "../shared/base32.h"
#include "../shared/resolver_pool.h"
#include "../shared/base32.h"
#include "../SPCDNS/dns.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Internal forward declarations */
void dns_tx_send_raw(const uint8_t *buf, size_t len);

/* ────────────────────────────────────────────── */
/*  Utility Functions                             */
/* ────────────────────────────────────────────── */

/* Dotify function from slipstream - inserts dots every 57 chars */
static size_t inline_dotify(char *buf, size_t buflen, size_t len) {
    if (len == 0) {
        if (buflen > 0) buf[0] = '\0';
        return 0;
    }
    size_t dots = len / 57;
    size_t new_len = len + dots;
    if (new_len + 1 > buflen) return (size_t)-1;
    buf[new_len] = '\0';
    char *src = buf + len - 1;
    char *dst = buf + new_len - 1;
    size_t next_dot = len - (len % 57);
    if (next_dot == len) next_dot = len - 57;
    size_t current_pos = len;
    while (current_pos > 0) {
        if (current_pos == next_dot && dots > 0) {
            *dst-- = '.';
            next_dot -= 57;
            current_pos--;
            dots--;
            continue;
        }
        *dst-- = *src--;
        current_pos--;
    }
    return new_len;
}

int dns_tx_build_query(uint8_t *outbuf, size_t *outlen,
                        const chunk_header_t *hdr,
                        const uint8_t *payload, size_t paylen,
                        const char *domain) {
    if (!hdr || !outbuf || !outlen || !domain) return -1;
    
    /* 1. Pack Header + Payload */
    uint8_t raw[1024];
    size_t  rawlen = 0;
    memcpy(raw, hdr, sizeof(chunk_header_t));
    rawlen += sizeof(chunk_header_t);
    if (payload && paylen > 0) {
        memcpy(raw + rawlen, payload, paylen);
        rawlen += paylen;
    }

    /* 2. Base32 Encoding */
    char b32_raw[2048];
    size_t b32_len = base32_encode(b32_raw, raw, rawlen);

    /* 3. Dotification */
    char b32_dotted[2048];
    memcpy(b32_dotted, b32_raw, b32_len);
    size_t dotted_len = inline_dotify(b32_dotted, sizeof(b32_dotted), b32_len);

    /* 4. Construct Full Domain (QNAME) */
    char qname[512];
    int qname_len = snprintf(qname, sizeof(qname), "%s.%s.", b32_dotted, domain);
    if (qname_len >= 254) {
        LOG_ERR("QNAME too long: %d bytes\n", qname_len);
        return -1;
    }

    /* 5. DNS Packet Construction */
    dns_question_t quest = { .name = qname, .type = RR_TXT, .class = CLASS_IN };
    
    /* EDNS0 OPT record for better UDP success */
    dns_answer_t opt = {0};
    opt.generic.name = (char*)".";
    opt.generic.type = RR_OPT;
    opt.generic.class = 1232;
    
    dns_query_t dns = {
        .id = (uint16_t)(rand() & 0xFFFF), .query = true, .rd = true,
        .qdcount = 1, .questions = &quest, .arcount = 1, .additional = &opt
    };

    size_t sz = *outlen;
    if (dns_encode((dns_packet_t*)outbuf, &sz, &dns) != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

/* ── Public API Implementation ────────────────────────────────────────────── */

static void on_udp_send_done(uv_udp_send_t *req, int status) {
    if (req->data) free(req->data);
    free(req);
    (void)status;
}

static void on_dns_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    (void)h;
    buf->base = malloc(sz);
    buf->len = (unsigned int)sz;
}

static void on_dns_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                         const struct sockaddr *addr, unsigned int flags) {
    (void)h; (void)addr; (void)flags;
    if (nread <= 0) {
        if (buf->base) free(buf->base);
        return;
    }

    if (g_client_stats) g_client_stats->queries_recv++;

    /* 1. Decode DNS Packet */
    dns_decoded_t decoded[1024];
    size_t decsz = sizeof(decoded);
    if (dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base, (size_t)nread) == RCODE_OKAY) {
        dns_query_t *dns = (dns_query_t *)decoded;
        /* Look for TXT record in answers */
        for (int i = 0; i < dns->ancount; i++) {
            if (dns->answers[i].generic.type == RR_TXT) {
                const char *txt = dns->answers[i].txt.text;
                if (!txt) continue;

                /* 2. Base32 Decode Tunnel Payload */
                uint8_t raw[1024];
                ssize_t rawlen = base32_decode(raw, txt, strlen(txt));
                if (rawlen >= (ssize_t)sizeof(server_response_header_t)) {
                    server_response_header_t *hdr = (server_response_header_t *)raw;
                    uint8_t sid = hdr->session_id;
                    uint16_t seq = hdr->seq;
                    bool has_seq = (hdr->flags & RESP_FLAG_HAS_SEQ) != 0;
                    
                    const uint8_t *data = raw + sizeof(server_response_header_t);
                    size_t dlen = (size_t)rawlen - sizeof(server_response_header_t);

                    /* 3. Dispatch to Session Manager */
                    if (sid < 255) {
                        int sidx = session_find_by_wire_id(sid);
                        if (sidx >= 0) {
                            session_process_incoming_chunk(sidx, has_seq ? seq : 0, data, dlen);
                        }
                    }
                }
            }
        }
    }
    
    if (buf->base) free(buf->base);
}

void dns_tx_send_raw(const uint8_t *buf, size_t len) {
    /* Multipath scattering: select a resolver from the active pool */
    if (!g_pool) return;
    int idx = rpool_select_active(g_pool);
    if (idx < 0) {
        if (g_client_stats) g_client_stats->queries_lost++;
        return;
    }
    resolver_t *r = &g_pool->resolvers[idx];

    uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
    if (!req) return;
    
    uint8_t *copy = malloc(len);
    if (!copy) { free(req); return; }
    memcpy(copy, buf, len);
    req->data = copy;
    
    uv_buf_t ubuf = uv_buf_init((char *)copy, (unsigned int)len);
    
    struct sockaddr_in dest;
    uv_ip4_addr(r->ip, 53, &dest);
    
    static uv_udp_t global_udp_out;
    static bool init = false;
    if (!init && g_client_loop) {
        uv_udp_init(g_client_loop, &global_udp_out);
        uv_udp_recv_start(&global_udp_out, on_dns_alloc, on_dns_recv);
        init = true;
    }

    if (uv_udp_send(req, &global_udp_out, &ubuf, 1, (const struct sockaddr *)&dest, on_udp_send_done) != 0) {
        free(copy);
        free(req);
    }
    
    if (g_client_stats) g_client_stats->queries_sent++;
}

void dns_tx_send_poll(int idx) {
    session_t *s = session_get(idx);
    if (!s) return;

    chunk_header_t hdr = {0};
    chunk_set_session_id(&hdr, s->session_id);
    hdr.flags = CHUNK_FLAG_POLL;
    hdr.seq = s->tx_next++; /* Sequential poll tracking */
    
    uint8_t pkt[512];
    size_t pktlen = sizeof(pkt);
    const char *domain = (g_client_cfg && g_client_cfg->domain_count > 0) ? g_client_cfg->domains[0] : "tun.example.com";
    
    if (dns_tx_build_query(pkt, &pktlen, &hdr, NULL, 0, domain) == 0) {
        dns_tx_send_raw(pkt, pktlen);
    }
}

void dns_tx_send_handshake(int idx) {
    session_t *s = session_get(idx);
    if (!s) return;

    chunk_header_t hdr = {0};
    chunk_set_session_id(&hdr, s->session_id);
    hdr.seq = 0; /* Handshake is always seq 0 */
    
    /* Handshake payload: Version(1) + DownstreamMTU(2) */
    uint8_t payload[5];
    payload[0] = DNSTUN_VERSION;
    uint16_t mtu = 512; /* Conservatively small MTU until response */
    payload[1] = mtu >> 8;
    payload[2] = mtu & 0xFF;
    
    uint8_t pkt[512];
    size_t pktlen = sizeof(pkt);
    const char *domain = (g_client_cfg && g_client_cfg->domain_count > 0) ? g_client_cfg->domains[0] : "tun.example.com";
    
    if (dns_tx_build_query(pkt, &pktlen, &hdr, payload, 3, domain) == 0) {
        dns_tx_send_raw(pkt, pktlen);
        LOG_INFO("Sent MTU Handshake for Sess %d (wire %u)\n", idx, s->session_id);
    }
}

/* ── Protocol Loopback Test Transmitter ──────────────────────────────────── */

typedef struct {
    uv_udp_t udp;
    uv_timer_t timer;
    uint64_t sent_ms;
    uint16_t expected_seq;
    char expected_payload[32];
    int closes;
} proto_ctx_t;

static void on_proto_close(uv_handle_t *h) {
    proto_ctx_t *ctx = h->data;
    if (++ctx->closes == 2) free(ctx);
}

static void on_proto_timeout(uv_timer_t *t) {
    proto_ctx_t *ctx = t->data;
    if (g_client_tui) {
        g_client_tui->proto_test.test_pending = 0;
        g_client_tui->proto_test.last_test_success = 0;
        g_client_tui->proto_test.last_test_recv_ms = uv_hrtime() / 1000000;
    }
    uv_close((uv_handle_t *)&ctx->udp, on_proto_close);
    uv_close((uv_handle_t *)&ctx->timer, on_proto_close);
}

static void on_proto_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                           const struct sockaddr *addr, unsigned int flags) {
    (void)addr; (void)flags;
    proto_ctx_t *ctx = h->data;
    if (nread > 0) {
        dns_decoded_t decoded[512]; size_t decsz = sizeof(decoded);
        if (dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base, (size_t)nread) == RCODE_OKAY) {
            dns_query_t *dns = (dns_query_t *)decoded;
            for (int i = 0; i < dns->ancount; i++) {
                if (dns->answers[i].generic.type == RR_TXT) {
                    uint8_t raw[512];
                    ssize_t rawlen = base32_decode(raw, dns->answers[i].txt.text, strlen(dns->answers[i].txt.text));
                    if (rawlen >= (ssize_t)sizeof(server_response_header_t)) {
                        server_response_header_t *hdr = (server_response_header_t *)raw;
                        if (hdr->session_id == 255) {
                            /* Success! */
                            if (g_client_tui) {
                                g_client_tui->proto_test.test_pending = 0;
                                g_client_tui->proto_test.last_test_success = 1;
                                g_client_tui->proto_test.last_test_recv_ms = uv_hrtime() / 1000000;
                                LOG_INFO("Protocol Loopback SUCCESS: RTT %llu ms\n", 
                                         (unsigned long long)(g_client_tui->proto_test.last_test_recv_ms - ctx->sent_ms));
                            }
                            uv_timer_stop(&ctx->timer);
                            uv_close((uv_handle_t *)&ctx->udp, on_proto_close);
                            uv_close((uv_handle_t *)&ctx->timer, on_proto_close);
                        }
                    }
                }
            }
        }
    }
    if (buf->base) free(buf->base);
}

void dns_tx_send_debug_packet(const char *payload, uint32_t seq) {
    if (!g_pool || !g_client_loop) return;
    int idx = rpool_select_active(g_pool);
    if (idx < 0) return;
    resolver_t *r = &g_pool->resolvers[idx];

    proto_ctx_t *ctx = calloc(1, sizeof(proto_ctx_t));
    if (!ctx) return;
    ctx->sent_ms = uv_hrtime() / 1000000;
    ctx->expected_seq = (uint16_t)(seq & 0xFFFF);
    strncpy(ctx->expected_payload, payload, sizeof(ctx->expected_payload) - 1);

    chunk_header_t chdr = {0};
    chunk_set_session_id(&chdr, 255);
    chdr.seq = ctx->expected_seq;

    uint8_t pkt[1024]; size_t pktlen = sizeof(pkt);
    const char *domain = (g_client_cfg && g_client_cfg->domain_count > 0) ? g_client_cfg->domains[0] : "tun.example.com";
    if (dns_tx_build_query(pkt, &pktlen, &chdr, (const uint8_t *)payload, strlen(payload), domain) != 0) {
        free(ctx); return;
    }

    /* Heap allocate request and packet buffer for async safely */
    uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
    if (!req) { free(ctx); return; }
    uint8_t *copy = malloc(pktlen);
    if (!copy) { free(req); free(ctx); return; }
    memcpy(copy, pkt, pktlen);
    req->data = copy;

    uv_udp_init(g_client_loop, &ctx->udp);
    ctx->udp.data = ctx;
    uv_timer_init(g_client_loop, &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, on_proto_timeout, 5000, 0);

    struct sockaddr_in dest;
    uv_ip4_addr(r->ip, 53, &dest);
    uv_udp_recv_start(&ctx->udp, on_dns_alloc, on_proto_recv);
    uv_buf_t b = uv_buf_init((char *)copy, (unsigned int)pktlen);
    
    if (uv_udp_send(req, &ctx->udp, &b, 1, (const struct sockaddr *)&dest, on_udp_send_done) != 0) {
        free(copy);
        free(req);
        uv_close((uv_handle_t*)&ctx->udp, on_proto_close);
        uv_close((uv_handle_t*)&ctx->timer, on_proto_close);
    }
}
