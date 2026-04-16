/**
 * @file client/dns/query.c
 * @brief DNS Query Building and Reply Handling Implementation (Client Side)
 *
 * Extracted from client/main.c sections:
 *   - Lines 188-353:  inline_dotify, build_dns_query
 *   - Lines 2506-2832: on_dns_recv, on_dns_timeout, on_dns_send, on_dns_alloc
 *   - Lines 2836-2853: Jitter timer (on_jitter_timer)
 *   - Lines 2855-3059: send_mtu_handshake, fire_dns_chunk_symbol
 *
 * DNS packet flow (upstream):
 *   fire_dns_chunk_symbol()
 *     → build_dns_query()   — QNAME = base32(header+payload).domain
 *     → uv_udp_send()       — sent to resolver:53 via UDP
 *     → on_dns_recv()       — parses TXT reply from resolver
 *       → reorder_buffer_insert() + reorder_buffer_flush()
 *       → socks5_flush_recv_buf() — delivers data to curl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "uv.h"
#include "third_party/spcdns/dns.h"
#include "third_party/spcdns/output.h"

#include "shared/base32.h"
#include "shared/codec.h"
#include "shared/config.h"
#include "shared/types.h"
#include "shared/resolver_pool.h"

#include "client/session/session.h"
#include "client/dns/query.h"
#include "shared/tui.h"

/* ── Externals from client/main.c ── */
extern uv_loop_t       *g_loop;
extern dnstun_config_t  g_cfg;
extern tui_stats_t      g_stats;
extern resolver_pool_t  g_pool;
extern session_t        g_sessions[];
extern int              g_session_count;

/* Forward declarations for SOCKS5 module (defined in client/socks5/proxy.c) */
typedef struct socks5_client socks5_client_t;
void socks5_flush_recv_buf(socks5_client_t *c);
void on_socks5_close(uv_handle_t *h);

/* Logging helpers */
static int log_level_fn(void);



static int log_level_fn(void) { return g_cfg.log_level; }

/* Random 16-bit number for DNS transaction IDs */
static uint16_t rand_u16(void) { return (uint16_t)(rand() & 0xFFFF); }

/* ────────────────────────────────────────────── */
/*  Inline Dotify                                 */
/* ────────────────────────────────────────────── */

size_t inline_dotify(char *buf, size_t buflen, size_t len) {
    if (len == 0) { if (buflen > 0) buf[0] = '\0'; return 0; }

    size_t dots    = len / 57;
    size_t new_len = len + dots;
    if (new_len + 1 > buflen) return (size_t)-1;

    buf[new_len] = '\0';

    char *src = buf + len - 1;
    char *dst = buf + new_len - 1;

    size_t next_dot   = len - (len % 57);
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

/* ────────────────────────────────────────────── */
/*  Build DNS Query                               */
/* ────────────────────────────────────────────── */

int build_dns_query(uint8_t *outbuf, size_t *outlen,
                     const chunk_header_t *hdr,
                     const uint8_t *payload, size_t paylen,
                     const char *domain) {
    /* Step 1: Encode header + payload into one raw block */
#define HDR_AND_PAYLOAD_MAX (20 + DNSTUN_CHUNK_PAYLOAD)
    uint8_t raw[HDR_AND_PAYLOAD_MAX];
    size_t  rawlen = 0;
    memcpy(raw, hdr, sizeof(chunk_header_t));
    rawlen += sizeof(chunk_header_t);
    if (payload && paylen > 0) {
        if (paylen > DNSTUN_CHUNK_PAYLOAD) {
            /* Payload too large — FEC symbol size mismatch */
            return -1;
        }
        memcpy(raw + rawlen, payload, paylen);
        rawlen += paylen;
    }

    /* Step 2: Base32 encode */
#define BASE32_MAX_OUTPUT(max_in) (((max_in) * 8 + 4) / 5)
    char b32_raw[BASE32_MAX_OUTPUT(HDR_AND_PAYLOAD_MAX)];
    size_t b32_len = base32_encode((uint8_t *)b32_raw, raw, rawlen);

    /* Step 3: Insert dots every 57 chars */
    char b32_dotted[BASE32_MAX_OUTPUT(HDR_AND_PAYLOAD_MAX) + 64];
    memcpy(b32_dotted, b32_raw, b32_len);
    size_t dotted_len = inline_dotify(b32_dotted, sizeof(b32_dotted), b32_len);

    /* Step 4: Build QNAME = <b32_dotted>.<domain>. */
    char qname[512];
    char clean_domain[256];
    size_t domain_len = strlen(domain);
    if (domain_len > 0 && domain[domain_len - 1] == '.') {
        strncpy(clean_domain, domain, domain_len - 1);
        clean_domain[domain_len - 1] = '\0';
    } else {
        strncpy(clean_domain, domain, sizeof(clean_domain) - 1);
        clean_domain[sizeof(clean_domain) - 1] = '\0';
    }
    int qname_len = snprintf(qname, sizeof(qname), "%s.%s.", b32_dotted, clean_domain);

    if (qname_len > DNSTUN_MAX_QNAME_LEN) return -1;

    /* Step 5: Build DNS query using SPCDNS */
    dns_question_t question = {0};
    question.name  = qname;
    question.type  = RR_TXT;
    question.class = CLASS_IN;

    dns_answer_t edns = {0};
    edns.generic.name  = (char *)".";
    edns.generic.type  = RR_OPT;
    edns.generic.class = 1232;
    edns.generic.ttl   = 0;

    dns_query_t query = {0};
    query.id        = rand_u16();
    query.query     = true;
    query.opcode    = OP_QUERY;
    query.rd        = true;
    query.rcode     = RCODE_OKAY;
    query.qdcount   = 1;
    query.questions = &question;
    query.arcount   = 1;
    query.additional = &edns;

    size_t sz = *outlen;
    if (dns_encode((dns_packet_t *)outbuf, &sz, &query) != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

/* ────────────────────────────────────────────── */
/*  DNS Query Context                             */
/* ────────────────────────────────────────────── */

typedef struct dns_query_ctx {
    uv_udp_t         udp;
    uv_timer_t       timer;
    int              closes;
    uv_udp_send_t    send_req;
    struct sockaddr_in dest;
    int              resolver_idx;
    int              session_idx;
    uint16_t         seq;
    uint64_t         sent_ms;
    uint8_t          sendbuf[4096];
    size_t           sendlen;
    uint8_t          recvbuf[4096];
} dns_query_ctx_t;

static void on_dns_query_close(uv_handle_t *h) {
    dns_query_ctx_t *q = h->data;
    if (++q->closes == 2) free(q);
}

static void on_dns_timeout(uv_timer_t *t) {
    dns_query_ctx_t *q = t->data;
    if (!uv_is_closing((uv_handle_t *)&q->udp)) {
        rpool_on_loss(&g_pool, q->resolver_idx);
        g_stats.queries_lost++;
        uv_close((uv_handle_t *)&q->udp,   on_dns_query_close);
        uv_close((uv_handle_t *)&q->timer, on_dns_query_close);
    }
}

static void on_dns_recv(uv_udp_t *h, ssize_t nread,
                         const uv_buf_t *buf,
                         const struct sockaddr *addr,
                         unsigned flags) {
    if (nread == 0 && addr == NULL) return;
    (void)flags;
    dns_query_ctx_t *q = h->data;
    int ridx = q->resolver_idx;

    if (nread > 0) {
        double rtt = (double)(uv_hrtime() / 1000000ULL - q->sent_ms);
        if (rtt < 0.0) rtt = 0.0;
        rpool_on_ack(&g_pool, ridx, rtt);

        dns_decoded_t decoded[DNS_DECODEBUF_4K];
        size_t decsz = sizeof(decoded);
        dns_rcode_t rc = dns_decode(decoded, &decsz,
                                     (const dns_packet_t *)buf->base,
                                     (size_t)nread);
        if (rc == RCODE_OKAY) {
            dns_query_t *resp = (dns_query_t *)decoded;
            for (int i = 0; i < (int)resp->ancount; i++) {
                dns_answer_t *ans = &resp->answers[i];
                if (ans->generic.type != RR_TXT || ans->txt.len == 0) continue;

                /* Check for SYNC response (comma-separated IPs) */
                bool is_sync = false;
                if (ans->txt.len > 7 && strchr(ans->txt.text, ',')) {
                    char first_part[16] = {0};
                    const char *comma = strchr(ans->txt.text, ',');
                    size_t first_len = comma ? (size_t)(comma - ans->txt.text) : ans->txt.len;
                    if (first_len < sizeof(first_part)) {
                        memcpy(first_part, ans->txt.text, first_len);
                        int dots = 0; bool has_digit = false;
                        for (size_t k = 0; k < first_len; k++) {
                            if (first_part[k] == '.') dots++;
                            if (first_part[k] >= '0' && first_part[k] <= '9') has_digit = true;
                        }
                        is_sync = (dots >= 3 && has_digit);
                    }
                }

                if (is_sync) {
                    char *ips = strndup(ans->txt.text, ans->txt.len);
                    char *tok = strtok(ips, ",");
                    while (tok) { rpool_add(&g_pool, tok); tok = strtok(NULL, ","); }
                    free(ips);
                } else {
                    /* Base64 decode TXT payload */
                    uint8_t raw_decoded[4096];
                    ptrdiff_t decoded_len = base64_decode(raw_decoded, ans->txt.text, ans->txt.len);
                    if (decoded_len < 0) continue;

                    int sidx = q->session_idx;
                    if (sidx >= 0 && sidx < DNSTUN_MAX_SESSIONS && !g_sessions[sidx].closed) {
                        session_t *s = &g_sessions[sidx];
                        const uint8_t *payload_ptr = raw_decoded;
                        size_t payload_len = (size_t)decoded_len;
                        uint16_t seq = 0;
                        bool has_seq = false;

                        /* Parse response header */
                        if (decoded_len >= (ptrdiff_t)sizeof(server_response_header_t)) {
                            server_response_header_t resp_hdr;
                            memcpy(&resp_hdr, raw_decoded, sizeof(resp_hdr));

                            if (resp_hdr.session_id != s->session_id) continue; /* Stale */

                            has_seq = (resp_hdr.flags & RESP_FLAG_HAS_SEQ) != 0;
                            if (has_seq) {
                                seq         = resp_hdr.seq;
                                payload_ptr = raw_decoded + sizeof(resp_hdr);
                                payload_len = (size_t)(decoded_len - sizeof(resp_hdr));
                            }
                        }

                        /* ACK byte check */
                        bool is_ack = (payload_len == 1 && payload_ptr[0] == '\0');
                        if (is_ack && !has_seq) { seq = 0; has_seq = true; }

                        if (has_seq) {
                            /* On first seq=0, clear stale reorder entries */
                            if (seq == 0 && s->reorder_buf.expected_seq == 0 && !s->first_seq_received) {
                                reorder_buffer_free(&s->reorder_buf);
                                s->reorder_buf.expected_seq = 0;
                                s->first_seq_received = true;
                            }

                            reorder_buffer_insert(&s->reorder_buf, seq, payload_ptr, payload_len);

                            uint8_t flush_buf[16384];
                            size_t flush_len = 0;
                            while (reorder_buffer_flush(&s->reorder_buf, flush_buf, sizeof(flush_buf), &flush_len) > 0) {
                                size_t data_start = 0;

                                /* Detect status byte (first byte of first flushed packet) */
                                if (flush_len >= 1 && !s->status_consumed) {
                                    uint8_t status_byte = flush_buf[0];
                                    s->status_consumed = true;
                                    data_start = 1;

                                    if (s->client_ptr) {
                                        socks5_client_t *c = (socks5_client_t *)s->client_ptr;
                                        if (!s->socks5_connected) {
                                            if (status_byte == 0x00) {
                                                /* Success in non-optimistic mode */
                                                extern void socks5_send(socks5_client_t *, const uint8_t *, size_t);
                                                uint8_t ok[10] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
                                                socks5_send(c, ok, 10);
                                                s->socks5_connected = true;
                                            } else {
                                                extern void socks5_send(socks5_client_t *, const uint8_t *, size_t);
                                                uint8_t err[10] = {0x05, status_byte, 0x00, 0x01, 0,0,0,0,0,0};
                                                socks5_send(c, err, 10);
                                                g_stats.socks5_total_errors++;
                                                uv_close((uv_handle_t *)
                                                    &((struct { uv_tcp_t tcp; } *)c)->tcp,
                                                    on_socks5_close);
                                            }
                                        } else {
                                            if (status_byte != 0x00) {
                                                g_stats.socks5_total_errors++;
                                                uv_close((uv_handle_t *)
                                                    &((struct { uv_tcp_t tcp; } *)c)->tcp,
                                                    on_socks5_close);
                                            }
                                        }
                                    }
                                }

                                size_t data_len = flush_len - data_start;
                                if (data_len > 0) {
                                    size_t need = s->recv_len + data_len;
                                    if (need > s->recv_cap) {
                                        size_t new_cap = (need + 8191) & ~4095;
                                        if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
                                        uint8_t *new_buf = realloc(s->recv_buf, new_cap);
                                        if (new_buf) { s->recv_buf = new_buf; s->recv_cap = new_cap; }
                                    }
                                    if (s->recv_cap >= s->recv_len + data_len) {
                                        memcpy(s->recv_buf + s->recv_len, flush_buf + data_start, data_len);
                                        s->recv_len += data_len;
                                        g_stats.rx_total     += data_len;
                                        g_stats.rx_bytes_sec += data_len;
                                    }
                                }
                                if (s->client_ptr)
                                    socks5_flush_recv_buf((socks5_client_t *)s->client_ptr);
                            }
                        } else if (payload_len > 0) {
                            /* Non-sequenced fallback */
                            size_t need = s->recv_len + payload_len;
                            if (need > s->recv_cap) {
                                size_t new_cap = need + 4096;
                                if (new_cap > MAX_SESSION_BUFFER) new_cap = MAX_SESSION_BUFFER;
                                uint8_t *new_buf = realloc(s->recv_buf, new_cap);
                                if (new_buf) { s->recv_buf = new_buf; s->recv_cap = new_cap; }
                            }
                            if (s->recv_cap >= s->recv_len + payload_len) {
                                memcpy(s->recv_buf + s->recv_len, payload_ptr, payload_len);
                                s->recv_len += payload_len;
                                g_stats.rx_total     += payload_len;
                                g_stats.rx_bytes_sec += payload_len;
                            }
                            if (s->client_ptr)
                                socks5_flush_recv_buf((socks5_client_t *)s->client_ptr);
                        }
                    }
                }
                g_stats.queries_recv++;
                g_stats.last_server_rx_ms = uv_hrtime() / 1000000ULL;
                if (!g_stats.server_connected) {
                    g_stats.server_connected = 1;
                }
            }
        } else {
            rpool_on_loss(&g_pool, ridx);
            g_stats.queries_lost++;
        }
    } else {
        rpool_on_loss(&g_pool, ridx);
        g_stats.queries_lost++;
    }

    if (!uv_is_closing((uv_handle_t *)&q->udp)) {
        resolver_t *r = &g_pool.resolvers[ridx];
        if (r->fail_count >= 20) {
            rpool_penalise(&g_pool, ridx);
            r->fail_count = 0;
        }
        uv_close((uv_handle_t *)&q->udp,   on_dns_query_close);
        uv_close((uv_handle_t *)&q->timer, on_dns_query_close);
    }
}

static void on_dns_send(uv_udp_send_t *sr, int status) {
    if (status != 0) {
        dns_query_ctx_t *q = sr->handle->data;
        if (!uv_is_closing((uv_handle_t *)&q->udp)) {
            rpool_on_loss(&g_pool, q->resolver_idx);
            g_stats.queries_lost++;
            uv_close((uv_handle_t *)&q->udp,   on_dns_query_close);
            uv_close((uv_handle_t *)&q->timer, on_dns_query_close);
        }
    }
}

static void on_dns_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    dns_query_ctx_t *q = h->data;
    (void)sz;
    buf->base = (char *)q->recvbuf;
    buf->len  = sizeof(q->recvbuf);
}

/* ────────────────────────────────────────────── */
/*  Jitter Timer — Deferred UDP Send              */
/* ────────────────────────────────────────────── */

typedef struct {
    uv_timer_t    timer;
    uv_udp_send_t send_req;
    dns_query_ctx_t *q;
} jitter_ctx_t;

static void on_jitter_timer(uv_timer_t *t) {
    jitter_ctx_t *jc = t->data;
    dns_query_ctx_t *q = jc->q;
    uv_buf_t buf = uv_buf_init((char *)q->sendbuf, (unsigned)q->sendlen);
    if (uv_udp_send(&jc->send_req, &q->udp, &buf, 1,
                    (const struct sockaddr *)&q->dest, on_dns_send) != 0) {
        uv_close((uv_handle_t *)&q->udp, on_dns_query_close);
    } else {
        g_stats.queries_sent++;
    }
    uv_close((uv_handle_t *)t, (uv_close_cb)free);
}

/* ────────────────────────────────────────────── */
/*  MTU Handshake                                 */
/* ────────────────────────────────────────────── */

void send_mtu_handshake(int session_idx) {
    /* Calculate average MTU from active resolvers */
    uint16_t upstream_mtu   = 512;
    uint16_t downstream_mtu = 220;
    int active_count = 0;
    uint32_t up_sum = 0, down_sum = 0;

    uv_mutex_lock(&g_pool.lock);
    for (int i = 0; i < g_pool.count; i++) {
        if (g_pool.resolvers[i].state == RSV_ACTIVE) {
            up_sum   += g_pool.resolvers[i].upstream_mtu;
            down_sum += g_pool.resolvers[i].downstream_mtu;
            active_count++;
        }
    }
    uv_mutex_unlock(&g_pool.lock);

    if (active_count > 0) {
        upstream_mtu   = (uint16_t)(up_sum   / active_count);
        downstream_mtu = (uint16_t)(down_sum / active_count);
    }
    if (downstream_mtu > g_cfg.max_download_mtu)
        downstream_mtu = g_cfg.max_download_mtu;

    uint8_t hs_payload[5];
    hs_payload[0] = DNSTUN_VERSION;
    hs_payload[1] = (uint8_t)(upstream_mtu >> 8);
    hs_payload[2] = (uint8_t)(upstream_mtu & 0xFF);
    hs_payload[3] = (uint8_t)(downstream_mtu >> 8);
    hs_payload[4] = (uint8_t)(downstream_mtu & 0xFF);

    fire_dns_chunk_symbol(session_idx, 0, hs_payload, sizeof(hs_payload), 0, 0, 0);
}

void send_sync(int session_idx) {
    session_t *sess = &g_sessions[session_idx];
    size_t host_len = strlen(sess->target_host);
    uint8_t payload[256];
    
    if (host_len > 240) host_len = 240; /* Bounds check */
    
    memcpy(payload, "SYNC", 4);
    payload[4] = (uint8_t)(host_len & 0xFF);
    memcpy(payload + 5, sess->target_host, host_len);
    payload[5 + host_len] = (uint8_t)((sess->target_port >> 8) & 0xFF);
    payload[6 + host_len] = (uint8_t)(sess->target_port & 0xFF);
    
    LOG_INFO("Session %d: Sending SYNC to %s:%d\n", 
             session_idx, sess->target_host, sess->target_port);
             
    fire_dns_chunk_symbol(session_idx, 0, payload, 7 + host_len, 0, 0, 0);
}

/* ────────────────────────────────────────────── */
/*  Fire One DNS Query Chunk                      */
/* ────────────────────────────────────────────── */

void fire_dns_chunk_symbol(int session_idx, uint16_t seq,
                            const uint8_t *payload, size_t paylen,
                            int total_symbols,
                            uint64_t oti_common, uint32_t oti_scheme) {
    int ridx = rpool_next(&g_pool);

    /* Fallback to dead resolvers if no active ones */
    if (ridx < 0) {
        uv_mutex_lock(&g_pool.lock);
        if (g_pool.dead_count > 0)
            ridx = g_pool.dead[rand() % g_pool.dead_count];
        uv_mutex_unlock(&g_pool.lock);
    }
    if (ridx < 0) {
        g_stats.queries_dropped++;
        return;
    }

    resolver_t *r = &g_pool.resolvers[ridx];

    dns_query_ctx_t *q = calloc(1, sizeof(*q));
    if (!q) return;
    q->resolver_idx = ridx;
    q->session_idx  = session_idx;
    q->seq          = seq;

    session_t *sess = &g_sessions[session_idx];

    /* Build chunk header */
    chunk_header_t hdr = {0};
    hdr.flags = (g_cfg.encryption ? CHUNK_FLAG_ENCRYPTED : 0) | CHUNK_FLAG_COMPRESSED;
    if (paylen   == 0) hdr.flags |= CHUNK_FLAG_POLL;
    if (total_symbols > 0) hdr.flags |= CHUNK_FLAG_FEC;
    chunk_set_session_id(&hdr, sess->session_id);
    hdr.seq = seq;

    uint8_t chunk_total = (uint8_t)(total_symbols > 0 ? total_symbols : 1);
    uint8_t fec_k_val   = (uint8_t)(r->fec_k > 15 ? 15 : r->fec_k);
    if (fec_k_val == 0 && chunk_total > 1) fec_k_val = chunk_total - 1;
    chunk_set_info(&hdr.chunk_info, chunk_total, fec_k_val);

    hdr.oti_common = oti_common;
    hdr.oti_scheme = oti_scheme;

    int didx     = rpool_flux_domain(&g_cfg);
    const char *domain = (g_cfg.domain_count > 0) ? g_cfg.domains[didx] : "tun.example.com";

    /* Build payload with capability header (non-FEC only) */
    uint8_t payload_with_cap[DNSTUN_CHUNK_PAYLOAD + sizeof(capability_header_t)];
    size_t final_paylen;

    if (total_symbols > 0) {
        if (paylen > DNSTUN_CHUNK_PAYLOAD) paylen = DNSTUN_CHUNK_PAYLOAD;
        if (payload && paylen > 0) memcpy(payload_with_cap, payload, paylen);
        final_paylen = paylen;
    } else {
        capability_header_t cap = {0};
        cap.version       = DNSTUN_VERSION;
        cap.upstream_mtu  = r->upstream_mtu;
        cap.downstream_mtu = r->downstream_mtu;
        cap.encoding      = (r->enc == ENC_BASE64) ? DNSTUN_ENC_BASE64 : DNSTUN_ENC_HEX;
        cap.loss_pct      = (uint8_t)(r->loss_rate * 100.0);
        size_t cap_len    = sizeof(capability_header_t);
        memcpy(payload_with_cap, &cap, cap_len);
        if (payload && paylen > 0) {
            if (paylen + cap_len > DNSTUN_CHUNK_PAYLOAD)
                paylen = DNSTUN_CHUNK_PAYLOAD - cap_len;
            memcpy(payload_with_cap + cap_len, payload, paylen);
        }
        final_paylen = paylen + cap_len;
    }

    q->sendlen = sizeof(q->sendbuf);
    if (build_dns_query(q->sendbuf, &q->sendlen, &hdr,
                         payload_with_cap, final_paylen, domain) != 0) {
        free(q);
        return;
    }

    memcpy(&q->dest, &r->addr, sizeof(q->dest));
    q->dest.sin_port = htons(53);

    uv_udp_init(g_loop, &q->udp);
    q->udp.data  = q;
    q->sent_ms   = uv_hrtime() / 1000000ULL;

    uv_timer_init(g_loop, &q->timer);
    q->timer.data = q;
    uv_timer_start(&q->timer, on_dns_timeout, 8000, 0);

    uv_udp_recv_start(&q->udp, on_dns_alloc, on_dns_recv);

    /* Anti-DPI Jitter: defer the UDP send by 0-50 ms */
    if (g_cfg.jitter) {
        uint64_t delay_ms = (uint64_t)(rand() % 50);
        jitter_ctx_t *jc  = malloc(sizeof(*jc));
        if (jc) {
            jc->q = q;
            uv_timer_init(g_loop, &jc->timer);
            jc->timer.data = jc;
            uv_timer_start(&jc->timer, on_jitter_timer, delay_ms, 0);
            return;
        }
    }

    /* Immediate send */
    uv_buf_t buf = uv_buf_init((char *)q->sendbuf, (unsigned)q->sendlen);
    int send_rc  = uv_udp_send(&q->send_req, &q->udp, &buf, 1,
                                (const struct sockaddr *)&q->dest, on_dns_send);
    if (send_rc != 0) {
        uv_close((uv_handle_t *)&q->udp,   on_dns_query_close);
        uv_close((uv_handle_t *)&q->timer, on_dns_query_close);
    } else {
        g_stats.queries_sent++;
    }
}
