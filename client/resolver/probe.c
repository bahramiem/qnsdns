/**
 * @file client/resolver/probe.c
 * @brief DNS Resolver Probing and Capability Testing
 *
 * Extracted from client/main.c lines 593-1272.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#include "shared/config.h"

#include "client/resolver/probe.h"
#include "client/resolver/mtu.h"
#include "shared/tui.h"

extern uv_loop_t       *g_loop;
extern dnstun_config_t  g_cfg;
extern resolver_pool_t  g_pool;
static uint16_t rand_u16(void) { return (uint16_t)(rand() & 0xFFFF); }
/* extern int log_level(void); */



/* ────────────────────────────────────────────── */
/*  Probe Structs and Callbacks                   */
/* ────────────────────────────────────────────── */

typedef struct {
    uv_udp_t udp;
    uv_timer_t timer;
    uv_udp_send_t send_req;
    int closes;
    struct sockaddr_in dest;
    int resolver_idx;
    uint16_t id;
    uint64_t sent_ms;
    uint8_t recv_buf[4096];
    uint8_t payload[4096];
    size_t  payload_len;
    bool is_init_probe;
    probe_test_type_t test_type;
    resolver_test_result_t *test_res;
    int mtu_test_val;
} probe_req_t;

static void on_probe_close(uv_handle_t *h) {
    probe_req_t *p = h->data;
    if (++p->closes == 2) {
        free(p);
    }
}

static void on_probe_timeout(uv_timer_t *t) {
    probe_req_t *p = t->data;
    if (!uv_is_closing((uv_handle_t*)&p->udp)) {
        if (!p->is_init_probe) {
            rpool_on_loss(&g_pool, p->resolver_idx);
        } else {
            resolver_t *r = &g_pool.resolvers[p->resolver_idx];
            if (p->test_type == PROBE_TEST_LONGNAME) {
                if (p->test_res) p->test_res->longname_supported = false;
                rpool_set_state(&g_pool, p->resolver_idx, RSV_DEAD);
            } else if (p->test_type == PROBE_TEST_NXDOMAIN) {
                if (p->test_res) p->test_res->nxdomain_correct = false;
                rpool_set_state(&g_pool, p->resolver_idx, RSV_DEAD);
            } else if (p->test_type == PROBE_TEST_EDNS_TXT) {
                if (p->test_res) {
                    p->test_res->edns_supported = false;
                    p->test_res->txt_supported = false;
                }
                rpool_set_state(&g_pool, p->resolver_idx, RSV_DEAD);
            } else if (p->test_type == PROBE_TEST_MTU_UP || p->test_type == PROBE_TEST_MTU_DOWN) {
                if (p->test_res) mark_mtu_tested(p->test_type == PROBE_TEST_MTU_UP ? &p->test_res->up_mtu_search : &p->test_res->down_mtu_search, p->mtu_test_val, false);
                int next_mtu = get_next_mtu_to_test(p->test_type == PROBE_TEST_MTU_UP ? &p->test_res->up_mtu_search : &p->test_res->down_mtu_search);
                if (next_mtu > 0) {
                    fire_mtu_test_probe(p->resolver_idx, p->test_type, p->test_res, next_mtu);
                }
            }
        }
        uv_close((uv_handle_t*)&p->udp, on_probe_close);
        uv_close((uv_handle_t*)&p->timer, on_probe_close);
    }
}

static void on_probe_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    probe_req_t *p = h->data;
    (void)sz;
    buf->base = (char*)p->recv_buf;
    buf->len  = sizeof(p->recv_buf);
}

static void on_probe_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread == 0 && addr == NULL) return;
    (void)flags;
    probe_req_t *p = h->data;
    int ridx = p->resolver_idx;
    resolver_t *r = &g_pool.resolvers[ridx];

    if (nread > 0) {
        double rtt = (double)(uv_hrtime() / 1000000ULL - p->sent_ms);
        if (rtt < 0.0) rtt = 0.0;
        
        /* Always record RTT for all probe responses, not just non-init probes */
        rpool_on_ack(&g_pool, ridx, rtt);

        dns_decoded_t decoded[DNS_DECODEBUF_4K];
        size_t decsz = sizeof(decoded);
        dns_rcode_t rc = dns_decode(decoded, &decsz, (const dns_packet_t*)buf->base, (size_t)nread);

        if (p->is_init_probe) {
            if (p->test_type == PROBE_TEST_LONGNAME) {
                 if (rc == RCODE_NAME_ERROR || rc == RCODE_OKAY) {
                     if (p->test_res) p->test_res->longname_supported = true;
                     LOG_INFO("Resolver %s passed Long QNAME test (RCODE %d)\n", r->ip, rc);
                 } else {
                     if (p->test_res) p->test_res->longname_supported = false;
                     rpool_set_state(&g_pool, ridx, RSV_DEAD);
                 }
            } else if (p->test_type == PROBE_TEST_NXDOMAIN) {
                dns_query_t *resp = (dns_query_t*)decoded;
                if (rc == RCODE_NAME_ERROR) {
                    if (p->test_res) p->test_res->nxdomain_correct = true;
                } else if (rc == RCODE_OKAY && resp->ancount == 0) {
                    /* Also accept NOERROR if there are zero answers (some resolvers do this) */
                    if (p->test_res) p->test_res->nxdomain_correct = true;
                } else if (rc == RCODE_OKAY && resp->ancount > 0) {
                    if (p->test_res) p->test_res->nxdomain_correct = false;
                    rpool_set_state(&g_pool, ridx, RSV_DEAD);
                    LOG_WARN("Resolver %s hijacks NXDOMAIN!\n", r->ip);
                } else {
                    if (p->test_res) p->test_res->nxdomain_correct = false;
                    rpool_set_state(&g_pool, ridx, RSV_DEAD);
                }
            } else if (p->test_type == PROBE_TEST_EDNS_TXT) {
                if (rc == RCODE_OKAY || rc == RCODE_NAME_ERROR) {
                    dns_query_t *resp = (dns_query_t*)decoded;
                    bool edns_ok = false;
                    bool txt_ok = false;
                    if (resp->additional) {
                        for (int i=0; i<resp->arcount; i++) {
                            if (resp->additional[i].generic.type == RR_OPT) {
                                edns_ok = true;
                                if (resp->additional[i].opt.udp_payload > 0) {
                                    if (p->test_res) {
                                        p->test_res->downstream_mtu = resp->additional[i].opt.udp_payload;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    if (resp->ancount > 0) {
                        for (int i=0; i<resp->ancount; i++) {
                            if (resp->answers[i].generic.type == RR_TXT) {
                                txt_ok = true; break;
                            }
                        }
                    } else if (resp->nameservers && resp->nscount > 0) {
                        txt_ok = true; 
                    } else {
                        txt_ok = true; 
                    }
                    if (p->test_res) {
                        p->test_res->edns_supported = edns_ok;
                        p->test_res->txt_supported = txt_ok;
                        p->test_res->upstream_mtu = 140;
                    }
                    if (!edns_ok && !txt_ok) {
                        rpool_set_state(&g_pool, ridx, RSV_DEAD);
                    }
                } else {
                    if (p->test_res) {
                        p->test_res->edns_supported = false;
                        p->test_res->txt_supported = false;
                    }
                    rpool_set_state(&g_pool, ridx, RSV_DEAD);
                }
            } else if (p->test_type == PROBE_TEST_MTU_UP || p->test_type == PROBE_TEST_MTU_DOWN) {
                bool success = false;
                if (nread >= 12) {
                    uint8_t *resp = (uint8_t *)buf->base;
                    uint16_t qdcount = (resp[4] << 8) | resp[5];
                    uint16_t ancount = (resp[6] << 8) | resp[7];
                    uint8_t rcode = resp[3] & 0x0F;

                    if (g_cfg.log_level >= 3) {
                        LOG_DEBUG("[MTU] Got response: rcode=%d, ancount=%d, test_mtu=%d\n", rcode, ancount, p->mtu_test_val);
                    }

                    if (rcode == RCODE_OKAY && ancount > 0) {
                        size_t offset = 12;
                        /* Skip Questions */
                        for (int i = 0; i < qdcount && offset < (size_t)nread; i++) {
                            while (offset < (size_t)nread) {
                                uint8_t len = resp[offset++];
                                if (len == 0) break;
                                if ((len & 0xC0) == 0xC0) { offset++; break; }
                                offset += len;
                            }
                            offset += 4; /* QTYPE + QCLASS */
                        }

                        /* Parse Answers for TXT "OK:LEN" */
                        for (int i = 0; i < ancount && offset < (size_t)nread; i++) {
                            /* Skip Name */
                            while (offset < (size_t)nread) {
                                uint8_t len = resp[offset++];
                                if (len == 0) break;
                                if ((len & 0xC0) == 0xC0) { offset++; break; }
                                offset += len;
                            }
                            if (offset + 10 > (size_t)nread) break;
                            uint16_t rtype = (resp[offset] << 8) | resp[offset + 1];
                            uint16_t rdlen = (resp[offset + 8] << 8) | resp[offset + 9];
                            offset += 10;
                            if (rtype == RR_TXT && rdlen > 0 && offset + rdlen <= (size_t)nread) {
                                uint8_t txt_len = resp[offset];
                                if (txt_len < rdlen && txt_len > 3) {
                                    char txt[64];
                                    size_t copy_len = txt_len > 60 ? 60 : txt_len;
                                    memcpy(txt, resp + offset + 1, copy_len);
                                    txt[copy_len] = '\0';
                                    if (strncmp(txt, "OK:", 3) == 0) {
                                        int verified_len = atoi(txt + 3);
                                        if (verified_len == p->mtu_test_val) {
                                            success = true;
                                            if (g_cfg.log_level >= 3) {
                                                LOG_INFO("[MTU] Verified MTU %d for %s\n", verified_len, r->ip);
                                            }
                                        } else {
                                            LOG_DEBUG("[MTU] Verification failed for %s: Sent %d, Server received %d\n", 
                                                      r->ip, p->mtu_test_val, verified_len);
                                        }
                                    }
                                }
                            }
                            offset += rdlen;
                        }
                    } else if (rcode == RCODE_NAME_ERROR || rcode == RCODE_OKAY) {
                         /* For MTU_DOWN, we often rely on simple arrival if ancount=0 but it's not ideal.
                          * However, MTU_UP MUST have an answer to be verified. */
                         if (p->test_type == PROBE_TEST_MTU_DOWN) success = true;
                    }
                }
                
                if (success) {
                    if (p->test_res) {
                        mark_mtu_tested(p->test_type == PROBE_TEST_MTU_UP ? &p->test_res->up_mtu_search : &p->test_res->down_mtu_search, p->mtu_test_val, true);
                        int next_mtu = get_next_mtu_to_test(p->test_type == PROBE_TEST_MTU_UP ? &p->test_res->up_mtu_search : &p->test_res->down_mtu_search);
                        if (next_mtu > 0) {
                            fire_mtu_test_probe(p->resolver_idx, p->test_type, p->test_res, next_mtu);
                        }
                    }
                } else {
                    if (p->test_res) {
                        mark_mtu_tested(p->test_type == PROBE_TEST_MTU_UP ? &p->test_res->up_mtu_search : &p->test_res->down_mtu_search, p->mtu_test_val, false);
                        int next_mtu = get_next_mtu_to_test(p->test_type == PROBE_TEST_MTU_UP ? &p->test_res->up_mtu_search : &p->test_res->down_mtu_search);
                        if (next_mtu > 0) {
                            fire_mtu_test_probe(p->resolver_idx, p->test_type, p->test_res, next_mtu);
                        }
                    }
                }
            }
        }
    } else {
        if (!p->is_init_probe) rpool_on_loss(&g_pool, ridx);
    }

    if (!uv_is_closing((uv_handle_t*)&p->udp)) {
        uv_close((uv_handle_t*)&p->udp, on_probe_close);
        uv_close((uv_handle_t*)&p->timer, on_probe_close);
    }
}

static void on_probe_send(uv_udp_send_t *sr, int status) {
    if (status != 0) {
        probe_req_t *p = sr->handle->data;
        if (!uv_is_closing((uv_handle_t*)&p->udp)) {
            if (!p->is_init_probe) rpool_on_loss(&g_pool, p->resolver_idx);
            uv_close((uv_handle_t*)&p->udp, on_probe_close);
            uv_close((uv_handle_t*)&p->timer, on_probe_close);
        }
    }
}

int build_test_dns_query(uint8_t *outbuf, size_t *outlen, const char *domain, uint16_t id, probe_test_type_t test_type) {
    dns_question_t question = {0};
    char qname[256];
    
    if (test_type == PROBE_TEST_LONGNAME) {
        char labels[256];
        int pos = 0;
        for (int i=0; i<3; i++) {
            for (int j=0; j<63; j++) labels[pos++] = 'a';
            labels[pos++] = '.';
        }
        labels[pos] = '\0';
        snprintf(qname, sizeof(qname), "%s%s.", labels, domain);
    } else if (test_type == PROBE_TEST_NXDOMAIN) {
        snprintf(qname, sizeof(qname), "nonexistent-test-domain-1234567890.%s.", domain);
    } else {
        snprintf(qname, sizeof(qname), "probe.%s.", domain);
    }
    
    question.name = qname;
    question.type = RR_A;
    if (test_type == PROBE_TEST_EDNS_TXT || test_type == PROBE_TEST_MTU_DOWN) {
        question.type = RR_TXT;
    }
    question.class = CLASS_IN;

    dns_answer_t edns = {0};
    edns.generic.name = (char*)".";
    edns.generic.type = RR_OPT;
    edns.generic.class = 4096;
    edns.generic.ttl = 0;

    dns_query_t query = {0};
    query.id = id;
    query.query = true;
    query.opcode = OP_QUERY;
    query.rd = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &question;

    if (test_type == PROBE_TEST_EDNS_TXT || test_type == PROBE_TEST_MTU_UP || test_type == PROBE_TEST_MTU_DOWN) {
        query.arcount = 1;
        query.additional = &edns;
    }

    size_t sz = *outlen;
    if (dns_encode((dns_packet_t*)outbuf, &sz, &query) != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

int build_mtu_test_query(uint8_t *buf, size_t *outlen, const char *domain, uint16_t id, int target_mtu, probe_test_type_t test_type) {
    if (!buf || !outlen || *outlen < 512) return -1;
    size_t bufsize = *outlen;
    size_t offset = 0;
    bool is_upload = (test_type == PROBE_TEST_MTU_UP);

    /* DNS Header (12 bytes) */
    buf[offset++] = (id >> 8) & 0xFF;
    buf[offset++] = id & 0xFF;
    buf[offset++] = 0x01;               /* Flags: RD = 1 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* QDCOUNT = 1 */
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;               /* ANCOUNT = 0 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* NSCOUNT = 0 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00;               /* ARCOUNT = 1 (EDNS) */
    buf[offset++] = 0x01;

    if (is_upload && target_mtu > 0) {
        /* 
         * DECODED PAYLOAD CENTRIC PROBING:
         * We pack exactly 'target_mtu' bytes into a raw buffer and then Base32 encode it.
         * Effective minimum is sizeof(query_header_t).
         */
        size_t hdr_sz = sizeof(query_header_t);
        uint16_t effective_mtu = (target_mtu < (int)hdr_sz) ? (uint16_t)hdr_sz : (uint16_t)target_mtu;
        
        uint8_t *raw = malloc(effective_mtu);
        if (!raw) return -1;
        memset(raw, 0, effective_mtu);

        /* Mandatory Header (SID=0, Flags=0, SEQ=0) to identify as non-tunnel */
        query_header_t qh = {0};
        memcpy(raw, &qh, hdr_sz);

        /* Fill remainder with random data */
        if (effective_mtu > hdr_sz) {
            for (size_t i = hdr_sz; i < effective_mtu; i++) raw[i] = (uint8_t)(rand() % 256);
        }

        /* Base32 encode */
        char *b32_payload = malloc(effective_mtu * 2 + 8);
        if (!b32_payload) { free(raw); return -1; }
        size_t b32_len = base32_encode((uint8_t*)b32_payload, raw, effective_mtu);
        b32_payload[b32_len] = '\0';
        free(raw);

        /* Split into DNS labels */
        size_t b32_pos = 0;
        while (b32_pos < b32_len) {
            size_t label_len = (b32_len - b32_pos > 63) ? 63 : (b32_len - b32_pos);
            if (offset + 1 + label_len > bufsize - 128) break;
            buf[offset++] = (uint8_t)label_len;
            memcpy(buf + offset, b32_payload + b32_pos, label_len);
            offset += label_len;
            b32_pos += label_len;
        }
        free(b32_payload);

        /* Add separator 'x' */
        if (offset + 2 < bufsize - 128) {
            buf[offset++] = 0x01;
            buf[offset++] = 'x';
        }
        
        /* Add domain */
        const char *d_ptr = domain;
        while (*d_ptr) {
            const char *dot = strchr(d_ptr, '.');
            if (!dot) dot = d_ptr + strlen(d_ptr);
            size_t label_len = dot - d_ptr;
            if (offset + 1 + label_len > bufsize - 128) break;
            buf[offset++] = (uint8_t)label_len;
            memcpy(buf + offset, d_ptr, label_len);
            offset += label_len;
            d_ptr = dot;
            if (*d_ptr) d_ptr++;
        }
    } else {
        /* Non-upload or simple probe */
        char prefix[64];
        if (target_mtu > 0) snprintf(prefix, sizeof(prefix), "mtu-req-%d", target_mtu);
        else snprintf(prefix, sizeof(prefix), "probe-%u", id);
        
        size_t plen = strlen(prefix);
        buf[offset++] = (uint8_t)plen;
        memcpy(buf + offset, prefix, plen);
        offset += plen;
        
        const char *d_ptr = domain;
        while (*d_ptr) {
            const char *dot = strchr(d_ptr, '.');
            if (!dot) dot = d_ptr + strlen(d_ptr);
            size_t label_len = dot - d_ptr;
            if (offset + 1 + label_len > bufsize - 128) break;
            buf[offset++] = (uint8_t)label_len;
            memcpy(buf + offset, d_ptr, label_len);
            offset += label_len;
            d_ptr = dot;
            if (*d_ptr) d_ptr++;
        }
    }

    buf[offset++] = 0; /* QNAME Term */
    buf[offset++] = 0x00; buf[offset++] = 0x10; /* TXT */
    buf[offset++] = 0x00; buf[offset++] = 0x01; /* IN */

    /* EDNS */
    buf[offset++] = 0x00; buf[offset++] = 0x00; buf[offset++] = 0x29; 
    buf[offset++] = 0x04; buf[offset++] = 0xD0; /* 1232 */
    buf[offset++] = 0x00; buf[offset++] = 0x00; buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x00; buf[offset++] = 0x00;

    if (g_cfg.log_level >= 3 && is_upload) {
        LOG_DEBUG("[MTU] Build query for %d-byte decoded payload\n", target_mtu);
    }

    *outlen = offset;
    return 0;
}

void fire_probe_ext(int resolver_idx, const char *domain, bool is_init_probe,
                    probe_test_type_t test_type, resolver_test_result_t *test_res,
                    int mtu_test_val)
{
    if (resolver_idx < 0 || resolver_idx >= g_pool.count) return;
    resolver_t *r = &g_pool.resolvers[resolver_idx];

    probe_req_t *p = calloc(1, sizeof(*p));
    if (!p) return;
    p->id = rand_u16();
    p->resolver_idx = resolver_idx;
    p->is_init_probe = is_init_probe;
    p->test_type = test_type;
    p->test_res = test_res;
    p->mtu_test_val = mtu_test_val;

    p->payload_len = sizeof(p->payload);
    
    if (test_type == PROBE_TEST_MTU_UP || test_type == PROBE_TEST_MTU_DOWN) {
        if (build_mtu_test_query(p->payload, &p->payload_len, domain, p->id, mtu_test_val, test_type) != 0) {
            free(p); return;
        }
    } else {
        if (build_test_dns_query(p->payload, &p->payload_len, domain, p->id, test_type) != 0) {
            free(p); return;
        }
    }

    memcpy(&p->dest, &r->addr, sizeof(p->dest));
    p->dest.sin_port = htons(53);

    uv_udp_init(g_loop, &p->udp);
    p->udp.data = p;
    p->sent_ms = uv_hrtime() / 1000000ULL;

    uv_timer_init(g_loop, &p->timer);
    p->timer.data = p;
    uv_timer_start(&p->timer, on_probe_timeout, g_cfg.test_timeout_ms > 0 ? g_cfg.test_timeout_ms : 5000, 0);

    uv_udp_recv_start(&p->udp, on_probe_alloc, on_probe_recv);
    uv_buf_t buf = uv_buf_init((char*)p->payload, (unsigned)p->payload_len);
    if (uv_udp_send(&p->send_req, &p->udp, &buf, 1, (const struct sockaddr*)&p->dest, on_probe_send) != 0) {
        uv_close((uv_handle_t*)&p->udp, on_probe_close);
        uv_close((uv_handle_t*)&p->timer, on_probe_close);
    }
}

void fire_test_probe(int resolver_idx, probe_test_type_t test_type, resolver_test_result_t *res) {
    int flux_idx = g_cfg.domain_count > 0 ? (rand() % g_cfg.domain_count) : 0;
    const char *domain = g_cfg.domain_count > 0 ? g_cfg.domains[flux_idx] : "tun.example.com";
    fire_probe_ext(resolver_idx, domain, true, test_type, res, 0);
}

void fire_probe(int resolver_idx, const char *domain) {
    fire_probe_ext(resolver_idx, domain, false, 0, NULL, 0);
}
