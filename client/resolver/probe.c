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
extern int log_level(void);



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
        
        if (!p->is_init_probe) {
            rpool_on_ack(&g_pool, ridx, rtt);
        }

        dns_decoded_t decoded[DNS_DECODEBUF_4K];
        size_t decsz = sizeof(decoded);
        dns_rcode_t rc = dns_decode(decoded, &decsz, (const dns_packet_t*)buf->base, (size_t)nread);

        if (p->is_init_probe) {
            if (p->test_type == PROBE_TEST_LONGNAME) {
                if (rc == RCODE_NAME_ERROR || rc == RCODE_OKAY || rc == RCODE_SERVER_FAILURE) {
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
                        p->test_res->upstream_mtu = 512;
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
                if (rc == RCODE_OKAY || rc == RCODE_NAME_ERROR || rc == RCODE_SERVER_FAILURE) {
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

int build_mtu_test_query(uint8_t *outbuf, size_t *outlen, const char *domain, uint16_t id, int mtu_size) {
    char qname[512] = {0};
    int qlen = 0;
    qlen += snprintf(qname, sizeof(qname), "mtu-req-%d.", mtu_size);
    /* Fill to targeted size roughly */
    int fill_needed = mtu_size - qlen - strlen(domain) - 20;
    while (fill_needed > 0) {
        int chunk = fill_needed > 63 ? 63 : fill_needed;
        for (int i=0; i<chunk; i++) {
            qname[qlen++] = 'm';
        }
        qname[qlen++] = '.';
        fill_needed -= chunk;
    }
    snprintf(qname + qlen, sizeof(qname) - qlen, "%s.", domain);

    dns_question_t question = {0};
    question.name = qname;
    question.type = RR_TXT;
    question.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = id;
    query.query = true;
    query.opcode = OP_QUERY;
    query.rd = true;
    query.qdcount = 1;
    query.questions = &question;

    dns_answer_t edns = {0};
    edns.generic.name = (char*)".";
    edns.generic.type = RR_OPT;
    edns.generic.class = 4096; 
    edns.generic.ttl = 0;
    query.arcount = 1;
    query.additional = &edns;

    size_t sz = *outlen;
    if (dns_encode((dns_packet_t*)outbuf, &sz, &query) != RCODE_OKAY) return -1;
    *outlen = sz;
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
        if (build_mtu_test_query(p->payload, &p->payload_len, domain, p->id, mtu_test_val) != 0) {
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
