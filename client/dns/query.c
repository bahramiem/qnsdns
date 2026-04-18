/**
 * @file client/dns/query.c
 * @brief DNS Query Building and Reply Handling Implementation (Client Side)
 */

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "third_party/spcdns/dns.h"
#include "third_party/spcdns/output.h"
#include "uv.h"

#include "shared/base32.h"
#include "shared/codec.h"
#include "shared/config.h"
#include "shared/resolver_pool.h"
#include "shared/types.h"

#include "client/dns/query.h"
#include "client/session/session.h"
#include "shared/tui.h"

/* ── Externals from client/main.c ── */
extern uv_loop_t *g_loop;
extern dnstun_config_t g_cfg;
extern tui_stats_t g_stats;
extern resolver_pool_t g_pool;
extern session_t g_sessions[];
extern int g_session_count;

/* Forward declarations */
typedef struct socks5_client socks5_client_t;
void socks5_flush_recv_buf(socks5_client_t *c);
void on_socks5_close(uv_handle_t *h);

/* Random 16-bit number for DNS transaction IDs */
static uint16_t rand_u16(void) { return (uint16_t)(rand() & 0xFFFF); }

/* ────────────────────────────────────────────── */
/*  Inline Dotify                                 */
/* ────────────────────────────────────────────── */

size_t inline_dotify(char *buf, size_t buflen, size_t len) {
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

/* ────────────────────────────────────────────── */
/*  Build DNS Query (Legacy/Single)               */
/* ────────────────────────────────────────────── */

int build_dns_query(uint8_t *outbuf, size_t *outlen, const query_header_t *hdr,
                    const uint8_t *payload, size_t paylen, const char *domain) {
  uint8_t raw[1024];
  size_t rawlen = 0;
  memcpy(raw, hdr, sizeof(query_header_t));
  rawlen += sizeof(query_header_t);
  if (payload && paylen > 0) {
    memcpy(raw + rawlen, payload, paylen);
    rawlen += paylen;
  }
  char b32_dotted[2048];
  size_t b32_len = base32_encode((uint8_t *)b32_dotted, raw, rawlen);
  size_t dotted_len = inline_dotify(b32_dotted, sizeof(b32_dotted), b32_len);
  char qname[512];
  snprintf(qname, sizeof(qname), "%s.%s", b32_dotted, domain);
  dns_question_t question = {0};
  question.name = qname; question.type = RR_TXT; question.class = CLASS_IN;
  dns_query_t query = {0};
  query.id = rand_u16(); query.query = true; query.rd = true; query.qdcount = 1; query.questions = &question;
  size_t sz = *outlen;
  if (dns_encode((dns_packet_t *)outbuf, &sz, &query) != RCODE_OKAY) return -1;
  *outlen = sz;
  return 0;
}

/* ────────────────────────────────────────────── */
/*  DNS Query Context                             */
/* ────────────────────────────────────────────── */

typedef struct dns_query_ctx {
  uv_udp_t udp;
  uv_timer_t timer;
  int closes;
  uv_udp_send_t send_req;
  struct sockaddr_in dest;
  int resolver_idx;
  int session_idx;
  uint16_t seq;
  uint64_t sent_ms;
  uint8_t sendbuf[2048];
  size_t sendlen;
  uint8_t recvbuf[4096];
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
    uv_close((uv_handle_t *)&q->udp, on_dns_query_close);
    uv_close((uv_handle_t *)&q->timer, on_dns_query_close);
  }
}

static void on_dns_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
  if (nread <= 0) return;
  dns_query_ctx_t *q = h->data;
  
  if (g_cfg.log_level >= 3) {
      char hex[128] = {0};
      for (size_t i = 0; i < (nread < 16 ? (size_t)nread : 16); i++) 
          sprintf(hex + i*2, "%02x", (uint8_t)buf->base[i]);
      LOG_DEBUG("  [UDP_RX] len=%zd from %s qid=%u hex=%s%s\n", 
                nread, g_pool.resolvers[q->resolver_idx].ip,
                (nread >= 2) ? (uint16_t)(((uint8_t)buf->base[0] << 8) | (uint8_t)buf->base[1]) : 0,
                hex, nread > 16 ? "..." : "");
  }

  int ridx = q->resolver_idx;
  double rtt = (double)(uv_hrtime() / 1000000ULL - q->sent_ms);
  rpool_on_ack(&g_pool, ridx, rtt);
  dns_decoded_t decoded[DNS_DECODEBUF_4K];
  size_t decsz = sizeof(decoded);
  dns_rcode_t rc = dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base, (size_t)nread);
  if (rc == RCODE_OKAY) {
    dns_query_t *resp = (dns_query_t *)decoded;
    for (int i = 0; i < (int)resp->ancount; i++) {
        dns_answer_t *ans = &resp->answers[i];
        if (ans->generic.type != RR_TXT || ans->txt.len == 0) continue;
        uint8_t raw_decoded[4096];
        ptrdiff_t decoded_len = base64_decode(raw_decoded, ans->txt.text, ans->txt.len);
        if (decoded_len < (ptrdiff_t)sizeof(server_response_header_t)) {
            LOG_DEBUG("  [IN] REJECTED (dec_len=%zd, expected >=%zu) from %s\n", 
                      decoded_len, sizeof(server_response_header_t), g_pool.resolvers[ridx].ip);
            continue;
        }
        session_t *s = &g_sessions[q->session_idx];
        server_response_header_t resp_hdr;
        memcpy(&resp_hdr, raw_decoded, sizeof(resp_hdr));
        if (resp_hdr.session_id != s->session_id) {
            LOG_DEBUG("  [IN] IGNORED (sid mismatch: recv=%u, current=%u) from %s\n", 
                      resp_hdr.session_id, s->session_id, g_pool.resolvers[ridx].ip);
            continue;
        }
        if (resp_hdr.flags & RESP_FLAG_MORE_DATA) s->fast_poll = true;
        
        /* ACK Pruning */
        uint16_t ack_seq = resp_hdr.ack_seq;
        if (ack_seq > s->tx_acked || (ack_seq < 100 && s->tx_acked > 60000)) {
            uint32_t prune = s->tx_offset_map[ack_seq % 256];
            if (prune > 0 && prune <= s->send_len) {
                if (g_cfg.log_level >= 3) LOG_DEBUG("  [PRUNE] ack=%u offset=%u len=%zu\n", ack_seq, (uint32_t)prune, s->send_len);
                memmove(s->send_buf, s->send_buf + prune, s->send_len - prune);
                s->send_len -= prune; s->tx_acked = ack_seq; s->last_ack_time = time(NULL);
                for(int m=0;m<256;m++) { if(s->tx_offset_map[m]>=prune) s->tx_offset_map[m]-=prune; else s->tx_offset_map[m]=0; }
            } else if (ack_seq == s->tx_next) { 
                if (g_cfg.log_level >= 3 && s->send_len > 0) LOG_DEBUG("  [PRUNE] full clear at seq %u\n", ack_seq);
                s->send_len = 0; s->tx_acked = ack_seq; memset(s->tx_offset_map, 0, sizeof(s->tx_offset_map)); 
            }
        }

        const uint8_t *payload = raw_decoded + sizeof(resp_hdr);
        size_t paylen = (size_t)(decoded_len - sizeof(resp_hdr));

        if (g_cfg.log_level >= 2) {
            LOG_DEBUG("  [IN] sid=%u recv_len=%zu header_flags=%02x paylen=%zu\n",
                      q->session_idx, decoded_len, resp_hdr.flags, paylen);
        }

        /* Handshake Echo Processing */
        if (paylen == sizeof(handshake_packet_t)) {
            handshake_packet_t *echo = (handshake_packet_t *)payload;
            if (echo->version == DNSTUN_VERSION) {
                if (!s->fec_synced) {
                    s->fec_synced = true; 
                    s->cl_fec_k = ntohs(echo->fec_k); 
                    s->cl_fec_n = ntohs(echo->fec_n); 
                    s->cl_symbol_size = ntohs(echo->symbol_size);
                    s->cl_loss_pct = echo->loss_pct;
                    
                    LOG_INFO("Session %u: Established (FEC K:%u N:%u Sym:%u Link:%u/%u)\n", 
                             s->session_id, s->cl_fec_k, s->cl_fec_n, s->cl_symbol_size,
                             ntohs(echo->upstream_mtu), ntohs(echo->downstream_mtu));

                    if (s->socks5_pending_ok && s->client_ptr) {
                        socks5_client_t *c = (socks5_client_t *)s->client_ptr;
                        extern void socks5_send(socks5_client_t *, const uint8_t *, size_t);
                        uint8_t ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                        socks5_send(c, ok, 10);
                        s->socks5_connected = true;
                        s->socks5_pending_ok = false;
                    }
                }
                /* ALWAYS continue for version-matched handshake packets to prevent SOCKS5 corruption */
                continue; 
            }
        }

        /* Data Processing */
        if (paylen == 0) continue;

        bool has_seq = (resp_hdr.flags & RESP_FLAG_HAS_SEQ) != 0;
        uint16_t seq = has_seq ? resp_hdr.seq : 0;
        if (has_seq) {
            if (!s->first_seq_received && seq == 0) s->first_seq_received = true;
            reorder_buffer_insert(&s->reorder_buf, seq, payload, paylen);
            uint8_t flush_buf[16384]; size_t flush_len = 0;
            while (reorder_buffer_flush(&s->reorder_buf, flush_buf, sizeof(flush_buf), &flush_len) > 0) {
                size_t start = 0;
                if (!s->status_consumed) { s->status_consumed = true; start = 1;
                    if (s->client_ptr) {
                        socks5_client_t *c = (socks5_client_t *)s->client_ptr;
                        if (flush_buf[0] == 0x00) { if (s->fec_synced) { extern void socks5_send(socks5_client_t *, const uint8_t *, size_t); uint8_t ok[10]={0x05,0,0,1,0,0,0,0,0,0}; socks5_send(c, ok, 10); s->socks5_connected = true; } else s->socks5_pending_ok = true; }
                        else { extern void socks5_send(socks5_client_t *, const uint8_t *, size_t); uint8_t err[10]={0x05, flush_buf[0],0,1,0,0,0,0,0,0}; socks5_send(c, err, 10); uv_close((uv_handle_t *)c, on_socks5_close); }
                    }
                }
                size_t dlen = flush_len - start;
                if (dlen > 0 && s->recv_len + dlen <= s->recv_cap) { memcpy(s->recv_buf + s->recv_len, flush_buf + start, dlen); s->recv_len += dlen; g_stats.rx_total += dlen; g_stats.rx_bytes_sec += dlen; }
                if (s->client_ptr) socks5_flush_recv_buf((socks5_client_t *)s->client_ptr);
            }
        }
    }
    g_stats.queries_recv++;
  }
  if (!uv_is_closing((uv_handle_t *)&q->udp)) { uv_close((uv_handle_t *)&q->udp, on_dns_query_close); uv_close((uv_handle_t *)&q->timer, on_dns_query_close); }
}

static void on_dns_send(uv_udp_send_t *sr, int status) {
    dns_query_ctx_t *q = sr->handle->data;
    if (status != 0 && !uv_is_closing((uv_handle_t *)&q->udp)) {
        rpool_on_loss(&g_pool, q->resolver_idx); g_stats.queries_lost++;
        uv_close((uv_handle_t *)&q->udp, on_dns_query_close); uv_close((uv_handle_t *)&q->timer, on_dns_query_close);
    }
}

static void on_dns_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    dns_query_ctx_t *q = h->data;
    buf->base = (char *)q->recvbuf; buf->len = sizeof(q->recvbuf);
}

static void on_dns_response(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    on_dns_recv(h, nread, buf, addr, flags);
}

/* ────────────────────────────────────────────── */
/*  MTU Handshake                                 */
/* ────────────────────────────────────────────── */

void send_mtu_handshake(int session_idx) {
    session_t *s = &g_sessions[session_idx];
    handshake_packet_t hs = {0};
    hs.version = DNSTUN_VERSION; 
    hs.upstream_mtu = htons(512); 
    hs.downstream_mtu = htons(220); 
    hs.fec_k = htons((uint16_t)g_cfg.fec_k); 
    hs.fec_n = htons((uint16_t)g_cfg.fec_n); 
    hs.symbol_size = htons(DNSTUN_CHUNK_PAYLOAD); 
    hs.encoding = DNSTUN_ENC_BASE64;
    const uint8_t *hs_ptr[1] = {(const uint8_t *)&hs};
    int esi = 0;
    for (int i=0; i<3; i++) { esi = 0; fire_dns_multi_symbols(session_idx, 0, hs_ptr, sizeof(hs), 1, &esi, false); }
}

/* ────────────────────────────────────────────── */
/*  Fire Multi-Symbol DNS Query                   */
/* ────────────────────────────────────────────── */

int fire_dns_multi_symbols(int session_idx, uint16_t seq,
                            const uint8_t **payloads, size_t paylen,
                            int num_symbols_total, int *esi_progress,
                            bool is_compressed) {
  if (session_idx < 0 || session_idx >= DNSTUN_MAX_SESSIONS) return 0;
  session_t *sess = &g_sessions[session_idx];
  int cur_esi = esi_progress ? *esi_progress : 0;
  int symbols_sent_this_call = 0;

  if (num_symbols_total > 1 && !sess->fec_synced && !g_cfg.encryption) return 0;

  while (cur_esi < num_symbols_total || num_symbols_total == 0) {
    dns_query_ctx_t *q = calloc(1, sizeof(*q));
    if (!q) return symbols_sent_this_call;
    uv_udp_init(g_loop, &q->udp); q->udp.data = q;
    int ridx = rpool_next_ready(&g_pool, g_cfg.poll_interval_ms);
    if (ridx < 0) { uv_close((uv_handle_t *)&q->udp, on_dns_query_close); return symbols_sent_this_call; }
    resolver_t *r = &g_pool.resolvers[ridx];
    q->resolver_idx = ridx; q->session_idx = session_idx; q->seq = seq;
    int didx = rpool_flux_domain(&g_cfg);
    const char *domain = (g_cfg.domain_count > 0) ? g_cfg.domains[didx] : "tun.example.com";
    int to_pack = 1;
    if (num_symbols_total > 1) {
        /* Optimize: Pack as many symbols as MTU allows. 
         * Overhead: ~30 chars base32 for header/ACK, plus domain labels. 
         * To be safe, use (MTU - 64) available for symbols. */
        int max_pack = (r->upstream_mtu > 64) ? (r->upstream_mtu - 64) / (paylen + 1) : 1;
        if (max_pack < 1) max_pack = 1;
        if (max_pack > 20) max_pack = 20; /* DNS label limit safely within 255 chars */
        to_pack = (num_symbols_total - cur_esi < max_pack) ? (num_symbols_total - cur_esi) : max_pack;
    } else if (num_symbols_total == 0) {
        to_pack = 0;
    }

    uint8_t pb[1024]; size_t pl = 0; uint8_t fl = 0;
    if (num_symbols_total == 0) {
        capability_header_t cap = {0}; cap.version=DNSTUN_VERSION; cap.upstream_mtu=r->upstream_mtu; cap.downstream_mtu=r->downstream_mtu; cap.encoding=DNSTUN_ENC_BASE64; cap.ack_seq=sess->reorder_buf.expected_seq;
        memcpy(pb, &cap, sizeof(cap)); pl = sizeof(cap); fl = CHUNK_FLAG_POLL;
        LOG_DEBUG("[UPSTREAM] Sending POLL for sid=%u (ack=%u)\n", session_idx, cap.ack_seq);
    } else if (num_symbols_total == 1 && cur_esi == 0) {
        /* Handshake: No ACK prepend, matching handshake_packet_t layout on server */
        memcpy(pb, payloads[0], paylen); pl = paylen; fl = CHUNK_FLAG_HANDSHAKE;
        LOG_DEBUG("[UPSTREAM] Sending HANDSHAKE for sid=%u (len=%zu)\n", session_idx, pl);
    } else {
        uint16_t ack = sess->reorder_buf.expected_seq; pb[pl++]=(uint8_t)(ack>>8); pb[pl++]=(uint8_t)ack;
        if (num_symbols_total > 1) fl = (is_compressed?CHUNK_FLAG_COMPRESSED:0)|(g_cfg.encryption?CHUNK_FLAG_ENCRYPTED:0)|CHUNK_FLAG_FEC;
        for (int i=0; i<to_pack; i++) { if (num_symbols_total>1) pb[pl++]=(uint8_t)(cur_esi+i); memcpy(pb+pl, payloads[cur_esi+i], paylen); pl += paylen; }
        LOG_DEBUG("[UPSTREAM] Sending DATA for sid=%u seq=%u pack=%d esi=%d/%d\n", session_idx, seq, to_pack, cur_esi, num_symbols_total);
    }
    
    query_header_t qh = {0};
    qh.sid = sess->session_id;
    qh.flags = fl | CHUNK_FLAG_IS_TUNNEL;
    qh.seq = seq;

    uint8_t tp[1400]; size_t tl=0; memcpy(tp, &qh, sizeof(qh)); tl+=sizeof(qh); memcpy(tp+tl, pb, pl); tl+=pl;
    
    if (g_cfg.log_level >= 3) {
        char hex[128] = {0};
        for (size_t i = 0; i < (tl < 16 ? tl : 16); i++) sprintf(hex + i*2, "%02x", tp[i]);
        LOG_DEBUG("[UPSTREAM] RAW HDR+PAYLOAD (len=%zu): %s%s\n", tl, hex, tl > 16 ? "..." : "");
    }

    size_t bl = base32_encode((char *)q->sendbuf, tp, tl);
    inline_dotify((char *)q->sendbuf, sizeof(q->sendbuf), bl);
    
    /* 
     * CRITICAL: Reverting to old working QNAME format. 
     * 1. Add trailing dot to ensure an absolute FQDN (avoids suffix search issues).
     * 2. Remove the '.x.' separator for tunnel traffic (keeps format simple like old working code).
     * DO NOT REMOVE THIS TRAILING DOT - it is required for network traversal via some resolvers.
     */
    char qn[2048]; 
    snprintf(qn, sizeof(qn), "%s.%s.", (char *)q->sendbuf, domain);
    if (g_cfg.log_level >= 3) {
        LOG_DEBUG("  [DNS_BUILD] qname=%s\n", qn);
    }
    
    dns_question_t quest={0}; quest.name=qn; quest.type=RR_TXT; quest.class=CLASS_IN;

    /* 
     * CRITICAL: Add EDNS0 (OPT record) to every query.
     * This signals support for larger payloads and prevents some resolvers (like 8.8.8.8) 
     * from dropping these queries as "suspicious" tunneling. 
     * DO NOT REMOVE THIS RECORD.
     */
    dns_answer_t edns = {0};
    edns.generic.name  = (char *)".";
    edns.generic.type  = RR_OPT;
    edns.generic.class = 1232; /* Advertised UDP payload size */
    edns.generic.ttl   = 0;

    dns_query_t query={0}; 
    query.id=rand_u16(); 
    query.query=true; 
    query.rd=true; 
    query.qdcount=1; 
    query.questions=&quest;
    query.arcount = 1;
    query.additional = &edns;

    LOG_INFO("[DNS_FIRE] qid=%u sid=%u flags=%02x seq=%u (payload=%zu bytes) to %s\n", 
               query.id, qh.sid, qh.flags, qh.seq, pl, rpool_get_name(&g_pool, ridx));
    size_t pktsz = sizeof(q->recvbuf); /* temporary use of recvbuf for encoding */
    if (dns_encode((dns_packet_t *)q->recvbuf, &pktsz, &query) != RCODE_OKAY) { 
        uv_close((uv_handle_t *)&q->udp, on_dns_query_close); 
        continue; 
    }
    memcpy(q->sendbuf, q->recvbuf, pktsz); q->sendlen = pktsz;
    uv_timer_init(g_loop, &q->timer); q->timer.data = q; uv_timer_start(&q->timer, on_dns_timeout, 8000, 0); uv_udp_recv_start(&q->udp, on_dns_alloc, on_dns_recv);
    q->sent_ms = uv_hrtime()/1000000ULL; uv_buf_t b = uv_buf_init((char *)q->sendbuf, (unsigned)pktsz);
    if (uv_udp_send(&q->send_req, &q->udp, &b, 1, (const struct sockaddr *)&r->addr, on_dns_send) != 0) { uv_close((uv_handle_t *)&q->udp, on_dns_query_close); uv_close((uv_handle_t *)&q->timer, on_dns_query_close); continue; }
    r->last_query_ms = q->sent_ms; 
    symbols_sent_this_call += (to_pack > 0 ? to_pack : 1); 
    cur_esi += to_pack; 
    if (esi_progress) *esi_progress = (uint16_t)cur_esi;
    if (num_symbols_total == 0) break;
  }
  return symbols_sent_this_call;
}
