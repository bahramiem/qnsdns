/**
 * @file server/dns/protocol.c
 * @brief DNS TXT Reply Building and Main UDP Receive Handler Implementation
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef sync
#undef sync
#endif
#else
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#endif

#include "uv.h"
#include "third_party/spcdns/dns.h"
#include "third_party/spcdns/output.h"

#include "shared/base32.h"
#include "shared/codec.h"
#include "shared/config.h"
#include "shared/types.h"

#include "server/session/session.h"
#include "server/swarm/swarm.h"
#include "server/dns/protocol.h"
#include "shared/tui.h"

/* ── Externals from main.c ── */
extern uv_loop_t       *g_loop;
extern dnstun_config_t  g_cfg;
extern tui_stats_t      g_stats;
extern uv_udp_t         g_udp_server;

/* ────────────────────────────────────────────── */
/*  Downstream Encoding Helper                    */
/* ────────────────────────────────────────────── */

static size_t encode_downstream_data(char *out, const uint8_t *in, size_t inlen) {
    if (g_cfg.downstream_encoding == 1)
        return hex_encode(out, in, inlen);
    return base64_encode(out, in, inlen);
}

/* ── DNS Reply Builders ─────────────────────────────────────────── */

int build_txt_reply_naked(uint8_t *outbuf, size_t *outlen,
                          uint16_t query_id, const char *qname,
                          const uint8_t *data, size_t data_len) {
    dns_answer_t ans = {0};
    ans.txt.name = (char *)qname;
    ans.txt.type = RR_TXT;
    ans.txt.class = CLASS_IN;
    ans.txt.ttl = 0;
    ans.txt.len = (uint16_t)data_len;
    ans.txt.text = (uint8_t *)data;

    dns_question_t q = {0};
    q.name = (char *)qname;
    q.type = RR_TXT;
    q.class = CLASS_IN;

    dns_answer_t edns = {0};
    edns.opt.name = (char *)".";
    edns.opt.type = RR_OPT;
    edns.opt.udp_payload = 4096;
    edns.opt.ttl = 0;
    edns.opt.version = 0;

    dns_query_t resp = {0};
    resp.id = query_id;
    resp.query = false;
    resp.rd = true;
    resp.ra = true;
    resp.qdcount = 1;
    resp.ancount = 1;
    resp.arcount = 1;
    resp.questions = &q;
    resp.answers = &ans;
    resp.additional = &edns;

    size_t sz = *outlen;
    dns_rcode_t rc = dns_encode((dns_packet_t *)outbuf, &sz, &resp);
    if (rc != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

#define MAX_FRAGMENTS 8
#define MAX_CHUNK_BINARY 191 

int build_txt_reply_multi(uint8_t *outbuf, size_t *outlen,
                          uint16_t query_id, const char *qname,
                          const uint8_t *data, size_t data_len,
                          uint16_t mtu, uint16_t start_seq,
                          uint16_t ack_seq,
                          uint8_t session_id, bool has_seq,
                          bool buffer_has_more,
                          int *num_frags, size_t *bytes_consumed) {
    if (num_frags) *num_frags = 0;
    if (bytes_consumed) *bytes_consumed = 0;

    size_t base_overhead = 12 + strlen(qname) + 6 + 11 + 20 + 32;
    if (mtu < base_overhead + 128) mtu = base_overhead + 128;
    size_t safe_packet_budget = (mtu > base_overhead + 128) ? ((mtu - base_overhead - 128) * 75 / 100) : 64;
    
    dns_answer_t ans[MAX_FRAGMENTS];
    char **encoded_chunks = malloc(MAX_FRAGMENTS * sizeof(char *));
    for (int i = 0; i < MAX_FRAGMENTS; i++) encoded_chunks[i] = malloc(1024);

    uint16_t current_seq = start_seq;
    int frag_count = 0;
    size_t data_offset = 0;
    size_t current_packet_size = 0;

    do {
        int chunk_data_len = (int)(data_len - data_offset);
        if (chunk_data_len > MAX_CHUNK_BINARY) chunk_data_len = MAX_CHUNK_BINARY;

        size_t frag_overhead = strlen(qname) + 11; 
        size_t b64_chars = (chunk_data_len == 0) ? 8 : ((chunk_data_len + 5) / 3 * 4);
        if (current_packet_size + frag_overhead + b64_chars > safe_packet_budget && frag_count > 0)
            break;

        server_response_header_t hdr = {0};
        hdr.session_id = session_id;
        hdr.flags = 0;
        if (has_seq) hdr.flags |= RESP_FLAG_HAS_SEQ;
        if (buffer_has_more || (data_offset + (size_t)chunk_data_len < data_len)) {
            hdr.flags |= RESP_FLAG_MORE_DATA;
        }
        hdr.seq = current_seq;
        hdr.ack_seq = ack_seq;

        uint8_t packet[1024];
        size_t packet_len = 0;
        if (g_cfg.log_level >= 3) {
            LOG_DEBUG("  [BUILD] Frag %d: chunk=%d b64=%zu overhead=%zu budget=%zu\n", 
                      frag_count, chunk_data_len, b64_chars, frag_overhead, safe_packet_budget);
        }
        memcpy(packet, &hdr, sizeof(hdr));
        packet_len += sizeof(hdr);

        if (chunk_data_len > 0 && data != NULL) {
            bool used_compression = false;
            if (g_cfg.downstream_compression && chunk_data_len > 16) {
                codec_result_t zres = codec_compress(data + data_offset, chunk_data_len, 0);
                if (!zres.error && zres.len < (size_t)chunk_data_len) {
                    hdr.flags |= RESP_FLAG_COMPRESSED;
                    LOG_DEBUG("Session %u: COMPRESSED fragment %d -> %zu bytes\n", session_id, chunk_data_len, zres.len);
                    memcpy(packet + packet_len, zres.data, zres.len);
                    packet_len += zres.len;
                    used_compression = true;
                }
                codec_free_result(&zres);
            }
            
            if (!used_compression) {
                memcpy(packet + packet_len, data + data_offset, chunk_data_len);
                packet_len += chunk_data_len;
            }
        }

        /* Update header in packet buffer since flags might have changed */
        memcpy(packet, &hdr, sizeof(hdr));

        size_t elen = encode_downstream_data(encoded_chunks[frag_count], packet, packet_len);
        if (elen >= 1024) elen = 1023;
        encoded_chunks[frag_count][elen] = '\0';

        ans[frag_count].txt.name = (char *)qname;
        ans[frag_count].txt.type = RR_TXT;
        ans[frag_count].txt.class = CLASS_IN;
        ans[frag_count].txt.ttl = 0;
        ans[frag_count].txt.len = (uint16_t)elen;
        ans[frag_count].txt.text = encoded_chunks[frag_count];

        current_packet_size += (frag_overhead + elen);
        frag_count++;
        current_seq++;
        data_offset += chunk_data_len;

    } while (data_offset < data_len && frag_count < MAX_FRAGMENTS);

    if (num_frags) *num_frags = frag_count;
    if (bytes_consumed) *bytes_consumed = data_offset;

    dns_answer_t edns = {0};
    edns.opt.name = (char *)".";
    edns.opt.type = RR_OPT;
    edns.opt.udp_payload = 4096;
    edns.opt.ttl = 0;
    edns.opt.version = 0;

    dns_question_t q = {0};
    q.name = qname;
    q.type = RR_TXT;
    q.class = CLASS_IN;

    dns_query_t resp = {0};
    resp.id = query_id;
    resp.query = false;
    resp.rd = true;
    resp.ra = true;
    resp.qdcount = 1;
    resp.ancount = frag_count;
    resp.arcount = 1;
    resp.questions = &q;
    resp.answers = ans;
    resp.additional = &edns;

    size_t sz = *outlen;
    dns_rcode_t rc = dns_encode((dns_packet_t *)outbuf, &sz, &resp);
    
    for (int i = 0; i < MAX_FRAGMENTS; i++) free(encoded_chunks[i]);
    free(encoded_chunks);

    if (rc != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

int build_txt_reply_with_seq(uint8_t *outbuf, size_t *outlen,
                             uint16_t query_id, const char *qname,
                             const uint8_t *data, size_t data_len,
                             uint16_t mtu, uint16_t seq,
                             uint16_t ack_seq,
                             uint8_t session_id, bool has_seq,
                             bool buffer_has_more) {
    int nf = 0;
    size_t bc = 0;
    return build_txt_reply_multi(outbuf, outlen, query_id, qname, data, data_len,
                                 mtu, seq, ack_seq, session_id, has_seq,
                                 buffer_has_more, &nf, &bc);
}

/* ────────────────────────────────────────────── */
/*  UDP Reply Helper                              */
/* ────────────────────────────────────────────── */

typedef struct {
    uv_udp_send_t    send_req;
    struct sockaddr_in dest;
    uint8_t          reply_buf[4096];
    size_t           reply_len;
} udp_reply_t;

static void on_udp_send_done(uv_udp_send_t *r, int status) {
    (void)status;
    free((udp_reply_t *)r);
}

void send_udp_reply(const struct sockaddr_in *dest, const uint8_t *data, size_t len) {
    char ip[INET_ADDRSTRLEN];
    uv_ip4_name(dest, ip, sizeof(ip));
    if (g_cfg.log_level >= 3) {
        LOG_DEBUG("  [OUT] -> %s:%d len=%zu (qid=%u)\n", 
                  ip, ntohs(dest->sin_port), len, 
                  (len >= 2) ? (uint16_t)((data[0] << 8) | data[1]) : 0);
    }
    udp_reply_t *rep = malloc(sizeof(*rep));
    if (!rep) return;
    memcpy(&rep->dest, dest, sizeof(*dest));
    if (len > sizeof(rep->reply_buf)) len = sizeof(rep->reply_buf);
    memcpy(rep->reply_buf, data, len);
    rep->reply_len = len;

    uv_buf_t buf = uv_buf_init((char *)rep->reply_buf, (unsigned)len);
    if (uv_udp_send(&rep->send_req, &g_udp_server, &buf, 1,
                    (const struct sockaddr *)dest, on_udp_send_done) != 0) {
        free(rep);
    }
    g_stats.queries_sent++;
}

/* ────────────────────────────────────────────── */
/*  Main UDP Receive / Dispatch                   */
/* ────────────────────────────────────────────── */

static uint8_t s_recv_buf[65536];

void on_server_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    (void)h; (void)sz;
    buf->base = (char *)s_recv_buf;
    buf->len  = sizeof(s_recv_buf);
}

void on_server_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags) {
    (void)h; (void)flags;
    if (nread <= 0 || !addr) {
        if (nread < 0) LOG_ERR("UDP recv error: %zd\n", nread);
        return;
    }

    const struct sockaddr_in *src = (const struct sockaddr_in *)addr;
    char src_ip[46];
    uv_inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
    g_stats.queries_recv++;
    swarm_record_ip(src_ip);

    dns_decoded_t decoded[DNS_DECODEBUF_4K];
    size_t decsz = sizeof(decoded);
    if (dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base, (size_t)nread) != RCODE_OKAY) {
        LOG_DEBUG("  [IN] dns_decode FAILED for %zd bytes from %s\n", nread, src_ip);
        g_stats.queries_lost++;
        return;
    }

    dns_query_t *qry = (dns_query_t *)decoded;
    if (qry->qdcount < 1) return;

    const char *qname    = qry->questions[0].name;
    uint16_t    query_id = qry->id;
    uint16_t    qtype    = qry->questions[0].type;
    LOG_DEBUG("  [RAW] qid=%u qtype=%u qname=%s from %s\n", query_id, qtype, qname, src_ip);

    char tmp[DNSTUN_MAX_QNAME_LEN + 1];
    strncpy(tmp, qname, sizeof(tmp) - 1);
    tmp[DNSTUN_MAX_QNAME_LEN] = '\0';

    char *parts[16] = {0};
    int   part_count = 0;
    char *tok = strtok(tmp, ".");
    while (tok && part_count < 16) { parts[part_count++] = tok; tok = strtok(NULL, "."); }

    int  domain_parts   = 0;
    bool is_mtu_probe   = false;
    bool is_crypto_probe = false;
    bool is_capability_probe = false;
    bool is_mine        = false;

    for (int d = 0; d < g_cfg.domain_count; d++) {
        const char *domain = g_cfg.domains[d];
        char domain_tmp[256];
        strncpy(domain_tmp, domain, sizeof(domain_tmp) - 1);
        char *domain_labels[8]; int dparts = 0;
        char *dtok = strtok(domain_tmp, ".");
        while (dtok && dparts < 8) { domain_labels[dparts++] = dtok; dtok = strtok(NULL, "."); }

        if (part_count >= dparts) {
            bool match = true;
            for (int j = 0; j < dparts; j++) {
                const char *qpart = parts[part_count - dparts + j];
#ifdef _WIN32
                if (_stricmp(qpart, domain_labels[j]) != 0) { match = false; break; }
#else
                if (strcasecmp(qpart, domain_labels[j]) != 0) { match = false; break; }
#endif
            }
            if (match) { 
                domain_parts = dparts; 
                is_mine = true; 
#ifdef _WIN32
                if (part_count > dparts && _stricmp(parts[part_count - dparts - 1], "x") == 0) domain_parts++;
#else
                if (part_count > dparts && strcasecmp(parts[part_count - dparts - 1], "x") == 0) domain_parts++;
#endif
                break; 
            }
        }
    }

    if (!is_mine) {
        LOG_DEBUG("  [IN] REJECTED (not my domain): qid=%u qname=%s from %s\n", query_id, qname, src_ip);
        return;
    }

    int payload_start_idx = part_count - domain_parts;
    if (payload_start_idx >= 1 && parts[0] != NULL) {
#ifdef _WIN32
        if (_strnicmp(parts[0], "mtu-req-", 8) == 0) is_mtu_probe = true;
        if (_strnicmp(parts[0], "CRYPTO_", 7)  == 0) is_crypto_probe = true;
        if (_stricmp(parts[0], "probe")       == 0) is_capability_probe = true;
#else
        if (strncasecmp(parts[0], "mtu-req-", 8) == 0) is_mtu_probe = true;
        if (strncasecmp(parts[0], "CRYPTO_", 7)  == 0) is_crypto_probe = true;
        if (strcasecmp(parts[0], "probe")       == 0) is_capability_probe = true;
#endif
    }

    if (qtype != RR_TXT && qtype != RR_ANY) {
        if (!is_mtu_probe && !is_capability_probe && !is_crypto_probe) {
            uint8_t nx[512];
            nx[0] = query_id >> 8; nx[1] = query_id & 0xFF;
            nx[2] = 0x81; nx[3] = 0x03;
            nx[4] = 0x00; nx[5] = 0x01;
            nx[6] = 0x00; nx[7] = 0x00;
            nx[8] = 0x00; nx[9] = 0x00;
            nx[10] = 0x00; nx[11] = 0x00;
            size_t q_len = (size_t)nread > 12 ? (size_t)nread - 12 : 0;
            if (q_len > sizeof(nx) - 12) q_len = sizeof(nx) - 12;
            memcpy(nx + 12, buf->base + 12, q_len);
            send_udp_reply(src, nx, 12 + q_len);
            return;
        }
    }

    if (is_mtu_probe && parts[0] != NULL) {
        int requested_mtu = atoi(parts[0] + 8);
        if (requested_mtu > 0 && requested_mtu <= 4096) {
            uint8_t *mtu_payload = malloc(4096);
            if (mtu_payload) {
                for (int i = 0; i < requested_mtu && i < 4096; i++) mtu_payload[i] = (uint8_t)(rand() & 0xFF);
                uint8_t reply[5120]; size_t rlen = sizeof(reply);
                if (build_txt_reply_naked(reply, &rlen, query_id, qname, mtu_payload, (size_t)requested_mtu) == 0)
                    send_udp_reply(src, reply, rlen);
                free(mtu_payload);
            }
        }
        return;
    }

    if (is_capability_probe) {
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        const uint8_t resp[] = "OK";
        if (build_txt_reply_naked(reply, &rlen, query_id, qname, resp, sizeof(resp)-1) == 0)
            send_udp_reply(src, reply, rlen);
        return;
    }

    char b32_payload[4096] = {0};
    for (int i = 0; i < payload_start_idx; i++) {
        /* Skip the "x" separator if it's the last label before the domain */
        if (i == payload_start_idx - 1 && strcmp(parts[i], "x") == 0) continue;
        strncat(b32_payload, parts[i], sizeof(b32_payload) - strlen(b32_payload) - 1);
    }
    size_t b32_len = strlen(b32_payload);

    uint8_t raw[4096];
    ssize_t rawlen  = base32_decode(raw, b32_payload, b32_len);

    if (rawlen < 0) {
        LOG_DEBUG("  [RAW] sid=N/A: Base32 decode failed for payload: %s\n", b32_payload);
        return;
    }

    if (g_cfg.log_level >= 3) {
        char hex[128] = {0};
        for (size_t i = 0; i < (rawlen < 16 ? (size_t)rawlen : 16); i++) sprintf(hex + i*2, "%02x", raw[i]);
        LOG_DEBUG("  [RAW] DECODED (len=%zd): %s%s\n", rawlen, hex, rawlen > 16 ? "..." : "");
    }

    if (rawlen < (ssize_t)sizeof(query_header_t)) {
        LOG_DEBUG("  [IN] REJECTED (too short: %zd < %zu): qname=%s from %s\n", rawlen, sizeof(query_header_t), qname, src_ip);
        return;
    }

    query_header_t *q_hdr = (query_header_t *)raw;
    uint8_t session_id = q_hdr->sid;
    uint8_t q_flags     = q_hdr->flags;
    uint16_t seq       = q_hdr->seq;
    
    const uint8_t *payload     = raw + sizeof(query_header_t);
    size_t         payload_len = (size_t)(rawlen - sizeof(query_header_t));

    LOG_DEBUG("  [IN] sid=%u flags=%02x seq=%u rawlen=%zd payload_len=%zu\n", 
              session_id, q_flags, seq, rawlen, payload_len);
    
    /* ── Traffic Isolation ─────────────────────────────────────── */
    if (!(q_flags & CHUNK_FLAG_IS_TUNNEL)) {
        /* This is either a random MTU Phase 1/3 label or an Upload MTU probe.
         * Send a generic "OK" TXT reply so the client MTU test passes. */
        LOG_DEBUG("  [PROBE] Identified non-tunnel probe (qid=%u flags=%02x). Sending OK.\n",
                  query_id, q_flags);
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        const uint8_t resp[] = "OK";
        if (build_txt_reply_naked(reply, &rlen, query_id, qname, resp, sizeof(resp)-1) == 0)
            send_udp_reply(src, reply, rlen);
        return;
    }
    
    
    bool    is_poll      = (q_flags & CHUNK_FLAG_POLL) != 0;
    bool    is_encrypted = (q_flags & CHUNK_FLAG_ENCRYPTED) != 0;
    bool    is_fec       = (q_flags & CHUNK_FLAG_FEC) != 0;
    bool    is_sync      = false;

    /* ── Tiered Metadata Parsing ──────────────────────────────── */
    uint16_t client_upstream_mtu = 220;
    uint16_t client_downstream_mtu = g_cfg.downstream_mtu;
    uint16_t client_ack_seq   = 0;
    bool     has_ack          = false;
    bool     has_capability_header = false;
    bool     is_handshake = (q_flags & CHUNK_FLAG_HANDSHAKE) != 0;

    if (is_poll) {
        /* POLL/SYNC: Expect full 9-byte capability header */
        if (payload_len >= sizeof(capability_header_t)) {
            capability_header_t cap;
            memcpy(&cap, payload, sizeof(cap));
            if (cap.version == DNSTUN_VERSION) {
                client_upstream_mtu   = cap.upstream_mtu;
                client_downstream_mtu = cap.downstream_mtu;
                client_ack_seq         = cap.ack_seq;
                has_ack               = true;
                has_capability_header = true;
                payload     += sizeof(capability_header_t);
                payload_len -= sizeof(capability_header_t);
            }
        }
    } else if (is_handshake) {
        /* Handshake: No extra metadata prepended, payload IS the handshake struct */
    } else if (payload_len >= 2) {
        /* DATA/FEC: Expect 2-byte compact ACK */
        client_ack_seq = (uint16_t)((payload[0] << 8) | payload[1]);
        has_ack = true;
        if (g_cfg.log_level >= 3) {
            LOG_DEBUG("  [ACK] sid=%u: Client expects next seq %u\n", session_id, client_ack_seq);
        }
        payload     += 2;
        payload_len -= 2;
    }

    if (payload_len >= 4 && memcmp(payload, "SYNC", 4) == 0) is_sync = true;

    int sidx = session_find_by_id(session_id);
    if (sidx < 0) {
        sidx = session_alloc_by_id(session_id);
        if (sidx < 0) {
            LOG_WARN("Failed to allocate session for id=%u\n", session_id);
            return;
        }
        LOG_INFO("New session id=%u allocated at index %d\n", session_id, sidx);
    }

    srv_session_t *sess = &g_sessions[sidx];
    sess->last_active   = time(NULL);
    sess->client_addr   = *src;

    if (has_capability_header) {
        sess->cl_upstream_mtu = client_upstream_mtu;
        sess->cl_downstream_mtu = client_downstream_mtu;
    }

    if (is_handshake) {
        handshake_packet_t hs;
        if (payload_len < sizeof(hs)) {
            LOG_DEBUG("  [HANDSHAKE] Error: payload too short (%zu < %zu)\n", payload_len, sizeof(hs));
            return;
        }
        memcpy(&hs, payload, sizeof(hs));
        
        if (hs.version != DNSTUN_VERSION) {
            LOG_DEBUG("  [HANDSHAKE] sid=%u Error: protocol version mismatch (recv:%u expected:%u)\n", 
                      session_id, hs.version, DNSTUN_VERSION);
            return;
        }
        LOG_DEBUG("  [HANDSHAKE] sid=%u version=%u (valid)\n", session_id, hs.version);
        
        uint16_t umtu = ntohs(hs.upstream_mtu);
        uint16_t dmtu = ntohs(hs.downstream_mtu);
        
        if (umtu >= 128) sess->cl_upstream_mtu = umtu;
        if (dmtu >= 128) sess->cl_downstream_mtu = dmtu;
        sess->cl_fec_k = ntohs(hs.fec_k);
        sess->cl_fec_n = ntohs(hs.fec_n);
        sess->cl_symbol_size = ntohs(hs.symbol_size);
        sess->cl_enc_format = hs.encoding;
        sess->cl_loss_pct = hs.loss_pct;
        
        LOG_INFO("Session %d: Handshake complete (CL_MTU Up:%u Down:%u FEC K:%u N:%u SymbolSize:%u)\n", 
                 sidx, sess->cl_upstream_mtu, sess->cl_downstream_mtu, sess->cl_fec_k, sess->cl_fec_n, sess->cl_symbol_size);
        sess->handshake_done = true;
        sess->waiting_for_first_data = true; /* Trigger Flash Sync on next data burst */
        sess->status_sent     = false;
        sess->retx_len        = 0;
        sess->retx_seq        = 0;
        sess->upstream_len    = 0;
        sess->downstream_seq  = 0; 
        session_clear_burst(sess); 
        
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        int nfrags = 0;
        /* Echo the handshake back to the client as data to acknowledge sync.
         * Use the current sequence 'seq' for ACK to avoid over-ACKing seq+1. */
        if (build_txt_reply_multi(reply, &rlen, query_id, qname, (uint8_t*)&hs, sizeof(hs), sess->cl_downstream_mtu, 0, seq, sess->session_id, true, false, &nfrags, NULL) == 0) {
            LOG_DEBUG("Session %u: sending HANDSHAKE echo back to client (ack=%u, rlen=%zu, qid=%u)\n", 
                      sess->session_id, seq, rlen, query_id);
            send_udp_reply(src, reply, rlen);
        } else {
            LOG_WARN("Session %u: FAILED to build HANDSHAKE echo reply\n", sess->session_id);
        }
        sess->rx_next = seq + 1; /* Adopt client sequence exactly */
        session_handle_data(sidx, NULL, 0, seq, 1);
        return;
    }

    /* ── Multi-Symbol Processing Loop ──────────────────────────── */
    const uint8_t *cur_ptr = payload;
    size_t         cur_rem = payload_len;

    /* REJECT data packets if FEC not yet synced via Handshake */
    if (cur_rem > 0 && !is_poll && !is_sync && sess->cl_symbol_size == 0) {
        LOG_WARN("  [IN] sid=%u: DROPPED data pkt (seq=%u) because handshake is not yet complete\n", 
                 session_id, seq);
        goto send_reply;
    }

    while (cur_rem > 0) {
        const uint8_t *sym_data = NULL;
        size_t         sym_len  = 0;
        uint16_t       sym_esi  = 0;
        uint16_t       sym_total = 1;

        if (is_fec) {
            /* FEC Aggregation: query payload is [ESI(1)][Data(T)] ... */
            if (sess->cl_symbol_size == 0) {
                LOG_DEBUG("  [FEC] Error: cl_symbol_size is 0, cannot extract symbols. Dropping packet.\n");
                break;
            }
            if (cur_rem < (size_t)(1 + sess->cl_symbol_size)) {
                LOG_DEBUG("    [EXTR] ERROR: cur_rem=%zu too small for symbol (ESI+Size=%zu)\n", 
                          cur_rem, (size_t)(1 + sess->cl_symbol_size));
                break;
            }
            sym_esi = *cur_ptr++;
            sym_data = cur_ptr;
            sym_len = sess->cl_symbol_size;
            sym_total = sess->cl_fec_n;
            cur_ptr += sym_len;
            cur_rem -= (1 + sym_len);
        } else if (!is_poll && !is_sync) {
            /* Single raw/compressed packet */
            sym_data = cur_ptr;
            sym_len = cur_rem;
            cur_rem = 0;
        } else {
            break; /* Poll/Sync have no inner payload */
        }

        LOG_DEBUG("    [EXTR] burst=%u esi=%u l=%zu rem=%zu\n", (is_fec ? seq : 0), sym_esi, sym_len, cur_rem);

        /* ── 15. FEC Burst Reassembly ── */
        if (is_fec) {
            if (sym_total > 128 || sym_len > 1500) continue;

            uint16_t burst_id = seq; 
            fec_burst_t *slot = session_get_fec_burst(sess, burst_id);
            if (!slot) continue;

            if (slot->count_needed == 0) {
                slot->count_needed   = sym_total;
                slot->count_received = 0;
                slot->decoded        = false;
                slot->symbol_len     = sym_len;
                slot->has_oti        = false;
                
                slot->symbols = calloc(sym_total, sizeof(uint8_t *));
                if (!slot->symbols) { session_clear_fec_slot(slot); continue; }
                LOG_DEBUG("  [FEC] id=%04x new_burst n=%u\n", burst_id, sym_total);
            }

            if (slot->symbols && sym_esi < (uint16_t)slot->count_needed && !slot->symbols[sym_esi]) {
                slot->symbols[sym_esi] = malloc(sym_len);
                if (slot->symbols[sym_esi]) {
                    memcpy(slot->symbols[sym_esi], sym_data, sym_len);
                    slot->count_received++;
                    LOG_DEBUG("  [FEC] id=%04x added esi=%u count=%d/%d\n", 
                              burst_id, sym_esi, slot->count_received, (int)sess->cl_fec_k);
                }
            }

            int k_est = (int)sess->cl_fec_k;
            if (k_est < 1) k_est = 1;

            if (slot->count_received >= k_est) {
                if (!slot->decoded) {
                    slot->decoded = true;
                    fec_encoded_t fec = {0};
                    fec.symbols      = slot->symbols;
                    fec.symbol_len   = slot->symbol_len;
                    fec.total_count  = slot->count_needed;
                    fec.k_source     = (uint16_t)k_est;
                    fec.has_oti      = false;

                    codec_result_t fdec = codec_fec_decode_raw(&fec, (uint16_t)k_est);
                    if (!fdec.error && fdec.len > 0) {
                        const uint8_t *dec_in = fdec.data;
                        size_t         dec_len = fdec.len;
                        codec_result_t dret = {0};
                        if (is_encrypted) {
                            dret = codec_decrypt(fdec.data, fdec.len, g_cfg.psk);
                            if (!dret.error) { dec_in = dret.data; dec_len = dret.len; }
                        }
                        codec_result_t zdec = codec_decompress(dec_in, dec_len, 0);
                        if (!zdec.error) {
                            const uint8_t *p = zdec.data; size_t l = zdec.len;
                            if (l >= 4 && !is_encrypted) { p += 4; l -= 4; }
                            LOG_DEBUG("  [FEC] sid=%u burst=%u DECO_OK l=%zu\n", 
                                      session_id, burst_id, l);
                             /* Crucial fix: Increment rx_next by 1 burst, not by symbol count. 
                             * The client increments tx_next by 1 per burst. */
                            session_handle_data(sidx, p, l, burst_id, 1);
                             session_clear_fec_slot(slot); /* Clear slot immediately after processing */
                            codec_free_result(&zdec);
                        }
                        if (!dret.error && dret.data) codec_free_result(&dret);
                        codec_free_result(&fdec);
                    } else {
                        LOG_DEBUG("  [DE-AGG] Session %u: Burst %u decoding FAILED\n", session_id, burst_id);
                    }
                }
            }
        } else if (!is_poll && !is_sync) {
            /* Single Packet Data */
            const uint8_t *dec_ptr = sym_data; size_t dec_len = sym_len;
            codec_result_t dcret = {0}, zret = {0};
            if (is_encrypted) {
                dcret = codec_decrypt(sym_data, sym_len, g_cfg.psk);
                if (!dcret.error) { dec_ptr = dcret.data; dec_len = dcret.len; }
            }
            if (q_flags & CHUNK_FLAG_COMPRESSED) {
                zret = codec_decompress(dec_ptr, dec_len, 0);
                if (!zret.error) {
                    const uint8_t *p = zret.data; size_t l = zret.len;
                    if (!is_encrypted && l >= 4) { p += 4; l -= 4; }
                    session_handle_data(sidx, p, l, seq, 1);
                    codec_free_result(&zret);
                }
            } else {
                session_handle_data(sidx, dec_ptr, dec_len, seq, 1);
            }
            if (!dcret.error && dcret.data) codec_free_result(&dcret);
        }
    }

    if (is_poll) { session_handle_data(sidx, NULL, 0, seq, 1); }

    if (is_sync) {
        char swarm_text[65536] = {0};
        size_t slen = swarm_build_sync_text(swarm_text, sizeof(swarm_text));
        uint8_t reply[4096]; size_t rlen = sizeof(reply);
        uint16_t swarm_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, (const uint8_t *)swarm_text, slen, sess->cl_downstream_mtu, swarm_seq, sess->rx_next, sess->session_id, sess->handshake_done, false) == 0)
            send_udp_reply(src, reply, rlen);
        session_handle_data(sidx, NULL, 0, seq, 1);
        return;
    }

    if (has_ack) {
        extern void session_handle_ack(int sidx, uint16_t ack_seq);
        session_handle_ack(sidx, client_ack_seq);
    }

send_reply:;
    uint8_t reply[4096]; size_t rlen = sizeof(reply);
    uint16_t mtu = sess->cl_downstream_mtu;
    if (mtu < 16 || mtu > 4096) mtu = 512;
    uint16_t out_seq = sess->handshake_done ? sess->downstream_seq : 0;

    bool client_needs_retx = (has_ack && sess->handshake_done && client_ack_seq < out_seq);
    bool can_send_new     = (sess->upstream_len > 0 && (!has_ack || client_ack_seq >= out_seq));

    if (can_send_new) {
        int nfrags = 0; size_t sz = 0;
        /* Pass true if we have significantly more data than a single MTU-worth of fragments */
        bool hint_more = (sess->upstream_len > (size_t)mtu * 2); 
        if (build_txt_reply_multi(reply, &rlen, query_id, qname, sess->upstream_buf, sess->upstream_len, mtu, out_seq, sess->rx_next, sess->session_id, sess->handshake_done, hint_more, &nfrags, &sz) == 0) {
            if (sess->handshake_done && sz > 0) sess->downstream_seq += nfrags;
            if (sz <= sizeof(sess->retx_buf)) {
                memcpy(sess->retx_buf, sess->upstream_buf, sz);
                sess->retx_len = sz; sess->retx_seq = out_seq; sess->retx_count = nfrags;
            }
            if (sz > 0) {
                if (sz < sess->upstream_len) memmove(sess->upstream_buf, sess->upstream_buf + sz, sess->upstream_len - sz);
                sess->upstream_len -= sz;
            }
            send_udp_reply(src, reply, rlen);
        }
    } else if (client_needs_retx && sess->retx_len > 0) {
        if (client_ack_seq >= sess->retx_seq && client_ack_seq < sess->retx_seq + sess->retx_count) {
            int nfrags = 0;
            if (build_txt_reply_multi(reply, &rlen, query_id, qname, sess->retx_buf, sess->retx_len, mtu, sess->retx_seq, sess->rx_next, sess->session_id, true, false, &nfrags, NULL) == 0)
                send_udp_reply(src, reply, rlen);
        } else goto send_empty;
    } else {
send_empty:;
        int nfrags = 0;
        if (build_txt_reply_multi(reply, &rlen, query_id, qname, NULL, 0, mtu, out_seq, sess->rx_next, sess->session_id, false, false, &nfrags, NULL) == 0)
            send_udp_reply(src, reply, rlen);
    }
}
