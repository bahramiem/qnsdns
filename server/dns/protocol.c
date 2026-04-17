/**
 * @file server/dns/protocol.c
 * @brief DNS TXT Reply Building and Main UDP Receive Handler Implementation
 *
 * Extracted from server/main.c lines 596-1523.
 *
 * This file contains:
 *   - encode_downstream_data():      Base64/hex encode for TXT records
 *   - build_txt_reply_with_seq():    Build full DNS TXT response with seq header
 *   - send_udp_reply():              Fire-and-forget UDP reply helper
 *   - on_server_recv():              The main UDP dispatch loop (QNAME parse,
 *                                    FEC reassembly, upstream forwarding, reply)
 *
 * Dependency graph:
 *   on_server_recv → session_find_by_id / session_alloc_by_id (session.h)
 *                 → swarm_record_ip (swarm.h)
 *                 → codec_fec_decode, codec_decrypt, codec_decompress (codec.h)
 *                 → upstream_write_and_read, on_upstream_connect (session.h)
 *                 → build_txt_reply_with_seq → send_udp_reply
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

/**
 * @brief Encode @p in bytes into @p out for DNS TXT transport.
 *
 * Defaults to base64 for maximum compatibility with intermediate resolvers.
 * Hex encoding can be enabled via g_cfg.downstream_encoding=1 for debugging.
 */
static size_t encode_downstream_data(char *out, const uint8_t *in, size_t inlen) {
    if (g_cfg.downstream_encoding == 1)
        return hex_encode(out, in, inlen);
    return base64_encode(out, in, inlen);
}

/* ────────────────────────────────────────────── */
/*  Build DNS TXT Reply with Sequence Number      */
/* ────────────────────────────────────────────── */

#define MAX_FRAGMENTS 8
#define MAX_CHUNK_BINARY 191 /* Encodes to ~255 Base64 chars */

int build_txt_reply_multi(uint8_t *outbuf, size_t *outlen,
                          uint16_t query_id, const char *qname,
                          const uint8_t *data, size_t data_len,
                          uint16_t mtu, uint16_t start_seq,
                          uint8_t session_id, bool has_seq,
                          int *num_frags, size_t *bytes_consumed) {
    if (num_frags) *num_frags = 0;
    if (bytes_consumed) *bytes_consumed = 0;

    /* Step 1: Compute safe capacity with 75% safety margin and 128-byte hardware padding */
    size_t base_overhead = 12 + strlen(qname) + 6 + 11 + 20 + 32; /* +32 for safety */
    if (mtu < base_overhead + 128) mtu = base_overhead + 128;
    size_t safe_packet_budget = (mtu > base_overhead + 128) ? ((mtu - base_overhead - 128) * 75 / 100) : 64;
    
    LOG_DEBUG("[MTU] QName='%s' MTU=%u BaseOverhead=%zu Budget=%zu\n", qname, mtu, base_overhead, safe_packet_budget);

    /* Step 2: Split data into fragments (max 191 binary bytes each) */
    dns_answer_t ans[MAX_FRAGMENTS];
    
    /* Allocate Base64 storage on heap to avoid stack overflow */
    char **encoded_chunks = malloc(MAX_FRAGMENTS * sizeof(char *));
    for (int i = 0; i < MAX_FRAGMENTS; i++) encoded_chunks[i] = malloc(1024);

    uint16_t current_seq = start_seq;
    int frag_count = 0;
    size_t data_offset = 0;
    size_t current_packet_size = 0;

    /* Loop until data is exhausted, fragmentation limit is reached, or MTU is full */
    do {
        int chunk_data_len = (int)(data_len - data_offset);
        if (chunk_data_len > MAX_CHUNK_BINARY) chunk_data_len = MAX_CHUNK_BINARY;

        /* Check if this fragment's overhead + payload fits in budget */
        /* Each TXT record adds qname(len) + hdr(10) + txt_len(1) + payload chars */
        size_t frag_overhead = strlen(qname) + 11; 
        size_t b64_chars = (chunk_data_len == 0) ? 8 : ((chunk_data_len + 5) / 3 * 4); // conservative estimate
        if (current_packet_size + frag_overhead + b64_chars > safe_packet_budget && frag_count > 0)
            break;

        /* Prepare fragment header + payload */
        server_response_header_t hdr = {0};
        hdr.session_id = session_id;
        hdr.flags = 0;
        if (has_seq) hdr.flags |= RESP_FLAG_HAS_SEQ;
        hdr.seq = current_seq;

        uint8_t packet[1024];
        size_t packet_len = 0;
        memcpy(packet, &hdr, sizeof(hdr));
        packet_len += sizeof(hdr);

        if (chunk_data_len > 0 && data != NULL) {
            memcpy(packet + packet_len, data + data_offset, chunk_data_len);
            packet_len += chunk_data_len;
        }

        /* Encode fragment */
        size_t elen = encode_downstream_data(encoded_chunks[frag_count], packet, packet_len);
        if (elen >= 1024) elen = 1023;
        encoded_chunks[frag_count][elen] = '\0';

        /* Build DNS RR */
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

    /* Step 3: Global OPT record (EDNS0) */
    dns_answer_t edns = {0};
    edns.opt.name = (char *)".";
    edns.opt.type = RR_OPT;
    edns.opt.udp_payload = 4096;
    edns.opt.ttl = 0;
    edns.opt.version = 0;

    /* Step 4: Final Encode */
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
    
    /* Cleanup heap-allocated buffers */
    for (int i = 0; i < MAX_FRAGMENTS; i++) free(encoded_chunks[i]);
    free(encoded_chunks);

    if (rc != RCODE_OKAY) {
        LOG_ERR("[DNS_ENCODE] Failed to encode multi-fragment reply: rcode=%d\n", rc);
        return -1;
    }
    
    /* LOG_DEBUG("[DNS_ENCODE] Multi-fragment reply sent: id=%u RRs=%d total_bytes=%zu\n", query_id, frag_count, sz); */

    *outlen = sz;
    return 0;
}

/* Compatibility wrapper */
int build_txt_reply_with_seq(uint8_t *outbuf, size_t *outlen,
                             uint16_t query_id, const char *qname,
                             const uint8_t *data, size_t data_len,
                             uint16_t mtu, uint16_t seq,
                             uint8_t session_id, bool has_seq) {
    int nf = 0;
    size_t bc = 0;
    return build_txt_reply_multi(outbuf, outlen, query_id, qname, data, data_len,
                                 mtu, seq, session_id, has_seq, &nf, &bc);
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
    udp_reply_t *rep = malloc(sizeof(*rep));
    if (!rep) return;
    memcpy(&rep->dest, dest, sizeof(*dest));
    if (len > sizeof(rep->reply_buf)) {
        LOG_WARN("send_udp_reply: TRUNCATING %zu to %zu\n",
                 len, sizeof(rep->reply_buf));
        len = sizeof(rep->reply_buf);
    }
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

    /* 1. Record source IP in swarm */
    swarm_record_ip(src_ip);

    /* 2. Decode DNS query */
    dns_decoded_t decoded[DNS_DECODEBUF_4K];
    size_t decsz = sizeof(decoded);
    if (dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base,
                   (size_t)nread) != RCODE_OKAY) {
        g_stats.queries_lost++;
        return;
    }

    dns_query_t *qry = (dns_query_t *)decoded;
    if (qry->qdcount < 1) return;

    const char *qname    = qry->questions[0].name;
    uint16_t    query_id = qry->id;
    uint16_t    qtype    = qry->questions[0].type;

    /* 3. Handle non-TXT queries (e.g. Cloudflare QNAME minimization A probes) */
    if (qtype != RR_TXT) {
        LOG_DEBUG("Non-TXT query (qtype=%u) from %s for %s - sending NXDOMAIN\n",
                  qtype, src_ip, qname);
        uint8_t noerr[512];
        noerr[0] = query_id >> 8; noerr[1] = query_id & 0xFF;
        noerr[2] = 0x81; noerr[3] = 0x03; /* RD=1, RCODE=3 (NXDOMAIN) */
        noerr[4] = 0x00; noerr[5] = 0x01;
        noerr[6] = 0x00; noerr[7] = 0x00;
        noerr[8] = 0x00; noerr[9] = 0x00;
        noerr[10] = 0x00; noerr[11] = 0x00;
        size_t q_len = (size_t)nread > 12 ? (size_t)nread - 12 : 0;
        if (q_len > sizeof(noerr) - 12) q_len = sizeof(noerr) - 12;
        memcpy(noerr + 12, buf->base + 12, q_len);
        send_udp_reply(src, noerr, 12 + q_len);
        return;
    }

    /* 4. Parse QNAME — strip domain suffix to extract b32 payload */
    char tmp[DNSTUN_MAX_QNAME_LEN + 1];
    strncpy(tmp, qname, sizeof(tmp) - 1);

    char *parts[16] = {0};
    int   part_count = 0;
    char *tok = strtok(tmp, ".");
    while (tok && part_count < 16) { parts[part_count++] = tok; tok = strtok(NULL, "."); }

    int  domain_parts   = 2;
    bool is_mtu_probe   = false;
    bool is_crypto_probe = false;
    bool is_capability_probe = false;

    /* Try matching against configured domains */
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
            if (match) { domain_parts = dparts; break; }
        }
    }

    if (domain_parts > part_count - 1) domain_parts = part_count - 1;
    int payload_start_idx = part_count - domain_parts;

    /* Check for special probe formats in first label */
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

    /* 5. Handle MTU probe */
    if (is_mtu_probe && parts[0] != NULL) {
        int requested_mtu = atoi(parts[0] + 8);
        if (requested_mtu > 0 && requested_mtu <= 4096) {
            uint8_t *mtu_payload = malloc(4096);
            if (mtu_payload) {
                for (int i = 0; i < requested_mtu && i < 4096; i++)
                    mtu_payload[i] = (uint8_t)(rand() & 0xFF);
                
                uint8_t reply[5120]; size_t rlen = sizeof(reply);
                /* For MTU tests, use a high MTU cap (4096) to allow large responses */
                if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                             mtu_payload, (size_t)requested_mtu,
                                             4096, 0, 0, false) == 0)
                    send_udp_reply(src, reply, rlen);
                free(mtu_payload);
            }
        }
        return;
    }

    /* 6. Handle CRYPTO probe */
    if (is_crypto_probe && parts[0] != NULL) {
        const char *nonce_hex = parts[0] + 7;
        LOG_INFO("CRYPTO probe received: nonce=%s\n", nonce_hex);
        /* TODO: Implement challenge-response with HMAC signing */
        return;
    }

    /* 6b. Handle Capability probe (Phase 3) */
    if (is_capability_probe) {
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        const uint8_t resp[] = "OK";
        /* session_id=0 for internal probes */
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                     resp, sizeof(resp)-1, 512, 0, 0, false) == 0)
            send_udp_reply(src, reply, rlen);
        return;
    }

    /* 7. Reconstruct b32 payload (concatenate parts WITHOUT dots) */
    char b32_payload[512] = {0};
    for (int i = 0; i < payload_start_idx; i++)
        strncat(b32_payload, parts[i], sizeof(b32_payload) - strlen(b32_payload) - 1);

    /* LOG_DEBUG("QNAME parse: qname='%s' parts=%d domain_parts=%d payload='%s'\n",
             qname, part_count, domain_parts, b32_payload); */

    if (b32_payload[0] == '\0') {
        LOG_DEBUG("Empty payload after QNAME parse, ignoring\n");
        return;
    }

    /* 8. Base32 decode → raw bytes */
    uint8_t raw[512];
    size_t  b32_len = strlen(b32_payload);
    ssize_t rawlen  = base32_decode(raw, b32_payload, b32_len);
    if (rawlen < (ssize_t)sizeof(chunk_header_t)) {
        LOG_DEBUG("Base32 decode failed or too small (%zd bytes) from %s - payload='%s'\n", rawlen, src_ip, b32_payload);
        return;
    }

    /* LOG_DEBUG("decode: rawlen=%zd first_bytes=%02x%02x%02x%02x\n",
             rawlen, raw[0], raw[1], raw[2], raw[3]); */

    /* 9. Parse chunk header */
    chunk_header_t hdr;
    memcpy(&hdr, raw, sizeof(hdr));
    const uint8_t *payload     = raw + sizeof(hdr);
    size_t         payload_len = (size_t)(rawlen - (ssize_t)sizeof(hdr));

    /* LOG_DEBUG("header: session_id=%u flags=0x%02x seq=%u chunk_info=0x%08x\n",
             hdr.session_id, hdr.flags, hdr.seq, hdr.chunk_info); */

    bool    is_poll      = (hdr.flags & CHUNK_FLAG_POLL) != 0;
    bool    is_encrypted = (hdr.flags & CHUNK_FLAG_ENCRYPTED) != 0;
    bool    is_sync      = false;
    uint8_t session_id   = chunk_get_session_id(&hdr);
    uint16_t seq         = hdr.seq;
    uint8_t chunk_total  = chunk_get_total(hdr.chunk_info);
    uint8_t fec_k        = chunk_get_fec_k(hdr.chunk_info);

    /* 10. Parse capability header */
    uint16_t client_upstream_mtu = 220; /* default */
    uint16_t client_downstream_mtu = g_cfg.downstream_mtu;
    bool     has_capability_header = false;
    uint16_t client_ack_seq   = 0;
    bool     has_ack          = false;

    /* New clients send chunk_total = 0 for internal handshakes. Standalone data = 1. */
    if ((chunk_total == 0 || chunk_total == 1) && payload_len >= sizeof(capability_header_t)) {
        capability_header_t cap;
        memcpy(&cap, payload, sizeof(cap));
        if (cap.version == DNSTUN_VERSION) {
            client_upstream_mtu   = cap.upstream_mtu;
            client_downstream_mtu = cap.downstream_mtu;
            client_ack_seq         = cap.ack_seq;
            has_ack               = true;
            has_capability_header = true;
            
            /* STRIP header from data stream */
            payload     += sizeof(capability_header_t);
            payload_len -= sizeof(capability_header_t);
            
            LOG_DEBUG("Session %u: CapHdr stripped, ack=%u mtu=%u/%u\n",
                      session_id, client_ack_seq, client_upstream_mtu, client_downstream_mtu);
        }
    }

    /* 11. Detect special commands */
    if (payload_len >= 4 && memcmp(payload, "SYNC", 4) == 0)
        is_sync = true;

    bool is_handshake = (payload_len == 5 && payload[0] == DNSTUN_VERSION);
    bool is_debug     = (payload_len >= strlen(DNSTUN_DEBUG_PREFIX) &&
                         memcmp(payload, DNSTUN_DEBUG_PREFIX,
                                strlen(DNSTUN_DEBUG_PREFIX)) == 0);

    /* 12. Debug packet: echo back through normal pipeline */
    if (is_debug) {
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                     payload, payload_len, 512, 0, session_id, false) == 0)
            send_udp_reply(src, reply, rlen);
        return;
    }

    /* 13. Session lookup / alloc */
    int sidx = session_find_by_id(session_id);
    if (sidx < 0) {
        sidx = session_alloc_by_id(session_id);
        if (sidx < 0) { LOG_ERR("Session table full\n"); return; }
        LOG_INFO("New session: idx=%d sid=%u poll=%d sync=%d hs=%d paylen=%zu\n",
                 sidx, session_id, is_poll, is_sync, is_handshake, payload_len);
    }

    srv_session_t *sess = &g_sessions[sidx];
    sess->last_active   = time(NULL);
    sess->client_addr   = *src;
    if (has_capability_header) {
        sess->cl_upstream_mtu = client_upstream_mtu;
        sess->cl_downstream_mtu = client_downstream_mtu;
    }
    sess->cl_fec_k      = fec_k;

    /* 14. Handle handshake MTU signalling */
    if (is_handshake) {
        handshake_packet_t hs;
        memcpy(&hs, payload, sizeof(hs));
        if (hs.upstream_mtu >= 128 && hs.upstream_mtu <= 4096)
            sess->cl_upstream_mtu = hs.upstream_mtu;
        if (hs.downstream_mtu >= 128 && hs.downstream_mtu <= 4096)
            sess->cl_downstream_mtu = hs.downstream_mtu;
        if (!sess->handshake_done) {
            LOG_INFO("Session %d: Handshake complete (CL_MTU Up:%u Down:%u)\n",
                     sidx, sess->cl_upstream_mtu, sess->cl_downstream_mtu);
            sess->handshake_done = true;
        }
        /* Proceed to end-of-function to send DNS reply (ACK) */
        sess->status_sent     = false;
        sess->retx_len        = 0;
        sess->retx_seq        = 0;
        sess->upstream_len    = 0;
        LOG_INFO("Session %d: handshake done, downstream_seq=0\n", sidx);
        /* 15. Handshake query triggers its own response (NON-sequenced ACK) */
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        int nfrags = 0;
        LOG_DEBUG("Session %u: Sending handshake ACK (non-sequenced)\n", sess->session_id);
        if (build_txt_reply_multi(reply, &rlen, query_id, qname,
                                 NULL, 0, sess->cl_downstream_mtu, 0,
                                 sess->session_id, false, &nfrags, NULL) == 0) {
            send_udp_reply(src, reply, rlen);
        }
        return;
    }

    /* ── 15. FEC Burst Reassembly ────────────────────────────── */
    if (chunk_total > 1) {
        /* Guardrails: Reject implausible FEC headers to prevent corruption crashes */
        if (chunk_total > 128 || payload_len > 1500) {
            LOG_ERR("Session %u: Implausible FEC header ignored (total=%u len=%zu)\n", 
                    session_id, chunk_total, payload_len);
            goto skip_fec_processing;
        }

        uint16_t esi           = (uint16_t)(seq % (uint16_t)chunk_total);
        uint16_t burst_base    = (uint16_t)(seq - esi);
        bool     is_new_burst  = (sess->burst_count_needed == 0) ||
                                  (burst_base != sess->burst_seq_start) ||
                                  (chunk_total != (uint16_t)sess->burst_count_needed);

        if (is_new_burst) {
            if (sess->burst_symbols) {
                for (int i = 0; i < sess->burst_count_needed; i++)
                    free(sess->burst_symbols[i]);
                free(sess->burst_symbols);
                sess->burst_symbols = NULL;
            }
            sess->burst_seq_start    = burst_base;
            sess->burst_count_needed = chunk_total;
            sess->cl_fec_k           = fec_k;
            sess->burst_received     = 0;
            sess->burst_symbols      = calloc(chunk_total, sizeof(uint8_t *));
            sess->burst_symbol_len   = payload_len;
            sess->burst_oti_common   = hdr.oti_common;
            sess->burst_oti_scheme   = hdr.oti_scheme;
            sess->burst_has_oti      = (hdr.oti_common != 0 && hdr.oti_scheme != 0);
            sess->burst_decoded      = false;
        }

        if (esi < (uint16_t)sess->burst_count_needed &&
            sess->burst_symbols && !sess->burst_symbols[esi]) {
            sess->burst_symbols[esi] = malloc(payload_len);
            if (sess->burst_symbols[esi]) {
                memcpy(sess->burst_symbols[esi], payload, payload_len);
                sess->burst_received++;
            }
        }

        int k_est = (int)sess->cl_fec_k;
        if (k_est < 1) k_est = 1;
        if (k_est > sess->burst_count_needed) k_est = sess->burst_count_needed;

        if (sess->burst_received >= k_est) {
            if (sess->burst_decoded) {
                LOG_DEBUG("FEC burst seq=%u already decoded, discarding duplicate\n",
                          sess->burst_seq_start);
                goto skip_fec_processing;
            }
            sess->burst_decoded = true;

            fec_encoded_t fec = {0};
            fec.symbols      = sess->burst_symbols;
            fec.symbol_len   = sess->burst_symbol_len;
            fec.total_count  = sess->burst_count_needed;
            fec.k_source     = k_est;
            fec.oti_common   = sess->burst_oti_common;
            fec.oti_scheme   = sess->burst_oti_scheme;
            fec.has_oti      = sess->burst_has_oti;

            codec_result_t fdec = fec.has_oti
                ? codec_fec_decode_oti(&fec)
                : codec_fec_decode(&fec, sess->burst_symbol_len);

            if (!fdec.error) {
                const uint8_t *dec_in = fdec.data;
                size_t         dec_len = fdec.len;
                codec_result_t dret = {0};

                /* Decrypt (optional) */
                if (is_encrypted) {
                    dret = codec_decrypt(fdec.data, fdec.len, g_cfg.psk);
                    if (!dret.error) { dec_in = dret.data; dec_len = dret.len; }
                    else {
                        LOG_ERR("Decryption failed\n");
                        codec_free_result(&fdec);
                        goto skip_fec_processing;
                    }
                }

                /* Decompress */
                codec_result_t zdec = codec_decompress(dec_in, dec_len, 0);
                if (!zdec.error) {
                    /* Strip 4-byte anti-cache nonce */
                    const uint8_t *p = zdec.data;
                    size_t l = zdec.len;
                    if (l >= 4) { p += 4; l -= 4; }
                    else {
                        codec_free_result(&zdec);
                        goto skip_fec_processing;
                    }

                    /* Route to session data handler (handles connect or upstream write) */
                    LOG_DEBUG("Session %u: FEC decoded burst, len %zu\n", session_id, l);
                    session_handle_data(sidx, p, l);
                    codec_free_result(&zdec);
                } else {
                    codec_free_result(&zdec);
                }
                if (!dret.error && dret.data) codec_free_result(&dret);
                codec_free_result(&fdec);
                goto reset_burst;
            }

            codec_free_result(&fdec);
            goto skip_fec_processing;

reset_burst:
            for (int i = 0; i < sess->burst_count_needed; i++)
                free(sess->burst_symbols[i]);
            free(sess->burst_symbols);
            sess->burst_symbols       = NULL;
            sess->burst_count_needed  = 0;
            sess->burst_received      = 0;
            sess->burst_has_oti       = false;
            sess->burst_oti_common    = 0;
            sess->burst_oti_scheme    = 0;
        }
        /* 
         * CRITICAL: A FEC fragment must NOT proceed to the standalone non-FEC handler.
         * Early-exit to the reply phase to ACK the symbol.
         */
        goto send_reply;

skip_fec_processing:
        goto send_reply;
    } else if (is_poll) {
        /* empty poll — triggers downstream data push below */
    }

    /* 16. SYNC response */
    if (is_sync) {
        char swarm_text[65536] = {0};
        size_t slen = swarm_build_sync_text(swarm_text, sizeof(swarm_text));
        uint8_t reply[4096]; size_t rlen = sizeof(reply);
        uint16_t swarm_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                     (const uint8_t *)swarm_text, slen,
                                     sess->cl_downstream_mtu, swarm_seq,
                                     sess->session_id, sess->handshake_done) == 0)
            send_udp_reply(src, reply, rlen);
        return;
    }

    /* 17. Forward non-FEC payload to session handler */
    if (!is_poll && !is_sync && payload_len > 0) {
        const uint8_t *decode_ptr = payload;
        size_t decode_len = payload_len;

        /* Variables for cleanup - initialized to empty */
        codec_result_t dcret = {0};
        codec_result_t zret = {0};

        /* Decrypt if needed */
        if (is_encrypted) {
            dcret = codec_decrypt(payload, payload_len, g_cfg.psk);
            if (dcret.error || !dcret.data) {
                LOG_ERR("Session %d: decrypt failed for non-FEC packet\n", sidx);
                /* Still try to send empty reply to keep connection alive */
                goto send_reply;
            }
            decode_ptr = dcret.data;
            decode_len = dcret.len;
        }

        /* Decompress if needed */
        if (hdr.flags & CHUNK_FLAG_COMPRESSED) {
            zret = codec_decompress(decode_ptr, decode_len, 0);
            if (zret.error || !zret.data) {
                LOG_ERR("Session %d: decompress failed for non-FEC packet\n", sidx);
                if (is_encrypted && dcret.data) codec_free_result(&dcret);
                goto send_reply;
            }
            /* Strip 4-byte anti-cache nonce */
            const uint8_t *p = zret.data;
            size_t l = zret.len;
            if (l >= 4) { p += 4; l -= 4; } else { l = 0; }
            decode_ptr = p;
            decode_len = l;
            if (is_encrypted) codec_free_result(&dcret);
            /* Keep zret buffer allocated, session_handle_data doesn't retain it */
        } else {
            /* Not compressed: strip nonce only if encrypted was applied (already handled above) */
            /* In non-FEC non-compressed path, there's no 4-byte nonce added */
        }

        uint8_t b0 = decode_len > 0 ? decode_ptr[0] : 0;
        uint8_t b1 = decode_len > 1 ? decode_ptr[1] : 0;
        uint8_t b2 = decode_len > 2 ? decode_ptr[2] : 0;
        uint8_t b3 = decode_len > 3 ? decode_ptr[3] : 0;
        LOG_DEBUG("Session %d: non-FEC forward len=%zu flags=0x%02x enc=%d comp=%d first=%02x %02x %02x %02x\n",
                  sidx, decode_len, hdr.flags,
                  (hdr.flags & CHUNK_FLAG_ENCRYPTED) ? 1 : 0,
                  (hdr.flags & CHUNK_FLAG_COMPRESSED) ? 1 : 0,
                  b0, b1, b2, b3);
        session_handle_data(sidx, decode_ptr, decode_len);

        if (hdr.flags & CHUNK_FLAG_COMPRESSED) {
            codec_free_result(&zret);
        }

        /* Cleanup decrypt result if we decrypted */
        if (is_encrypted && dcret.data) {
            codec_free_result(&dcret);
        }
    }

    /* 18. Build and send reply to client */
send_reply:
    uint8_t reply[4096]; size_t rlen = sizeof(reply);
    uint16_t mtu = sess->cl_downstream_mtu;
    if (mtu < 16 || mtu > 4096) mtu = 512;

    uint16_t out_seq = sess->handshake_done ? sess->downstream_seq : 0;

    /* Logic: 
     * 1. If client is missing data (ack_seq < out_seq), check if we can retransmit.
     * 2. If client is caught up (ack_seq == out_seq), check if we have NEW data to send.
     * 3. Otherwise send empty ACK.
     */
    bool client_needs_retx = (has_ack && sess->handshake_done && client_ack_seq < out_seq);
    bool can_send_new     = (sess->upstream_len > 0 && (!has_ack || client_ack_seq >= out_seq));

    if (can_send_new) {
        int nfrags = 0;
        size_t sz = 0;

        if (build_txt_reply_multi(reply, &rlen, query_id, qname,
                                 sess->upstream_buf, sess->upstream_len,
                                 mtu, out_seq, sess->session_id, 
                                 sess->handshake_done, &nfrags, &sz) == 0) {
            
            LOG_DEBUG("Server sending burst: session=%u seq=%u..%u frags=%d bytes=%zu/%zu mtu=%u\n",
                    sess->session_id, out_seq, out_seq + nfrags - 1, nfrags, sz, sess->upstream_len, mtu);

            /* Increment sequence only if we actually consumed data */
            if (sess->handshake_done && sz > 0) sess->downstream_seq += nfrags;

            /* Update retransmission buffer with the entire binary burst */
            if (sz <= sizeof(sess->retx_buf)) {
                memcpy(sess->retx_buf, sess->upstream_buf, sz);
                sess->retx_len = sz;
                sess->retx_seq = out_seq;
                sess->retx_count = nfrags;
            }

            /* Consume from upstream buffer */
            if (sz > 0) {
                if (sz < sess->upstream_len) {
                    memmove(sess->upstream_buf, sess->upstream_buf + sz, sess->upstream_len - sz);
                }
                sess->upstream_len -= sz;
            }
            
            send_udp_reply(src, reply, rlen);
        }
    } else if (client_needs_retx && sess->retx_len > 0) {
        /* Check if requested seq is within our last burst */
        if (client_ack_seq >= sess->retx_seq && client_ack_seq < sess->retx_seq + sess->retx_count) {
            LOG_DEBUG("Server retransmitting burst on request: ack_seq=%u matching retx_seq=%u..%u\n",
                    client_ack_seq, sess->retx_seq, sess->retx_seq + sess->retx_count - 1);
            
            int nfrags = 0;
            if (build_txt_reply_multi(reply, &rlen, query_id, qname,
                                     sess->retx_buf, sess->retx_len,
                                     mtu, sess->retx_seq, sess->session_id, 
                                     true, &nfrags, NULL) == 0) {
                send_udp_reply(src, reply, rlen);
            }
        } else {
            LOG_WARN("Server cannot retransmit: client asked for %u but we only have %u..%u\n",
                     client_ack_seq, sess->retx_seq, sess->retx_seq + sess->retx_count - 1);
            goto send_empty;
        }
    } else {
send_empty:;
        int nfrags = 0;
        /* Empty data polls do NOT advance the sequence and are NOT sequenced */
        if (build_txt_reply_multi(reply, &rlen, query_id, qname,
                                 NULL, 0, mtu, out_seq,
                                 sess->session_id, false, &nfrags, NULL) == 0) {
            send_udp_reply(src, reply, rlen);
        }
    }
}
