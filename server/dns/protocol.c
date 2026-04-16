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

int build_txt_reply_with_seq(uint8_t *outbuf, size_t *outlen,
                             uint16_t query_id, const char *qname,
                             const uint8_t *data, size_t data_len,
                             uint16_t mtu, uint16_t seq,
                             uint8_t session_id, bool has_seq) {
    /* Step 1: Compute safe capacity to avoid truncation inside the MTU */
    size_t overhead     = 12 + strlen(qname) + 6 + 16 + 20;
    size_t safe_txt_len = (mtu > overhead + 64) ? (mtu - overhead) : 64;
    size_t max_packet   = (safe_txt_len * 3) / 4;
    size_t binary_mtu   = max_packet > 4 ? max_packet - 4 : 0;
    if (data_len > binary_mtu) data_len = binary_mtu;

    /* Step 2: Build response header */
    server_response_header_t hdr = {0};
    hdr.session_id = session_id;
    hdr.flags      = 0;
    if (has_seq) hdr.flags |= RESP_FLAG_HAS_SEQ;
    hdr.seq        = seq;

    /* Step 3: Pack header + payload */
    uint8_t packet[4096];
    size_t  packet_len = 0;
    memcpy(packet, &hdr, sizeof(hdr));
    packet_len += sizeof(hdr);
    if (data_len > 0 && data != NULL) {
        if (packet_len + data_len > sizeof(packet))
            data_len = sizeof(packet) - packet_len;
        memcpy(packet + packet_len, data, data_len);
        packet_len += data_len;
    }

    /* Step 4: Base64-encode the full packet for TXT record */
    char encoded[8192];
    size_t encoded_len = encode_downstream_data(encoded, packet, packet_len);
    if (encoded_len >= sizeof(encoded)) encoded_len = sizeof(encoded) - 1;
    encoded[encoded_len] = '\0';

    /* Step 5: Build DNS query+answer structures */
    dns_question_t q = {0};
    q.name  = qname;
    q.type  = RR_TXT;
    q.class = CLASS_IN;

    dns_answer_t ans = {0};
    ans.txt.name  = qname;
    ans.txt.type  = RR_TXT;
    ans.txt.class = CLASS_IN;
    ans.txt.ttl   = 0;
    ans.txt.len   = (uint16_t)encoded_len;
    ans.txt.text  = encoded;

    dns_query_t resp = {0};
    resp.id       = query_id;
    resp.query    = false;
    resp.rd       = true;
    resp.ra       = true;
    resp.qdcount  = 1;
    resp.ancount  = 1;
    resp.questions = &q;
    resp.answers   = &ans;

    size_t sz = *outlen;
    dns_rcode_t rc = dns_encode((dns_packet_t *)outbuf, &sz, &resp);
    if (rc != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
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
            uint8_t mtu_payload[4096];
            for (int i = 0; i < requested_mtu && i < (int)sizeof(mtu_payload); i++)
                mtu_payload[i] = (uint8_t)(rand() & 0xFF);
            uint8_t reply[5120]; size_t rlen = sizeof(reply);
            if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                         mtu_payload, requested_mtu,
                                         512, 0, 0, false) == 0)
                send_udp_reply(src, reply, rlen);
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

    LOG_DEBUG("QNAME parse: qname='%s' parts=%d domain_parts=%d payload='%s'\n",
             qname, part_count, domain_parts, b32_payload);

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

    LOG_DEBUG("decode: rawlen=%zd first_bytes=%02x%02x%02x%02x\n",
             rawlen, raw[0], raw[1], raw[2], raw[3]);

    /* 9. Parse chunk header */
    chunk_header_t hdr;
    memcpy(&hdr, raw, sizeof(hdr));
    const uint8_t *payload     = raw + sizeof(hdr);
    size_t         payload_len = (size_t)(rawlen - (ssize_t)sizeof(hdr));

    LOG_DEBUG("header: session_id=%u flags=0x%02x seq=%u chunk_info=0x%08x\n",
             hdr.session_id, hdr.flags, hdr.seq, hdr.chunk_info);

    bool    is_poll      = (hdr.flags & CHUNK_FLAG_POLL) != 0;
    bool    is_encrypted = (hdr.flags & CHUNK_FLAG_ENCRYPTED) != 0;
    bool    is_sync      = false;
    uint8_t session_id   = chunk_get_session_id(&hdr);
    uint16_t seq         = hdr.seq;
    uint8_t chunk_total  = chunk_get_total(hdr.chunk_info);
    uint8_t fec_k        = chunk_get_fec_k(hdr.chunk_info);

    /* 10. Parse capability header (non-FEC packets only) */
    uint16_t client_upstream_mtu = 220; /* default */
    uint16_t client_downstream_mtu = g_cfg.downstream_mtu;
    bool     has_capability_header = false;
    if (chunk_total == 1 && payload_len >= sizeof(capability_header_t)) {
        capability_header_t cap;
        memcpy(&cap, payload, sizeof(cap));
        if (cap.version == DNSTUN_VERSION) {
            client_upstream_mtu = cap.upstream_mtu;
            client_downstream_mtu = cap.downstream_mtu;
            payload     += sizeof(capability_header_t);
            payload_len -= sizeof(capability_header_t);
            has_capability_header = true;
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
    }

    /* ── 15. FEC Burst Reassembly ────────────────────────────── */
    if (chunk_total > 1) {
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
skip_fec_processing:; /* empty for label */
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
    if (!is_poll && !is_sync && payload_len > 0)
        session_handle_data(sidx, payload, payload_len);

    /* 18. Build and send reply to client */
    uint8_t reply[4096]; size_t rlen = sizeof(reply);
    uint16_t mtu = sess->cl_downstream_mtu;
    if (mtu < 16 || mtu > 4096) mtu = 512;

    if (sess->upstream_len > 0) {
        size_t overhead     = 12 + strlen(qname) + 6 + 16 + 20;
        size_t safe_txt_len = (mtu > overhead + 64) ? (mtu - overhead) : 64;
        size_t binary_mtu   = ((safe_txt_len * 3) / 4) - 4;
        size_t sz = sess->upstream_len;
        if (sz > binary_mtu) sz = binary_mtu;

        LOG_DEBUG("Server sending: upstream_len=%zu sz=%zu mtu=%u\n",
                sess->upstream_len, sz, mtu);

        uint16_t out_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                     sess->upstream_buf, sz, mtu,
                                     out_seq, sess->session_id, sess->handshake_done) == 0) {
            if (sz <= sizeof(sess->retx_buf)) {
                memcpy(sess->retx_buf, sess->upstream_buf, sz);
                sess->retx_len = sz;
                sess->retx_seq = out_seq;
            }
            memmove(sess->upstream_buf, sess->upstream_buf + sz, sess->upstream_len - sz);
            sess->upstream_len -= sz;
            send_udp_reply(src, reply, rlen);
        }
    } else if (sess->retx_len > 0) {
        LOG_DEBUG("Server retransmitting seq=%u len=%zu\n",
                sess->retx_seq, sess->retx_len);
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                     sess->retx_buf, sess->retx_len,
                                     mtu, sess->retx_seq, sess->session_id, true) == 0)
            send_udp_reply(src, reply, rlen);
    } else {
        uint16_t out_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        LOG_DEBUG("Server empty reply: session=%u seq=%u\n",
                sess->session_id, out_seq);
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname,
                                     NULL, 0, mtu, out_seq,
                                     sess->session_id, sess->handshake_done) == 0)
            send_udp_reply(src, reply, rlen);
    }
}
