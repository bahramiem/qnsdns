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

/* ────────────────────────────────────────────── */
/*  Build DNS TXT Reply with Sequence Number      */
/* ────────────────────────────────────────────── */

#define MAX_FRAGMENTS 8
#define MAX_CHUNK_BINARY 191 

int build_txt_reply_multi(uint8_t *outbuf, size_t *outlen,
                          uint16_t query_id, const char *qname,
                          const uint8_t *data, size_t data_len,
                          uint16_t mtu, uint16_t start_seq,
                          uint8_t session_id, bool has_seq,
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
        hdr.seq = current_seq;

        uint8_t packet[1024];
        size_t packet_len = 0;
        memcpy(packet, &hdr, sizeof(hdr));
        packet_len += sizeof(hdr);

        if (chunk_data_len > 0 && data != NULL) {
            memcpy(packet + packet_len, data + data_offset, chunk_data_len);
            packet_len += chunk_data_len;
        }

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
            if (is_mine) LOG_DEBUG("Non-TXT query (qtype=%u) for matches domain - sending NXDOMAIN\n", qtype);
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
                if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, mtu_payload, (size_t)requested_mtu, 4096, 0, 0, false) == 0)
                    send_udp_reply(src, reply, rlen);
                free(mtu_payload);
            }
        }
        return;
    }

    if (is_capability_probe) {
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        const uint8_t resp[] = "OK";
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, resp, sizeof(resp)-1, 512, 0, 0, false) == 0)
            send_udp_reply(src, reply, rlen);
        return;
    }

    char b32_payload[512] = {0};
    for (int i = 0; i < payload_start_idx; i++)
        strncat(b32_payload, parts[i], sizeof(b32_payload) - strlen(b32_payload) - 1);

    if (b32_payload[0] == '\0') return;

    uint8_t raw[512];
    size_t  b32_len = strlen(b32_payload);
    ssize_t rawlen  = base32_decode(raw, b32_payload, b32_len);
    if (rawlen < (ssize_t)sizeof(chunk_header_t)) return;

    chunk_header_t hdr;
    memcpy(&hdr, raw, sizeof(hdr));
    const uint8_t *payload     = raw + sizeof(hdr);
    size_t         payload_len = (size_t)(rawlen - (ssize_t)sizeof(hdr));

    bool    is_poll      = (hdr.flags & CHUNK_FLAG_POLL) != 0;
    bool    is_encrypted = (hdr.flags & CHUNK_FLAG_ENCRYPTED) != 0;
    bool    is_sync      = false;
    uint8_t session_id   = chunk_get_session_id(&hdr);
    uint16_t seq         = hdr.seq;
    
    LOG_DEBUG("Incoming Query: id=%u sess=%u seq=%u flags=0x%02x rawlen=%zd\n", 
              query_id, session_id, seq, hdr.flags, rawlen);
    
    uint16_t chunk_total = chunk_get_total(hdr.chunk_info);
    if (chunk_total == 0) chunk_total = 1;
    uint16_t esi         = chunk_get_esi(hdr.chunk_info);
    uint8_t fec_k        = chunk_get_fec_k(hdr.chunk_info);

    /* LOG_DEBUG("DNS Query: id=%u sess=%u seq=%u total=%u esi=%u\n", query_id, session_id, seq, chunk_total, esi); */

    uint16_t client_upstream_mtu = 220;
    uint16_t client_downstream_mtu = g_cfg.downstream_mtu;
    uint16_t client_ack_seq   = 0;
    bool     has_ack          = false;
    bool     has_capability_header = false;

    if ((chunk_total == 0 || chunk_total == 1) && payload_len >= sizeof(capability_header_t)) {
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
            LOG_DEBUG("Sess %u: Cap header found (UpMTU:%u DownMTU:%u Ack:%u)\n", 
                      session_id, client_upstream_mtu, client_downstream_mtu, client_ack_seq);
        }
    }

    if (payload_len >= 4 && memcmp(payload, "SYNC", 4) == 0) is_sync = true;
    bool is_handshake = (payload_len == 5 && payload[0] == DNSTUN_VERSION);

    int sidx = session_find_by_id(session_id);
    if (sidx < 0) {
        sidx = session_alloc_by_id(session_id);
        if (sidx < 0) return;
        LOG_INFO("New session id=%u\n", session_id);
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
        memcpy(&hs, payload, sizeof(hs));
        if (hs.upstream_mtu >= 128) sess->cl_upstream_mtu = hs.upstream_mtu;
        if (hs.downstream_mtu >= 128) sess->cl_downstream_mtu = hs.downstream_mtu;
        
        LOG_INFO("Session %d: Handshake complete (CL_MTU Up:%u Down:%u)\n", sidx, sess->cl_upstream_mtu, sess->cl_downstream_mtu);
        sess->handshake_done = true;
        sess->status_sent     = false;
        sess->retx_len        = 0;
        sess->retx_seq        = 0;
        sess->upstream_len    = 0;
        sess->downstream_seq  = 0; 
        session_clear_burst(sess); 
        
        uint8_t reply[512]; size_t rlen = sizeof(reply);
        int nfrags = 0;
        if (build_txt_reply_multi(reply, &rlen, query_id, qname, NULL, 0, sess->cl_downstream_mtu, 0, sess->session_id, false, &nfrags, NULL) == 0)
            send_udp_reply(src, reply, rlen);
            
        session_handle_data(sidx, NULL, 0, seq, 1);
        return;
    }

    /* ── 15. FEC Burst Reassembly ────────────────────────────── */
    if (chunk_total > 1) {
        if (chunk_total > 128 || payload_len > 1500) {
            LOG_ERR("Session %u: Implausible FEC header ignored (total=%u len=%zu)\n", session_id, chunk_total, payload_len);
            goto skip_fec_processing;
        }

        uint16_t burst_id = seq; 
        fec_burst_t *slot = session_get_fec_burst(sess, burst_id);
        if (!slot) goto skip_fec_processing;

        if (slot->count_needed == 0) {
            slot->count_needed   = chunk_total;
            slot->count_received = 0;
            slot->decoded        = false;
            slot->symbol_len     = payload_len;
            slot->oti_common     = hdr.oti_common;
            slot->oti_scheme     = hdr.oti_scheme;
            slot->has_oti        = (hdr.oti_common != 0 && hdr.oti_scheme != 0);
            
            slot->symbols = calloc(chunk_total, sizeof(uint8_t *));
            if (!slot->symbols) { session_clear_fec_slot(slot); goto skip_fec_processing; }
            LOG_DEBUG("Session %u: New concurrent FEC burst (id=%u total=%u)\n", session_id, burst_id, chunk_total);
        }

        /* Store the symbol if we haven't received this ESI yet */
        if (slot->symbols && esi < (uint16_t)slot->count_needed && !slot->symbols[esi]) {
            slot->symbols[esi] = malloc(payload_len);
            if (slot->symbols[esi]) {
                memcpy(slot->symbols[esi], payload, payload_len);
                slot->count_received++;
                /* LOG_DEBUG("Session %u: Burst %u ESI %u received (%d symbols so far)\n", 
                         session_id, burst_id, esi, slot->count_received); */
            }
        }

        int k_est = (int)fec_k;
        if (k_est < 1) k_est = 1;
        if (k_est > slot->count_needed) k_est = slot->count_needed;

        if (slot->count_received >= k_est) {
            if (slot->decoded) goto skip_fec_processing;
            slot->decoded = true;

            fec_encoded_t fec = {0};
            fec.symbols      = slot->symbols;
            fec.symbol_len   = slot->symbol_len;
            fec.total_count  = slot->count_needed;
            fec.k_source     = k_est;
            fec.oti_common   = slot->oti_common;
            fec.oti_scheme   = slot->oti_scheme;
            fec.has_oti      = slot->has_oti;

            codec_result_t fdec = fec.has_oti ? codec_fec_decode_oti(&fec) : codec_fec_decode(&fec, slot->symbol_len);
            if (!fdec.error && fdec.len > 0) {
                const uint8_t *dec_in = fdec.data;
                size_t         dec_len = fdec.len;
                codec_result_t dret = {0};
                if (is_encrypted) {
                    dret = codec_decrypt(fdec.data, fdec.len, g_cfg.psk);
                    if (!dret.error) { dec_in = dret.data; dec_len = dret.len; }
                    else { codec_free_result(&fdec); session_clear_fec_slot(slot); return; }
                }

                codec_result_t zdec = codec_decompress(dec_in, dec_len, 0);
                if (!zdec.error) {
                    const uint8_t *p = zdec.data; size_t l = zdec.len;
                    if (l >= 4) { p += 4; l -= 4; }
                    else {
                        codec_free_result(&zdec);
                        if (!dret.error && dret.data) codec_free_result(&dret);
                        codec_free_result(&fdec);
                        session_clear_fec_slot(slot);
                        return;
                    }
                    LOG_DEBUG("Session %u: FEC burst %u decoded, len %zu\n", session_id, burst_id, l);
                    session_handle_data(sidx, p, l, burst_id, slot->count_needed);
                    codec_free_result(&zdec);
                }
                if (!dret.error && dret.data) codec_free_result(&dret);
                codec_free_result(&fdec);
            }
        }
        goto send_reply;

skip_fec_processing:
        goto send_reply;
    }

    if (is_poll) { session_handle_data(sidx, NULL, 0, seq, 1); }

    if (is_sync) {
        char swarm_text[65536] = {0};
        size_t slen = swarm_build_sync_text(swarm_text, sizeof(swarm_text));
        uint8_t reply[4096]; size_t rlen = sizeof(reply);
        uint16_t swarm_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, (const uint8_t *)swarm_text, slen, sess->cl_downstream_mtu, swarm_seq, sess->session_id, sess->handshake_done) == 0)
            send_udp_reply(src, reply, rlen);
        session_handle_data(sidx, NULL, 0, seq, 1);
        return;
    }

    if (!is_poll && !is_sync && payload_len > 0) {
        const uint8_t *dec_ptr = payload; size_t dec_len = payload_len;
        codec_result_t dcret = {0}, zret = {0};
        if (is_encrypted) {
            dcret = codec_decrypt(payload, payload_len, g_cfg.psk);
            if (dcret.error) goto send_reply;
            dec_ptr = dcret.data; dec_len = dcret.len;
        }
        if (hdr.flags & CHUNK_FLAG_COMPRESSED) {
            zret = codec_decompress(dec_ptr, dec_len, 0);
            if (zret.error) { if (is_encrypted) codec_free_result(&dcret); goto send_reply; }
            const uint8_t *p = zret.data; size_t l = zret.len;
            if (l >= 4) { p += 4; l -= 4; } else l = 0;
            dec_ptr = p; dec_len = l;
        }
        session_handle_data(sidx, dec_ptr, dec_len, seq, 1);
        if (hdr.flags & CHUNK_FLAG_COMPRESSED) codec_free_result(&zret);
        if (is_encrypted) codec_free_result(&dcret);
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
        if (build_txt_reply_multi(reply, &rlen, query_id, qname, sess->upstream_buf, sess->upstream_len, mtu, out_seq, sess->session_id, sess->handshake_done, &nfrags, &sz) == 0) {
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
            if (build_txt_reply_multi(reply, &rlen, query_id, qname, sess->retx_buf, sess->retx_len, mtu, sess->retx_seq, sess->session_id, true, &nfrags, NULL) == 0)
                send_udp_reply(src, reply, rlen);
        } else goto send_empty;
    } else {
send_empty:;
        int nfrags = 0;
        if (build_txt_reply_multi(reply, &rlen, query_id, qname, NULL, 0, mtu, out_seq, sess->session_id, false, &nfrags, NULL) == 0)
            send_udp_reply(src, reply, rlen);
    }
}
