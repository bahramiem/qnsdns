/**
 * @file server/dns_handler.c
 * @brief Implementation of DNS protocol handling and FEC reassembly.
 */

#include "dns_handler.h"
#include "session.h"
#include "swarm.h"
#include "server_common.h"
#include "../shared/base32.h"
#include "../shared/codec.h"
#include "../shared/types.h"
#include "../SPCDNS/dns.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Forward Declarations */
static int build_txt_reply(uint8_t *out, size_t *outlen, uint16_t qid, const char *qname,
                          const uint8_t *data, size_t dlen, uint16_t mtu, uint16_t seq,
                          uint8_t sid, bool has_seq);
static void send_udp_reply_direct(uv_udp_t *h, const struct sockaddr_in *dest, 
                                 const uint8_t *data, size_t len);

/* ── DNS Receiving logic ──────────────────────────────────────────────────── */

static void on_udp_send_done(uv_udp_send_t *req, int status) {
    if (req->data) free(req->data);
    free(req);
    (void)status;
}

static void send_udp_reply_direct(uv_udp_t *h, const struct sockaddr_in *dest, 
                                 const uint8_t *data, size_t len) {
    if (!h || !dest || !data || len == 0) return;
    
    uv_udp_send_t *req = malloc(sizeof(uv_udp_send_t));
    if (!req) return;
    
    uint8_t *copy = malloc(len);
    if (!copy) { free(req); return; }
    memcpy(copy, data, len);
    req->data = copy;
    
    uv_buf_t buf = uv_buf_init((char *)copy, (unsigned int)len);
    if (uv_udp_send(req, h, &buf, 1, (const struct sockaddr *)dest, on_udp_send_done) != 0) {
        free(copy);
        free(req);
    }
    
    if (g_server_stats) g_server_stats->queries_sent++;
}

/**
 * @brief Decode downstream data using Base64 (DNS compatible).
 */
static size_t encode_payload(char *out, const uint8_t *in, size_t inlen) {
    return base64_encode(out, in, inlen);
}

static int build_txt_reply(uint8_t *out, size_t *outlen, uint16_t qid, const char *qname,
                          const uint8_t *data, size_t dlen, uint16_t mtu, uint16_t seq,
                          uint8_t sid, bool has_seq) {
    /* Safe capacity check for TXT records */
    size_t overhead = 12 + strlen(qname) + 6 + 16 + 20;
    size_t safe_txt = (mtu > overhead + 64) ? (mtu - overhead) : 64;
    size_t max_binary = (safe_txt * 3) / 4;
    size_t bin_mtu = max_binary > 4 ? max_binary - 4 : 0;
    
    if (dlen > bin_mtu) dlen = bin_mtu;

    /* Build Tunnel Header */
    server_response_header_t hdr = {0};
    hdr.session_id = sid;
    hdr.flags = 0; /* Base64 encoding */
    if (has_seq) hdr.flags |= RESP_FLAG_HAS_SEQ;
    hdr.seq = seq;

    /* Build Combined Packet */
    uint8_t packet[4096];
    memcpy(packet, &hdr, sizeof(hdr));
    size_t plen = sizeof(hdr);
    if (data && dlen > 0) {
        memcpy(packet + plen, data, dlen);
        plen += dlen;
    }

    /* Encode to Base32/64 for TXT */
    char encoded[4096];
    size_t elen = encode_payload(encoded, packet, plen);
    encoded[elen] = '\0';

    /* Build DNS Packet Structures */
    dns_question_t q = { .name = qname, .type = RR_TXT, .class = CLASS_IN };
    dns_answer_t ans = {
        .txt.name = qname, .txt.type = RR_TXT, .txt.class = CLASS_IN,
        .txt.ttl = 0, .txt.len = (uint16_t)elen, .txt.text = encoded
    };
    dns_query_t resp = {
        .id = qid, .query = false, .rd = true, .ra = true,
        .qdcount = 1, .ancount = 1, .questions = &q, .answers = &ans
    };

    size_t sz = *outlen;
    if (dns_encode((dns_packet_t*)out, &sz, &resp) != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

void dns_handler_on_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned int flags) {
    if (nread <= 0 || !addr) return;
    const struct sockaddr_in *src = (const struct sockaddr_in *)addr;
    char src_ip[46];
    uv_ip4_name(src, src_ip, sizeof(src_ip));

    if (g_server_stats) g_server_stats->queries_recv++;
    swarm_record_ip(src_ip);

    /* 1. Decode DNS Structure */
    dns_decoded_t decoded[DNS_DECODEBUF_4K];
    size_t decsz = sizeof(decoded);
    if (dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base, (size_t)nread) != RCODE_OKAY) {
        if (g_server_stats) g_server_stats->queries_lost++;
        return;
    }

    dns_query_t *qry = (dns_query_t *)decoded;
    if (qry->qdcount < 1) return;
    const char *qname = qry->questions[0].name;
    uint16_t query_id = qry->id;
    uint16_t qtype    = qry->questions[0].type;

    /* 2. Handle Non-TXT Probes (e.g. Cloudflare A probes) */
    if (qtype != RR_TXT) {
        LOG_DEBUG("Non-TXT query (%u) for %s - responding NOERROR empty\n", qtype, qname);
        uint8_t noerr[512];
        memset(noerr, 0, 12);
        noerr[0] = query_id >> 8; noerr[1] = query_id & 0xFF;
        noerr[2] = 0x84; noerr[4] = 0x00; noerr[5] = 0x01; /* QR=1 QD=1 */
        size_t q_len = (size_t)nread > 12 ? (size_t)nread - 12 : 0;
        if (q_len > 400) q_len = 400;
        memcpy(noerr + 12, buf->base + 12, q_len);
        send_udp_reply_direct(h, src, noerr, 12 + q_len);
        return;
    }

    /* 3. Parse QNAME and Extract Payload */
    char tmp_qname[512];
    strncpy(tmp_qname, qname, sizeof(tmp_qname)-1);
    char *parts[16] = {0};
    int pcount = 0;
    char *tok = strtok(tmp_qname, ".");
    while (tok && pcount < 16) { parts[pcount++] = tok; tok = strtok(NULL, "."); }

    /* Identify Domain Suffix (Restored from stable version) */
    int dparts = 2; /* Default */
    if (g_server_cfg && g_server_cfg->domain_count > 0) {
        const char *domain = g_server_cfg->domains[0];
        char dtmp[256]; strncpy(dtmp, domain, sizeof(dtmp)-1);
        char *dtok = strtok(dtmp, ".");
        int cur_d = 0;
        while (dtok) { cur_d++; dtok = strtok(NULL, "."); }
        if (cur_d > 0) dparts = cur_d;
    }
    
    int payload_labels = pcount - dparts;
    if (payload_labels < 1) return;

    /* Reconstruct Base32 Payload (ignoring dots) */
    char b32[512] = {0};
    for (int i = 0; i < payload_labels; i++) {
        strncat(b32, parts[i], sizeof(b32) - strlen(b32) - 1);
    }

    /* 4. Base32 Decode to Chunk Header and Payload */
    uint8_t raw[1024];
    ssize_t rawlen = base32_decode(raw, b32, (size_t)strlen(b32));
    if (rawlen < (ssize_t)sizeof(chunk_header_t)) return;

    chunk_header_t *hdr = (chunk_header_t *)raw;
    uint8_t sid      = chunk_get_session_id(hdr);
    uint8_t total    = chunk_get_total(hdr->chunk_info);
    uint8_t k_source = chunk_get_fec_k(hdr->chunk_info);
    uint16_t seq    = hdr->seq;
    bool is_poll    = (hdr->flags & CHUNK_FLAG_POLL) != 0;
    
    const uint8_t *data = raw + sizeof(chunk_header_t);
    size_t dlen = (size_t)rawlen - sizeof(chunk_header_t);

    /* 5. Session Linkage */
    srv_session_t *sess = session_find_by_id(sid);
    if (!sess) sess = session_alloc_by_id(sid);
    if (!sess) { LOG_ERR("Sess table full for ID %u\n", sid); return; }
    
    sess->last_active = time(NULL);
    sess->client_addr = *src;

    /* 6. Protocol Logic (FEC Reassembly or Direct Forward) */
    if (total > 1) {
        /* FEC Multi-symbol Burst Handle */
        uint16_t esi = (uint16_t)(seq % total);
        uint16_t base = (uint16_t)(seq - esi);
        
        bool is_new = (sess->burst_count_needed == 0) || (base != sess->burst_seq_start);
        if (is_new) {
            /* Cleanup and Start New Burst */
            if (sess->burst_symbols) { 
                for (int m=0; m<sess->burst_count_needed; m++) if (sess->burst_symbols[m]) free(sess->burst_symbols[m]);
                free(sess->burst_symbols);
            }
            sess->burst_seq_start = base;
            sess->burst_count_needed = total;
            sess->cl_fec_k = k_source;
            sess->burst_received = 0;
            sess->burst_symbols = calloc(total, sizeof(uint8_t *));
            sess->burst_symbol_len = dlen;
            sess->burst_oti_common = hdr->oti_common;
            sess->burst_oti_scheme = hdr->oti_scheme;
            sess->burst_has_oti = (hdr->oti_common != 0);
            sess->burst_decoded = false;
        }

        if (esi < total && sess->burst_symbols && !sess->burst_symbols[esi]) {
            sess->burst_symbols[esi] = malloc(dlen);
            if (sess->burst_symbols[esi]) {
                memcpy(sess->burst_symbols[esi], data, dlen);
                sess->burst_received++;
            }
        }

        /* Trigger Decoding if K symbols reached */
        if (sess->burst_received >= k_source && !sess->burst_decoded) {
            sess->burst_decoded = true;
            fec_encoded_t fenc = {
                .symbols = sess->burst_symbols, .symbol_len = dlen,
                .total_count = total, .k_source = k_source,
                .oti_common = sess->burst_oti_common, .oti_scheme = sess->burst_oti_scheme,
                .has_oti = sess->burst_has_oti
            };
            
            codec_result_t fdec = codec_fec_decode_oti(&fenc);
            if (!fdec.error) {
                /* Decompress (skip 4-byte nonce automatically encoded by client) */
                codec_result_t zdec = codec_decompress(fdec.data, fdec.len, 0);
                if (!zdec.error && zdec.len > 4) {
                    const uint8_t *p = zdec.data + 4; 
                    size_t plen = zdec.len - 4;
                    
                    if (!sess->tcp_connected && plen >= 10 && p[0] == 0x05 && p[1] == 0x01) {
                        /* RESTORATION: Parse SOCKS5 Target from real payload */
                        char target[256] = {0}; uint16_t tport = 0;
                        uint8_t atype = p[3];
                        if (atype == 0x01) { /* IPv4 */
                            sprintf(target, "%d.%d.%d.%d", p[4], p[5], p[6], p[7]);
                            tport = (uint16_t)((p[8] << 8) | p[9]);
                        } else if (atype == 0x03) { /* Domain */
                            uint8_t hlen = p[4];
                            if (hlen < 255 && hlen + 7 <= plen) {
                                memcpy(target, p + 5, hlen);
                                tport = (uint16_t)((p[5 + hlen] << 8) | p[6 + hlen]);
                            }
                        }
                        if (target[0]) {
                            LOG_INFO("SOCKS5 CONNECT: %s:%d (ID %u)\n", target, tport, sid);
                            session_upstream_connect(sess, target, tport, NULL, 0);
                            /* Prepend the mandatory SOCKS5 Success status byte to the response stream */
                            uint8_t status[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0,0,0};
                            session_upstream_write_to_buffer(sess, status, 10);
                        }
                    } else if (sess->tcp_connected) {
                         session_upstream_write(sess, p, plen);
                    }
                }
                codec_free_result(&zdec);
            }
            codec_free_result(&fdec);
        }
    } else if (!is_poll && dlen > 0) {
        /* Handshake or Direct Tunnel (non-FEC) */
        if (dlen >= 3 && data[0] == DNSTUN_VERSION) {
            sess->handshake_done = true;
            sess->cl_downstream_mtu = (uint16_t)((data[1] << 8) | data[2]);
            sess->downstream_seq = 0; 
            sess->status_sent = false;
        } else if (sess->tcp_connected) {
            session_upstream_write(sess, data, dlen);
        }
    }

    /* 7. Build and Send Reply (Stuff with Upstream Data) */
    uint8_t reply[4096];
    size_t rlen = sizeof(reply);
    uint16_t mtu = sess->cl_downstream_mtu > 0 ? sess->cl_downstream_mtu : 512;
    
    if (sess->upstream_len > 0) {
        uint16_t out_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        if (build_txt_reply(reply, &rlen, query_id, qname, sess->upstream_buf, sess->upstream_len,
                           mtu, out_seq, sid, sess->handshake_done) == 0) {
            /* Consume session buffer and send */
            sess->upstream_len = 0; /* Multi-chunk logic needed for real scale */
            send_udp_reply_direct(h, src, reply, rlen);
        }
    } else {
        /* Empty Poll Reply */
        uint16_t out_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
        if (build_txt_reply(reply, &rlen, query_id, qname, NULL, 0, mtu, out_seq, 
                           sid, sess->handshake_done) == 0) {
            send_udp_reply_direct(h, src, reply, rlen);
        }
    }
}

void dns_handler_init(void) {
    LOG_INFO("DNS Protocol Handler initialized\n");
}
