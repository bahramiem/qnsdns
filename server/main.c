/*
 * dnstun-server — DNS Tunnel VPN Server
 *
 * Architecture:
 *   UDP DNS listener (port 53) via libuv
 *     → Parse QNAME → extract session-id, seq, chunk header + payload
 *     → Resolver Swarm: record source IP as functional resolver
 *     → Session demultiplexing (per session_id)
 *     → SYNC command: respond with swarm IP list
 *     → Forward payload to upstream target via TCP
 *     → Receive upstream response
 *     → Encode response into DNS TXT reply (FEC K from client header)
 *     → Send TXT reply back to querying resolver
 *     → TUI: sessions, bandwidth, errors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <process.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "uv.h"
#include "SPCDNS/dns.h"
#include "SPCDNS/output.h"

#include "shared/config.h"
#include "shared/types.h"
#include "shared/resolver_pool.h"
#include "shared/base32.h"
#include "shared/tui.h"
#include "shared/codec.h"

/* ────────────────────────────────────────────── */
/*  Global state                                  */
/* ────────────────────────────────────────────── */
static dnstun_config_t  g_cfg;
static tui_ctx_t        g_tui;
static tui_stats_t      g_stats;
static uv_loop_t       *g_loop;

/* UDP listener */
static uv_udp_t         g_udp_server;

/* TUI timer */
static uv_timer_t       g_tui_timer;
static uv_timer_t       g_idle_timer;

/* Active upstream sessions */
typedef struct srv_session {
    bool      used;

    /* 4-bit session ID (0-15, embedded in chunk header flags) */
    uint8_t   session_id;

    /* upstream TCP */
    uv_tcp_t  upstream_tcp;
    bool      tcp_connected;

    /* recv buffer from upstream */
    uint8_t  *upstream_buf;
    size_t    upstream_len;
    size_t    upstream_cap;

    /* Last seen client address (reply target) */
    struct sockaddr_in client_addr;

    /* Client-reported capabilities */
    uint16_t  cl_downstream_mtu;
    uint16_t  next_downstream_seq; /* Sequence for downstream reordering */
    uint8_t   cl_enc_format;
    uint8_t   cl_loss_pct;
    uint8_t   cl_fec_k;
    char      user_id[16];

    /* Burst buffering for FEC */
    uint16_t  burst_seq_start;
    int       burst_count_needed;
    int       burst_received;
    uint8_t **burst_symbols;
    size_t    burst_symbol_len;

    time_t    last_active;
} srv_session_t;

#define SRV_MAX_SESSIONS 1024
static srv_session_t g_sessions[SRV_MAX_SESSIONS];

/* Resolver swarm database */
#define SWARM_MAX 16384
static char   g_swarm_ips[SWARM_MAX][46];
static int    g_swarm_count = 0;
static uv_mutex_t g_swarm_lock;

/* ────────────────────────────────────────────── */
/*  Logging                                       */
/* ────────────────────────────────────────────── */
static FILE *g_debug_log = NULL;

#define LOG_INFO(...)  do { if (g_cfg.log_level >= 1) { fprintf(stdout, "[INFO]  " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[INFO]  " __VA_ARGS__); } } while(0)
#define LOG_DEBUG(...) do { if (g_cfg.log_level >= 2) { fprintf(stdout, "[DEBUG] " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[DEBUG] " __VA_ARGS__); } } while(0)
#define LOG_ERR(...)   do { fprintf(stderr, "[ERROR] " __VA_ARGS__); if (g_debug_log) fprintf(g_debug_log, "[ERROR] " __VA_ARGS__); } while(0)

/* ────────────────────────────────────────────── */
/*  Swarm management                              */
/* ────────────────────────────────────────────── */
static void swarm_record_ip(const char *ip) {
    uv_mutex_lock(&g_swarm_lock);
    for (int i = 0; i < g_swarm_count; i++) {
        if (strcmp(g_swarm_ips[i], ip) == 0) {
            uv_mutex_unlock(&g_swarm_lock);
            return;
        }
    }
    if (g_swarm_count < SWARM_MAX) {
        strncpy(g_swarm_ips[g_swarm_count++], ip, 45);
        LOG_INFO("Swarm: +%s (%d total)\n", ip, g_swarm_count);
    }
    uv_mutex_unlock(&g_swarm_lock);
}

static char g_swarm_file[1024];

static void swarm_save(void) {
    if (!g_swarm_file[0]) return;
    FILE *f = fopen(g_swarm_file, "w");
    if (!f) return;
    uv_mutex_lock(&g_swarm_lock);
    for (int i = 0; i < g_swarm_count; i++)
        fprintf(f, "%s\n", g_swarm_ips[i]);
    uv_mutex_unlock(&g_swarm_lock);
    fclose(f);
}

static void swarm_load(void) {
    if (!g_swarm_file[0]) return;
    FILE *f = fopen(g_swarm_file, "r");
    if (!f) return;
    char ip[64];
    while (fgets(ip, sizeof(ip), f)) {
        /* trim newline */
        ip[strcspn(ip, "\r\n")] = '\0';
        if (ip[0]) swarm_record_ip(ip);
    }
    fclose(f);
}

/* ────────────────────────────────────────────── */
/*  Session lookup / alloc                        */
/* ────────────────────────────────────────────── */

/* Find session by 4-bit session ID and client address (fix hijacking) */
static int session_find(const struct sockaddr_in *addr, uint8_t id) {
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        if (g_sessions[i].used && g_sessions[i].session_id == id) {
            if (g_sessions[i].client_addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
                g_sessions[i].client_addr.sin_port == addr->sin_port) {
                return i;
            }
        }
    }
    return -1;
}

/* Allocate new session with 4-bit session ID and record client address */
static int session_alloc(const struct sockaddr_in *addr, uint8_t id) {
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        if (!g_sessions[i].used) {
            /* If this index was used before, ensure its handle was closed.
               uv_tcp_init below will fail if it's already a closing/active handle. */
            memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
            g_sessions[i].session_id   = id;
            g_sessions[i].used         = true;
            g_sessions[i].client_addr  = *addr;
            g_sessions[i].last_active  = time(NULL);
            g_stats.active_sessions++;
            return i;
        }
    }
    return -1;
}

static void session_close(int idx) {
    srv_session_t *s = &g_sessions[idx];
    if (!s->used) return;
    if (s->tcp_connected && !uv_is_closing((uv_handle_t*)&s->upstream_tcp))
        uv_close((uv_handle_t*)&s->upstream_tcp, NULL);
    free(s->upstream_buf);
    s->upstream_buf = NULL;

    if (s->burst_symbols) {
        for (int i = 0; i < s->burst_count_needed; i++) free(s->burst_symbols[i]);
        free(s->burst_symbols);
    }

    s->used = false;
    if (g_stats.active_sessions > 0)
        g_stats.active_sessions--;
}

/* ────────────────────────────────────────────── */
/*  Upstream TCP connection                       */
/* ────────────────────────────────────────────── */
typedef struct connect_req {
    uv_connect_t  connect;
    int           session_idx;
    uint8_t      *payload;
    size_t        payload_len;
} connect_req_t;

static void on_upstream_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf);
static void on_upstream_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf);
static void on_upstream_write(uv_write_t *w, int status);
static void on_upstream_connect(uv_connect_t *req, int status);

/* Write payload to upstream and then start reading responses */
static void upstream_write_and_read(int session_idx,
                                    const uint8_t *data, size_t len)
{
    srv_session_t *s = &g_sessions[session_idx];
    if (!s->tcp_connected) return;

    uv_write_t *w = malloc(sizeof(*w) + len);
    if (!w) return;
    uint8_t *copy = (uint8_t*)(w + 1);
    memcpy(copy, data, len);
    w->data = w;
    uv_buf_t buf = uv_buf_init((char*)copy, (unsigned)len);
    uv_write(w, (uv_stream_t*)&s->upstream_tcp, &buf, 1, on_upstream_write);

    g_stats.tx_total += len;
    g_stats.tx_bytes_sec += len;
}

static void on_upstream_write(uv_write_t *w, int status) {
    free(w->data);
    (void)status;
}

static void on_upstream_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    /* Fix #3: use per-session heap buffer instead of shared static buffer.
       Each srv_session has its own upstream_buf (grown with realloc). We
       allocate a fresh 8 KB block here; on_upstream_read appends into the
       session's persistent buffer and frees this temporary one. */
    (void)sz;
    int *sidx_ptr = h->data;
    int sidx = sidx_ptr ? *sidx_ptr : -1;
    if (sidx < 0 || !g_sessions[sidx].used) {
        buf->base = NULL;
        buf->len  = 0;
        return;
    }
    buf->base = (char*)malloc(8192);
    buf->len  = buf->base ? 8192 : 0;
}

static void on_upstream_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf)
{
    int *sidx_ptr = s->data;
    int sidx = sidx_ptr ? *sidx_ptr : -1;
    if (sidx < 0) { free(buf->base); return; }
    srv_session_t *sess = &g_sessions[sidx];

    if (nread <= 0) {
        free(buf->base);
        session_close(sidx);
        return;
    }

    /* Append received bytes into the session's persistent buffer */
    size_t need = sess->upstream_len + (size_t)nread;
    if (need > sess->upstream_cap) {
        sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
        sess->upstream_cap = need + 8192;
    }
    memcpy(sess->upstream_buf + sess->upstream_len, buf->base, (size_t)nread);
    sess->upstream_len += (size_t)nread;
    
    /* Debug: log first 64 bytes received from upstream */
    LOG_DEBUG("Session %d: received %zd bytes from upstream, first 64: '%.64s'\n",
              sidx, nread, sess->upstream_buf + sess->upstream_len - nread);
    
    free(buf->base);

    g_stats.rx_total += (size_t)nread;
    g_stats.rx_bytes_sec += (size_t)nread;
}

static void on_upstream_connect(uv_connect_t *req, int status) {
    connect_req_t *cr = (connect_req_t*)req;
    int sidx = cr->session_idx;
    srv_session_t *sess = &g_sessions[sidx];

    if (status != 0) {
        LOG_ERR("Upstream connect failed for session %d: %s\n", sidx, uv_strerror(status));
        free(cr->payload);
        free(cr);
        session_close(sidx);
        return;
    }
    LOG_INFO("Upstream connected for session %d\n", sidx);

    sess->tcp_connected = true;
    static int sidx_store[SRV_MAX_SESSIONS];
    sidx_store[sidx] = sidx;
    sess->upstream_tcp.data = &sidx_store[sidx];

    uv_read_start((uv_stream_t*)&sess->upstream_tcp,
                  on_upstream_alloc, on_upstream_read);

    if (cr->payload && cr->payload_len > 0)
        upstream_write_and_read(sidx, cr->payload, cr->payload_len);

    free(cr->payload);
    free(cr);
}

/* ────────────────────────────────────────────── */
/*  Build DNS TXT Reply                           */
/* ────────────────────────────────────────────── */

/* Obsolete: handled inline in build_txt_reply */
static size_t encode_downstream_data(char *out, const uint8_t *in, size_t inlen) {
    /* Use base64 encoding by default for better compatibility with intermediate resolvers.
     * Raw binary data often gets dropped or mangled by DNS infrastructure. */
    if (g_cfg.downstream_encoding == 1) {
        /* Hex encoding (for debugging) */
        return hex_encode(out, in, inlen);
    }
    /* Default: base64 encoding for better DNS compatibility */
    return base64_encode(out, in, inlen);
}

static int build_txt_reply(uint8_t *outbuf, size_t *outlen,
                           uint16_t query_id, const char *qname,
                           uint8_t session_id, uint16_t seq,
                           const uint8_t *data, size_t data_len,
                           uint16_t mtu)
{
    /* 1. Pack header + data into a temporary buffer */
    uint8_t pkt[DNSTUN_MAX_DOWNSTREAM_MTU + 8];
    server_response_header_t hdr = {0};
    hdr.flags = 0; /* base64 */
    hdr.session_id = session_id;
    hdr.seq = seq;
    
    if (data_len > mtu - sizeof(hdr)) data_len = mtu - sizeof(hdr);
    
    memcpy(pkt, &hdr, sizeof(hdr));
    if (data_len > 0) memcpy(pkt + sizeof(hdr), data, data_len);
    
    /* 2. Base64 encode the whole package */
    char encoded[DNSTUN_MAX_DOWNSTREAM_MTU * 2];
    size_t encoded_len = base64_encode(encoded, pkt, sizeof(hdr) + data_len);
    
    dns_question_t q = {0};
    q.name  = qname;
    q.type  = RR_TXT;
    q.class = CLASS_IN;
 
    dns_answer_t ans = {0};
    ans.txt.name = qname;
    ans.txt.type   = RR_TXT;
    ans.txt.class  = CLASS_IN;
    ans.txt.ttl    = 0;
    ans.txt.len    = (uint16_t)encoded_len;
    ans.txt.text   = encoded;
 
    dns_query_t resp = {0};
    resp.id        = query_id;
    resp.query     = false;
    resp.rd        = true;
    resp.ra        = true;
    resp.qdcount   = 1;
    resp.ancount   = 1;
    resp.questions = &q;
    resp.answers   = &ans;
 
    size_t sz = *outlen;
    dns_rcode_t rc = dns_encode((dns_packet_t*)outbuf, &sz, &resp);
    if (rc != RCODE_OKAY) return -1;
    *outlen = sz;
    return 0;
}

/* ────────────────────────────────────────────── */
/*  Main UDP receive handler                      */
/* ────────────────────────────────────────────── */
typedef struct {
    uv_udp_send_t    send_req;
    struct sockaddr_in dest;
    uint8_t          reply_buf[512]; /* Fix: was DNS_BUFFER_UDP which is only 64 bytes on 64-bit systems */
    size_t           reply_len;
} udp_reply_t;

static void on_udp_send_done(uv_udp_send_t *r, int status) {
    (void)status;
    udp_reply_t *rep = (udp_reply_t*)r;
    free(rep);
}

static void send_udp_reply(const struct sockaddr_in *dest,
                           const uint8_t *data, size_t len)
{
    udp_reply_t *rep = malloc(sizeof(*rep));
    if (!rep) return;
    memcpy(&rep->dest, dest, sizeof(*dest));
    if (len > sizeof(rep->reply_buf)) len = sizeof(rep->reply_buf);
    memcpy(rep->reply_buf, data, len);
    rep->reply_len = len;

    uv_buf_t buf = uv_buf_init((char*)rep->reply_buf, (unsigned)len);
    if (uv_udp_send(&rep->send_req, &g_udp_server, &buf, 1,
                    (const struct sockaddr*)dest, on_udp_send_done) != 0)
    {
        free(rep);
    }
    g_stats.queries_sent++;
}

static uint8_t s_recv_buf[65536];

static void on_server_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    (void)h; (void)sz;
    buf->base = (char*)s_recv_buf;
    buf->len  = sizeof(s_recv_buf);
}

static void on_server_recv(uv_udp_t *h,
                            ssize_t nread,
                            const uv_buf_t *buf,
                            const struct sockaddr *addr,
                            unsigned flags)
{
    (void)h; (void)flags;
    if (nread <= 0 || !addr) {
        if (nread < 0) {
            LOG_ERR("UDP recv error: %zd\n", nread);
        }
        return;
    }

    const struct sockaddr_in *src = (const struct sockaddr_in*)addr;
    char src_ip[46];
    uv_inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
    LOG_DEBUG("Server received %zd bytes from %s:%d\n", nread, src_ip, ntohs(src->sin_port));
    g_stats.queries_recv++;

    /* Record source IP in swarm (src_ip already defined above) */
    swarm_record_ip(src_ip);

    /* Decode DNS query */
    dns_decoded_t decoded[DNS_DECODEBUF_4K];
    size_t decsz = sizeof(decoded);
    if (dns_decode(decoded, &decsz,
                   (const dns_packet_t*)buf->base,
                   (size_t)nread) != RCODE_OKAY)
    {
        LOG_DEBUG("DNS decode failed from %s\n", src_ip);
        g_stats.queries_lost++;
        return;
    }

    dns_query_t *qry = (dns_query_t*)decoded;
    if (qry->qdcount < 1) return;

    const char *qname = qry->questions[0].name;
    uint16_t query_id = qry->id;

    /* Parse QNAME: <seq_hex>.<b32_parts...>.<sid_hex>.tun.<domain>
       Fix #31: Handle multi-label b32 payloads split by the client. */
    char tmp[DNSTUN_MAX_QNAME_LEN + 1];
    strncpy(tmp, qname, sizeof(tmp)-1);

    char *parts[16] = {0};
    int part_count = 0;
    char *tok = strtok(tmp, ".");
    while (tok && part_count < 16) {
        parts[part_count++] = tok;
        tok = strtok(NULL, ".");
    }

    /* Find "tun" marker to identify structure
     * Use case-insensitive comparison because DNS is case-insensitive
     * and some resolvers use 0x20 case randomization */
    int tun_idx = -1;
    for (int i = 0; i < part_count; i++) {
        if (strcasecmp(parts[i], "tun") == 0) { tun_idx = i; break; }
    }

    /* New compact format: <b32_payload>.tun.<domain>
     * The session_id is embedded in the chunk header flags byte, NOT in QNAME.
     * Format: parts[0..tun_idx-1] = base32 payload, parts[tun_idx] = "tun"
     */
    if (tun_idx < 1) { /* Need at least b32_payload and tun */
        /* This is likely a resolver test probe (MTU test, NXDOMAIN test, etc.)
         * from the client. These don't have the .tun. marker. Silently ignore. */
        LOG_DEBUG("Ignoring non-tunnel probe from %s: %s (tun_idx=%d, part_count=%d)\n",
                src_ip, qname, tun_idx, part_count);
        return;
    }
    LOG_DEBUG("Parsed QNAME: tun_idx=%d, part_count=%d\n", tun_idx, part_count);

    /* Reassemble b32 payload from all parts before .tun. marker
     * (now single consolidated label after client inline_dotify) */
    char b32_payload[512] = {0};
    for (int i = 0; i < tun_idx; i++) {
        strncat(b32_payload, parts[i], sizeof(b32_payload) - strlen(b32_payload) - 1);
    }
    /* Decode b32 payload → raw bytes (chunk_header + data) */
    uint8_t raw[sizeof(chunk_header_t) + DNSTUN_CHUNK_PAYLOAD + 4];
    ssize_t rawlen = base32_decode(raw, b32_payload, strlen(b32_payload));
    if (rawlen < (ssize_t)sizeof(chunk_header_t)) {
        LOG_DEBUG("Base32 decode too short from %s\n", src_ip);
        return;
    }

    /* Parse new compact 4-byte header */
    chunk_header_t hdr;
    memcpy(&hdr, raw, sizeof(hdr));
    const uint8_t  *payload = raw + sizeof(chunk_header_t);
    size_t          payload_len = (size_t)(rawlen - (ssize_t)sizeof(chunk_header_t));

    /* Extract fields from new compact header */
    bool is_poll = (hdr.flags & CHUNK_FLAG_POLL) != 0;
    bool is_encrypted = (hdr.flags & CHUNK_FLAG_ENCRYPTED) != 0;
    uint8_t session_id = chunk_get_session_id(hdr.flags);
    uint16_t seq = hdr.seq;
    
    /* chunk_info: high nibble = chunk_total-1, low nibble = fec_k */
    uint8_t chunk_total = chunk_get_total(hdr.chunk_info);
    uint8_t fec_k = chunk_get_fec_k(hdr.chunk_info);

    bool is_sync = false;
    /* SYNC command: payload starts with "SYNC" (ASCII) */
    if (payload_len >= 4 && memcmp(payload, "SYNC", 4) == 0) is_sync = true;

    /* Session lookup / allocate by 4-bit session ID + source IP */
    int sidx = session_find(src, session_id);
    if (sidx < 0) {
        sidx = session_alloc(src, session_id);
        if (sidx < 0) {
            LOG_ERR("Session table full\n");
            return;
        }
        LOG_INFO("New session created: idx=%d, sid=%u, is_poll=%d, is_sync=%d, payload_len=%zu\n",
                 sidx, session_id, is_poll, is_sync, payload_len);
    } else {
        LOG_DEBUG("Existing session: idx=%d, sid=%u, seq=%u, total=%u, payload_len=%zu\n",
                  sidx, session_id, seq, chunk_total, payload_len);
    }

    srv_session_t *sess = &g_sessions[sidx];
    sess->last_active       = time(NULL);
    sess->client_addr       = *src;
    
    sess->cl_downstream_mtu = DNSTUN_MAX_DOWNSTREAM_MTU;
    sess->cl_enc_format     = 0;
    sess->cl_loss_pct       = 0;
    sess->cl_fec_k          = fec_k;

    /* ── Handle FEC Burst Reassembly ──────────────────────────────────── */
    if (chunk_total > 0) {
        if (chunk_total > 32 || payload_len > 2048) {
            LOG_ERR("DoS: oversized FEC burst (total=%u, len=%zu)\n", chunk_total, payload_len);
            return;
        }

        if (sess->burst_count_needed == 0 || seq < sess->burst_seq_start) {
            if (sess->burst_symbols) {
                for (int i = 0; i < (int)sess->burst_count_needed; i++) {
                    if (sess->burst_symbols[i]) free(sess->burst_symbols[i]);
                }
                free(sess->burst_symbols);
            }
            sess->burst_seq_start     = seq;
            sess->burst_count_needed  = chunk_total;
            sess->burst_received      = 0;
            sess->burst_symbols       = calloc(chunk_total, sizeof(uint8_t*));
            sess->burst_symbol_len    = payload_len;
        }

        int offset = seq - sess->burst_seq_start;
        if (offset >= 0 && offset < (int)sess->burst_count_needed && !sess->burst_symbols[offset]) {
            if (payload_len != sess->burst_symbol_len) {
                LOG_ERR("FEC: symbol size mismatch (%zu vs %zu)\n", payload_len, sess->burst_symbol_len);
                return;
            }
            sess->burst_symbols[offset] = malloc(payload_len);
            if (sess->burst_symbols[offset]) {
                memcpy(sess->burst_symbols[offset], payload, payload_len);
                sess->burst_received++;
            }
        }

        int k_est = sess->burst_count_needed - (int)sess->cl_fec_k;
        if (k_est < 1) k_est = 1;

        if (sess->burst_received >= k_est) {
            fec_encoded_t fec = {0};
            fec.symbols      = sess->burst_symbols;
            fec.symbol_len   = sess->burst_symbol_len;
            fec.total_count  = sess->burst_count_needed;

            size_t orig_len_est = (size_t)k_est * DNSTUN_CHUNK_PAYLOAD;
            codec_result_t fdec = codec_fec_decode(&fec, orig_len_est);
            if (!fdec.error) {
                const uint8_t *dec_in = fdec.data;
                size_t         dec_len = fdec.len;
                codec_result_t dret = {0};
                codec_result_t zdec = {0};

                if (hdr.flags & CHUNK_FLAG_ENCRYPTED) {
                    dret = codec_decrypt(fdec.data, fdec.len, g_cfg.psk);
                    if (!dret.error) {
                        dec_in = dret.data;
                        dec_len = dret.len;
                    } else {
                        LOG_ERR("Decryption failed\n");
                        goto cleanup_burst_results;
                    }
                }

                zdec = codec_decompress(dec_in, dec_len, 0);
                if (!zdec.error) {
                    if (!sess->tcp_connected) {
                        const uint8_t *p = zdec.data;
                        size_t l = zdec.len;
                        if (l >= 10 && p[0] == 0x05 && p[1] == 0x01) {
                            char target_host[256] = {0};
                            uint16_t target_port = 0;
                            uint8_t atype = p[3];
                            if (atype == 0x01) {
                                snprintf(target_host, sizeof(target_host), "%d.%d.%d.%d", p[4], p[5], p[6], p[7]);
                                target_port = (uint16_t)((p[8]<<8)|p[9]);
                            } else if (atype == 0x03) {
                                uint8_t dlen = p[4];
                                if ((size_t)(5 + dlen + 2) <= l && dlen < 255) {
                                    memcpy(target_host, p + 5, dlen);
                                    target_host[dlen] = '\0';
                                    target_port = (uint16_t)((p[5+dlen]<<8)|p[6+dlen]);
                                }
                            }
                            if (target_host[0] && target_port > 0) {
                                struct sockaddr_in up_addr;
                                uv_ip4_addr(target_host, target_port, &up_addr);
                                connect_req_t *cr = calloc(1, sizeof(*cr));
                                cr->session_idx = sidx;
                                size_t hdr_sz = (atype == 0x01) ? 10 : (5 + p[4] + 2);
                                if (l > hdr_sz) {
                                    cr->payload_len = l - hdr_sz;
                                    cr->payload = malloc(cr->payload_len);
                                    memcpy(cr->payload, p + hdr_sz, cr->payload_len);
                                }
                                LOG_INFO("Connecting upstream for session %d to %s:%d\n", sidx, target_host, target_port);
                                uv_tcp_init(g_loop, &sess->upstream_tcp);
                                uv_tcp_nodelay(&sess->upstream_tcp, 1);
                                uv_tcp_connect(&cr->connect, &sess->upstream_tcp, (const struct sockaddr*)&up_addr, on_upstream_connect);
                            }
                        }
                    } else {
                        upstream_write_and_read(sidx, zdec.data, zdec.len);
                    }
                    codec_free_result(&zdec);
                }
            cleanup_burst_results:
                if (dret.data) codec_free_result(&dret);
                codec_free_result(&fdec);
            }

        next_burst:
            /* Reset burst */
            for (int i = 0; i < (int)sess->burst_count_needed; i++) {
                if (sess->burst_symbols[i]) free(sess->burst_symbols[i]);
            }
            free(sess->burst_symbols);
            sess->burst_symbols = NULL;
            sess->burst_count_needed = 0;
            sess->burst_received = 0;
        }
    } else if (is_poll) {
        /* Handle empty poll normally to trigger downstream data push */
    }

    /* ── Handle SWARM Sync (if enabled) ─────────────────────────── */
    if (is_sync) {
        char swarm_text[65536] = {0};
        size_t slen = 0;
        uv_mutex_lock(&g_swarm_lock);
        for (int i = 0; i < g_swarm_count && slen < sizeof(swarm_text) - 48; i++) {
            slen += (size_t)snprintf(swarm_text + slen,
                                     sizeof(swarm_text) - slen,
                                     "%s,", g_swarm_ips[i]);
        }
        uv_mutex_unlock(&g_swarm_lock);

        uint8_t reply[512]; /* Fix: was DNS_BUFFER_UDP which is only 64 bytes on 64-bit systems */
        size_t  rlen = sizeof(reply);
        if (build_txt_reply(reply, &rlen, query_id, qname,
                            session_id, 0, /* SWARM sync is unsequenced/standalone */
                            (const uint8_t*)swarm_text,
                            slen,
                            sess->cl_downstream_mtu) == 0)
        {
            send_udp_reply(src, reply, rlen);
        }
        return;
    }

    /* ── Forward payload to upstream (non-FEC path) ──────────────── */
    /* Fix #11: Only forward to already-connected sessions. SOCKS5 CONNECT
       must arrive via the FEC+decompress path to be decoded correctly. */
    LOG_DEBUG("Session %d: checking forward - is_poll=%d, payload_len=%zu, tcp_connected=%d\n",
              sidx, is_poll, payload_len, sess->tcp_connected);
    if (!is_poll && payload_len > 0 && sess->tcp_connected) {
        LOG_DEBUG("Session %d: forwarding %zu bytes to upstream\n", sidx, payload_len);
        upstream_write_and_read(sidx, payload, payload_len);
    } else if (payload_len > 0 && !sess->tcp_connected) {
        LOG_DEBUG("Session %d: NOT forwarding - tcp not connected yet\n", sidx);
    } else if (payload_len > 0) {
        LOG_DEBUG("Session %d: NOT forwarding - is_poll=%d\n", sidx, is_poll);
    }

    /* ── Build reply — stuff any pending upstream data ───────────── */
        uint8_t reply[512]; /* Fix: was DNS_BUFFER_UDP which is only 64 bytes on 64-bit systems */
        size_t  rlen = sizeof(reply);
    uint16_t mtu = sess->cl_downstream_mtu;
    if (mtu < 16 || mtu > 4096) mtu = 512;

    if (sess->upstream_len > 0) {
        size_t sz = sess->upstream_len;
        if (sz > mtu) sz = mtu;

        /* Debug: log first 64 bytes being sent */
        LOG_DEBUG("Session %d: sending %zu bytes to client, first 64: '%.64s'\n",
                  sidx, sz, (char*)sess->upstream_buf);

        if (build_txt_reply(reply, &rlen, query_id, qname,
                            session_id, sess->next_downstream_seq++,
                            sess->upstream_buf, sz, mtu) == 0)
        {
            /* Shift consumed bytes out of upstream buffer */
            memmove(sess->upstream_buf,
                    sess->upstream_buf + sz,
                    sess->upstream_len - sz);
            sess->upstream_len -= sz;
            send_udp_reply(src, reply, rlen);
        }
    } else {
        /* Empty reply — acknowledge the query */
        uint8_t ack[1] = {0};
        if (build_txt_reply(reply, &rlen, query_id, qname,
                            session_id, sess->next_downstream_seq, ack, 1, mtu) == 0)
            send_udp_reply(src, reply, rlen);
    }
}

/* ────────────────────────────────────────────── */
/*  Idle / cleanup timer (1s)                     */
/* ────────────────────────────────────────────── */
static void on_idle_timer(uv_timer_t *t) {
    (void)t;
    time_t now = time(NULL);
    for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
        srv_session_t *s = &g_sessions[i];
        if (!s->used) continue;
        if (now - s->last_active > g_cfg.idle_timeout_sec) {
            LOG_INFO("Session %d idle timeout\n", i);
            session_close(i);
        }
    }

    /* Save swarm periodically */
    static int save_tick = 0;
    if (++save_tick >= 60) {
        save_tick = 0;
        if (g_cfg.swarm_save_disk)
            swarm_save();
    }

    /* Update TUI stats */
    g_stats.tx_bytes_sec = 0;
    g_stats.rx_bytes_sec = 0;
}

/* ────────────────────────────────────────────── */
/*  TUI Render Timer (1s)                         */
/* ────────────────────────────────────────────── */
static void on_tui_timer(uv_timer_t *t) {
    (void)t;
    /* Count active sessions for TUI */
    int n = 0;
    for (int i = 0; i < SRV_MAX_SESSIONS; i++)
        if (g_sessions[i].used) n++;
    g_stats.active_sessions = n;

    uv_mutex_lock(&g_swarm_lock);
    g_stats.active_resolvers = g_swarm_count;
    uv_mutex_unlock(&g_swarm_lock);

    tui_render(&g_tui);
}

/* ────────────────────────────────────────────── */
/*  Entry point                                   */
/* ────────────────────────────────────────────── */
/* ────────────────────────────────────────────── */
/*  TUI callback for active clients               */
/* ────────────────────────────────────────────── */
static int get_active_clients(tui_client_snap_t *out, int max_clients) {
    int count = 0;
    time_t now = time(NULL);
    for (int i = 0; i < SRV_MAX_SESSIONS && count < max_clients; i++) {
        if (g_sessions[i].used) {
            uv_ip4_name(&g_sessions[i].client_addr, out[count].ip, sizeof(out[count].ip));
            out[count].downstream_mtu = g_sessions[i].cl_downstream_mtu;
            out[count].loss_pct       = g_sessions[i].cl_loss_pct;
            out[count].fec_k          = g_sessions[i].cl_fec_k;
            out[count].enc_format     = g_sessions[i].cl_enc_format;
            out[count].idle_sec       = (uint32_t)(now - g_sessions[i].last_active);
            strncpy(out[count].user_id, g_sessions[i].user_id, sizeof(out[count].user_id)-1);
            out[count].user_id[sizeof(out[count].user_id)-1] = '\0';
            count++;
        }
    }
    return count;
}

/* ────────────────────────────────────────────── */
/*  TUI Input (TTY)                               */
/* ────────────────────────────────────────────── */
static uv_tty_t g_tty;

static void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)stream;
    if (nread > 0) {
        for (ssize_t i=0; i<nread; i++) {
            tui_handle_key(&g_tui, buf->base[i]);
            if (!g_tui.running) uv_stop(g_loop);
        }
    }
    if (buf->base) free(buf->base);
}

int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    static char auto_config_path[1024] = {0};
    char domain_buf[512] = {0};
    char threads_str[16];
    char *slash;
#ifdef _WIN32
    char *bslash;
#endif
    char bind_ip[64]  = "0.0.0.0";
    int  bind_port    = 53;
    char tmp[64];
    char *colon;
    struct sockaddr_in srv_addr;
    int r;
    static resolver_pool_t dummy_pool;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_path = argv[i+1];
            break;
        }
    }

    if (!config_path) {
        /* Auto-locate server.ini */
        const char *candidates[] = {
            "server.ini",
            "../server.ini",
            "../../server.ini",
            "../../../server.ini",
            "/etc/dnstun/server.ini"
        };
        for (int i = 0; i < 5; i++) {
            FILE *f = fopen(candidates[i], "r");
            if (f) {
                fclose(f);
                config_path = candidates[i];
                break;
            }
        }
        if (!config_path) {
            /* Try relative to executable */
            char exe_path[1024];
            size_t size = sizeof(exe_path);
            if (uv_exepath(exe_path, &size) == 0) {
                char *eslash = strrchr(exe_path, '/');
#ifdef _WIN32
                char *ebslash = strrchr(exe_path, '\\');
                if (ebslash > eslash) eslash = ebslash;
#endif
                if (eslash) {
                    *eslash = '\0';
                    const char *rel[] = {"", "/..", "/../..", "/../../.."};
                    for (int i = 0; i < 4; i++) {
                        snprintf(auto_config_path, sizeof(auto_config_path), "%s%s/server.ini", exe_path, rel[i]);
                        FILE *tf = fopen(auto_config_path, "r");
                        if (tf) {
                            fclose(tf);
                            config_path = auto_config_path;
                            break;
                        }
                    }
                }
            }
        }
        if (!config_path) config_path = "server.ini";
    }
    
    if (config_path && config_path != auto_config_path) {
        strncpy(auto_config_path, config_path, sizeof(auto_config_path)-1);
        config_path = auto_config_path;
    }

    /* Load config */
    config_defaults(&g_cfg, true);
    if (config_load(&g_cfg, config_path) != 0) {
        fprintf(stderr,
            "Warning: could not load '%s', using defaults.\n"
            "Create server.ini to configure the server.\n\n",
            config_path);
    }

    /* Open debug log file */
    g_debug_log = fopen("/tmp/qnsdns_server.log", "a");
    if (g_debug_log) {
        fprintf(g_debug_log, "\n=== Server started at ");
        time_t now = time(NULL);
        fprintf(g_debug_log, "%s", ctime(&now));
        fflush(g_debug_log);
    }

    /* ── First-run: ask for tunnel domain if not configured ── */
    if (g_cfg.domain_count == 0 || (g_cfg.domain_count == 1 && strcmp(g_cfg.domains[0], "tun.example.com") == 0)) {
        printf("\n  No tunnel domain configured (or default tun.example.com is in use).\n");
        printf("  Enter the subdomain this server will handle\n");
        printf("  (e.g. tun.example.com, separate multiple with commas): ");
        fflush(stdout);
        if (fgets(domain_buf, sizeof(domain_buf), stdin)) {
            domain_buf[strcspn(domain_buf, "\r\n")] = '\0';
            if (domain_buf[0]) {
                config_set_key(&g_cfg, "domains", "list", domain_buf);
                if (config_save_domains(config_path, &g_cfg) == 0)
                    printf("  Saved to %s\n\n", config_path);
            }
        }
        if (g_cfg.domain_count == 0)
            fprintf(stderr, "[WARN] No domain configured. Server will accept queries for any domain.\n");
    }

    /* libuv thread pool */
    snprintf(threads_str, sizeof(threads_str), "%d", g_cfg.workers);
#ifdef _WIN32
    _putenv_s("UV_THREADPOOL_SIZE", threads_str);
#else
    setenv("UV_THREADPOOL_SIZE", threads_str, 1);
#endif

    g_loop = uv_default_loop();

    /* Init swarm */
    /* Set up server swarm file path safely beside config_path */
    strncpy(g_swarm_file, config_path, sizeof(g_swarm_file)-1);
    slash = strrchr(g_swarm_file, '/');
#ifdef _WIN32
    bslash = strrchr(g_swarm_file, '\\');
    if (bslash > slash) slash = bslash;
#endif
    if (slash) strncpy(slash + 1, "server_resolvers.txt", sizeof(g_swarm_file) - (slash - g_swarm_file) - 1);
    else strcpy(g_swarm_file, "server_resolvers.txt");

    uv_mutex_init(&g_swarm_lock);
    if (g_cfg.swarm_save_disk)
        swarm_load();

    /* Parse bind address */
    if (g_cfg.server_bind[0]) {
        strncpy(tmp, g_cfg.server_bind, sizeof(tmp)-1);
        colon = strrchr(tmp, ':');
        if (colon) {
            *colon = '\0';
            bind_port = atoi(colon+1);
            strncpy(bind_ip, tmp, sizeof(bind_ip)-1);
        }
    }

    /* Bind UDP port 53 */
    uv_ip4_addr(bind_ip, bind_port, &srv_addr);
    uv_udp_init(g_loop, &g_udp_server);
    r = uv_udp_bind(&g_udp_server,
                        (const struct sockaddr*)&srv_addr,
                        UV_UDP_REUSEADDR);
    if (r != 0) {
        LOG_ERR("Cannot bind UDP %s:%d — %s\n",
                bind_ip, bind_port, uv_strerror(r));
        return 1;
    }

    uv_udp_recv_start(&g_udp_server, on_server_alloc, on_server_recv);

    /* TUI with dummy resolver pool (server shows swarm count) */
    memset(&dummy_pool, 0, sizeof(dummy_pool));
    uv_mutex_init(&dummy_pool.lock);
    dummy_pool.cfg = &g_cfg;

    tui_init(&g_tui, &g_stats, &dummy_pool, &g_cfg, "SERVER", config_path);
    g_tui.get_clients_cb = get_active_clients;

    /* Timers */
    uv_timer_init(g_loop, &g_tui_timer);
    uv_timer_start(&g_tui_timer, on_tui_timer, 1000, 1000);

    uv_timer_init(g_loop, &g_idle_timer);
    uv_timer_start(&g_idle_timer, on_idle_timer, 1000, 1000);

    LOG_INFO("dnstun-server listening on %s:%d\n", bind_ip, bind_port);
    LOG_INFO("  Workers  : %d\n", g_cfg.workers);
    LOG_INFO("  Swarm    : %d known resolvers\n", g_swarm_count);
    LOG_INFO("  Swarm serve: %s\n", g_cfg.swarm_serve ? "yes" : "no");

    /* Bind STDIN */
    uv_tty_init(g_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);

    uv_run(g_loop, UV_RUN_DEFAULT);

    tui_shutdown(&g_tui);
    if (g_cfg.swarm_save_disk)
        swarm_save();

    uv_mutex_destroy(&g_swarm_lock);
    codec_pool_shutdown();  /* Shutdown buffer pool */

    if (g_tui.restart) {
        LOG_INFO("Restarting process to apply new domain...\n");
#ifdef _WIN32
        _execvp(argv[0], argv);
#else
        execvp(argv[0], argv);
#endif
    }
    return 0;
}
