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

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#ifdef _WIN32
/* Include winsock2.h BEFORE windows.h to prevent winsock.h conflicts */
#define WIN32_LEAN_AND_MEAN
#include <process.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* Undefine any Windows macro that might conflict with our identifiers */
#ifdef sync
#undef sync
#endif
#else
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>

#endif

#include "SPCDNS/dns.h"
#include "SPCDNS/output.h"
#include "uv.h"


#include "shared/base32.h"
#include "shared/codec.h"
#include "shared/config.h"
#include "shared/mgmt.h"
#include "shared/resolver_pool.h"
#include "shared/tui.h"
#include "shared/types.h"


/* Forward declarations */
static int build_txt_reply_with_seq(uint8_t *outbuf, size_t *outlen,
                                    uint16_t query_id, const char *qname,
                                    const uint8_t *data, size_t data_len,
                                    uint16_t mtu, uint16_t seq,
                                    uint8_t session_id);
static void send_udp_reply(const struct sockaddr_in *dest, const uint8_t *data,
                           size_t len);

/* ────────────────────────────────────────────── */
/*  Global state                                  */
/* ────────────────────────────────────────────── */
static dnstun_config_t g_cfg;
static tui_ctx_t g_tui;
static tui_stats_t g_stats;
static uv_loop_t *g_loop;
static mgmt_server_t *g_mgmt; /* Management server for TUI */

/* UDP listener */
static uv_udp_t g_udp_server;

/* TUI timer */
static uv_timer_t g_tui_timer;
static uv_timer_t g_idle_timer;

/* Active upstream sessions */
typedef struct srv_session {
  bool used;

  /* 8-bit session ID (0-255) */
  uint8_t session_id;

  /* upstream TCP */
  uv_tcp_t upstream_tcp;
  bool tcp_connected;

  /* recv buffer from upstream */
  uint8_t *upstream_buf;
  size_t upstream_len;
  size_t upstream_cap;

  /* Last seen client address (reply target) */
  struct sockaddr_in client_addr;

  /* Client-reported capabilities */
  uint16_t cl_downstream_mtu;
  uint8_t cl_enc_format;
  uint8_t cl_loss_pct;
  uint8_t cl_fec_k;
  char user_id[16];

  /* Burst buffering for FEC */
  uint16_t burst_seq_start;
  int burst_count_needed;
  int burst_received;
  uint8_t **burst_symbols;
  size_t burst_symbol_len;
  uint64_t burst_oti_common; /* OTI Common from first symbol of burst */
  uint32_t burst_oti_scheme; /* OTI Scheme from first symbol of burst */
  bool burst_has_oti;        /* true if OTI has been set for this burst */
  bool burst_decoded;        /* true once this burst_seq_start has been fully
                              * decoded+forwarded; gate against re-decode from
                              * redundant FEC symbols of the same burst */

  /* Set true once the client has sent a capability/MTU handshake for this
   * session. After this point downstream_seq is used for ALL replies
   * (including FEC chunk ACKs and polls) so the client reorder buffer
   * receives a gapless monotonic stream. Pre-handshake probe polls get
   * seq=0 with no increment to keep them outside the reorder window. */
  bool handshake_done;

  /* Downstream sequencing (Server → Client) */
  uint16_t downstream_seq; /* Next seq to assign for downstream packets */

  bool status_sent;
  time_t last_active;

  /* Retransmit slot: last sent downstream data, resent on every poll until
   * new upstream data arrives (acts as implicit ACK that the old data was
   * received). Cleared when upstream_buf has new data to send. */
  uint8_t retx_buf[4096];  /* copy of last sent payload */
  size_t  retx_len;        /* bytes in retx_buf (0 = nothing to retransmit) */
  uint16_t retx_seq;       /* downstream_seq that was used for retx_buf */
} srv_session_t;

#define SRV_MAX_SESSIONS 1024
static srv_session_t g_sessions[SRV_MAX_SESSIONS];

/* Resolver swarm database */
#define SWARM_MAX 16384
static char g_swarm_ips[SWARM_MAX][46];
static int g_swarm_count = 0;
static uv_mutex_t g_swarm_lock;

/* ────────────────────────────────────────────── */
/*  Logging                                       */
/* ────────────────────────────────────────────── */
static FILE *g_debug_log = NULL;

#define LOG_INFO(...)                                                          \
  do {                                                                         \
    if (g_cfg.log_level >= 1) {                                                \
      fprintf(stdout, "[INFO]  " __VA_ARGS__);                                 \
      if (g_debug_log)                                                         \
        fprintf(g_debug_log, "[INFO]  " __VA_ARGS__);                          \
      tui_debug_log(&g_tui, 2, __VA_ARGS__);                                   \
    }                                                                          \
  } while (0)
#define LOG_DEBUG(...)                                                         \
  do {                                                                         \
    if (g_cfg.log_level >= 2) {                                                \
      fprintf(stdout, "[DEBUG] " __VA_ARGS__);                                 \
      if (g_debug_log)                                                         \
        fprintf(g_debug_log, "[DEBUG] " __VA_ARGS__);                          \
      tui_debug_log(&g_tui, 3, __VA_ARGS__);                                   \
    }                                                                          \
  } while (0)
#define LOG_ERR(...)                                                           \
  do {                                                                         \
    fprintf(stderr, "[ERROR] " __VA_ARGS__);                                   \
    if (g_debug_log)                                                           \
      fprintf(g_debug_log, "[ERROR] " __VA_ARGS__);                            \
    tui_debug_log(&g_tui, 0, __VA_ARGS__);                                     \
  } while (0)

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
  if (!g_swarm_file[0])
    return;
  FILE *f = fopen(g_swarm_file, "w");
  if (!f)
    return;
  uv_mutex_lock(&g_swarm_lock);
  for (int i = 0; i < g_swarm_count; i++)
    fprintf(f, "%s\n", g_swarm_ips[i]);
  uv_mutex_unlock(&g_swarm_lock);
  fclose(f);
}

static void swarm_load(void) {
  if (!g_swarm_file[0])
    return;
  FILE *f = fopen(g_swarm_file, "r");
  if (!f)
    return;
  char ip[64];
  while (fgets(ip, sizeof(ip), f)) {
    /* trim newline */
    ip[strcspn(ip, "\r\n")] = '\0';
    if (ip[0])
      swarm_record_ip(ip);
  }
  fclose(f);
}

/* ────────────────────────────────────────────── */
/*  Session lookup / alloc                        */
/* ────────────────────────────────────────────── */

/* Find session by 8-bit session ID */
static int session_find_by_id(uint8_t id) {
  for (int i = 0; i < SRV_MAX_SESSIONS; i++)
    if (g_sessions[i].used && g_sessions[i].session_id == id)
      return i;
  return -1;
}

/* Allocate new session with 8-bit session ID */
static int session_alloc_by_id(uint8_t id) {
  for (int i = 0; i < SRV_MAX_SESSIONS; i++) {
    if (!g_sessions[i].used) {
      memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
      g_sessions[i].session_id = id;
      g_sessions[i].used = true;
      g_sessions[i].last_active = time(NULL);
      g_stats.active_sessions++;
      return i;
    }
  }
  return -1;
}

static void session_close(int idx) {
  srv_session_t *s = &g_sessions[idx];
  if (!s->used)
    return;
  if (s->tcp_connected && !uv_is_closing((uv_handle_t *)&s->upstream_tcp))
    uv_close((uv_handle_t *)&s->upstream_tcp, NULL);
  free(s->upstream_buf);
  s->upstream_buf = NULL;

  if (s->burst_symbols) {
    for (int i = 0; i < s->burst_count_needed; i++)
      free(s->burst_symbols[i]);
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
  uv_connect_t connect;
  int session_idx;
  uint8_t *payload;
  size_t payload_len;
  char target_host[256];
  uint16_t target_port;
} connect_req_t;

static void on_upstream_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf);
static void on_upstream_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf);
static void on_upstream_write(uv_write_t *w, int status);
static void on_upstream_connect(uv_connect_t *req, int status);
static void on_upstream_resolve(uv_getaddrinfo_t *resolver, int status,
                                struct addrinfo *res);

/* Write payload to upstream and then start reading responses */
static void upstream_write_and_read(int session_idx, const uint8_t *data,
                                    size_t len) {
  srv_session_t *s = &g_sessions[session_idx];
  if (!s->tcp_connected)
    return;

  uv_write_t *w = malloc(sizeof(*w) + len);
  if (!w)
    return;
  uint8_t *copy = (uint8_t *)(w + 1);
  memcpy(copy, data, len);
  w->data = w;
  uv_buf_t buf = uv_buf_init((char *)copy, (unsigned)len);
  uv_write(w, (uv_stream_t *)&s->upstream_tcp, &buf, 1, on_upstream_write);

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
    buf->len = 0;
    return;
  }
  buf->base = (char *)malloc(8192);
  buf->len = buf->base ? 8192 : 0;
}

static void on_upstream_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf) {
  int *sidx_ptr = s->data;
  int sidx = sidx_ptr ? *sidx_ptr : -1;
  if (sidx < 0) {
    free(buf->base);
    return;
  }
  srv_session_t *sess = &g_sessions[sidx];

  if (nread <= 0) {
    free(buf->base);
    session_close(sidx);
    return;
  }

  /* Check if this data starts with SOCKS5 reply signature (0x05 0x00 0x00 0x01).
   * The SOCKS5 reply is 10 bytes total and should NOT be sent through the DNS tunnel.
   * It's an internal protocol response that the client doesn't need.
   * Only the HTTP response data should go through the tunnel.
   * 
   * Format: VER(0x05) + REP(0x00) + RSV(0x00) + ATYP(0x01) + BND.ADDR(4 bytes) + BND.PORT(2 bytes) = 10 bytes
   */
  if (nread >= 4 && buf->base[0] == 0x05 && buf->base[1] == 0x00 && 
      buf->base[2] == 0x00 && buf->base[3] == 0x01) {
    LOG_DEBUG("Session %d: Received SOCKS5 reply (%zd bytes) - NOT sending to client via DNS tunnel\n",
              sidx, nread);
    /* SOCKS5 reply received - do NOT buffer or send through DNS tunnel.
     * The client already received/sends the ACK via optimistic mode.
     * Only HTTP response data should go through the tunnel. */
    free(buf->base);
    
    /* If there's also HTTP response data in this same read, buffer only the HTTP part */
    if (nread > 10) {
      size_t http_len = (size_t)nread - 10;
      size_t need = sess->upstream_len + http_len;
      if (need > sess->upstream_cap) {
        sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
        sess->upstream_cap = need + 8192;
      }
      memcpy(sess->upstream_buf + sess->upstream_len, buf->base + 10, http_len);
      sess->upstream_len += http_len;
      LOG_DEBUG("Session %d: Buffered %zu bytes of HTTP data after SOCKS5 reply\n", sidx, http_len);
    }
    
    g_stats.rx_total += (size_t)nread;
    g_stats.rx_bytes_sec += (size_t)nread;
    return;
  }

  /* Normal case: append HTTP response data to buffer for DNS tunnel */
  size_t need = sess->upstream_len + (size_t)nread;
  if (need > sess->upstream_cap) {
    sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
    sess->upstream_cap = need + 8192;
  }
  memcpy(sess->upstream_buf + sess->upstream_len, buf->base, (size_t)nread);
  sess->upstream_len += (size_t)nread;

  free(buf->base);

  g_stats.rx_total += (size_t)nread;
  g_stats.rx_bytes_sec += (size_t)nread;
}

/* Send a SOCKS5 status/ACK byte (0x00=success, 0x01-0x08=SOCKS5 errors) to the
 * client */
static void session_send_status(int sidx, uint8_t status) {
  srv_session_t *sess = &g_sessions[sidx];
  if (sess->status_sent)
    return;

  size_t need = sess->upstream_len + 1;
  if (need > sess->upstream_cap) {
    sess->upstream_buf = realloc(sess->upstream_buf, need + 8192);
    sess->upstream_cap = need + 8192;
  }

  if (sess->upstream_buf) {
    /* Prepend status byte if data already exists, though it should be empty */
    if (sess->upstream_len > 0) {
      memmove(sess->upstream_buf + 1, sess->upstream_buf, sess->upstream_len);
    }
    sess->upstream_buf[0] = status;
    sess->upstream_len++;
    /* Reset downstream_seq to 0 so the status byte is ALWAYS delivered at
     * seq=0, which the client's reorder buffer (expected_seq=0) can flush
     * immediately regardless of how many poll replies were sent before the
     * upstream connection completed. */
    /* Do NOT reset downstream_seq here. The status byte is delivered at
     * whatever downstream_seq is currently at. The client reorder buffer
     * (expected_seq) has been advancing with each empty poll reply, so the
     * status byte arrives at the correct next seq and is delivered without
     * gaps. Resetting to 0 caused the status byte to collide with the
     * handshake reply (also seq=0) and be dropped as a duplicate. */
    sess->status_sent = true;
    LOG_DEBUG("Session %d: queued SOCKS5 status %02x at downstream_seq=%u\n", sidx, status, sess->downstream_seq);
  }
}

static void on_upstream_resolve(uv_getaddrinfo_t *resolver, int status,
                                struct addrinfo *res) {
  connect_req_t *cr = (connect_req_t *)resolver->data;
  int sidx = cr->session_idx;
  srv_session_t *sess = &g_sessions[sidx];

  if (status != 0 || res == NULL) {
    LOG_ERR("DNS resolution failed for session %d (%s:%d): %s\n", sidx,
            cr->target_host, cr->target_port, uv_strerror(status));

    /* Map resolver errors to SOCKS5 codes */
    uint8_t socks_err = 0x04; /* Host unreachable by default */
    if (status == UV_EAI_NONAME)
      socks_err = 0x04;

    session_send_status(sidx, socks_err);
    free(cr->payload);
    free(cr);
    free(resolver);
    /* Don't close session immediately; let client receive the error byte */
    return;
  }

  /* Use the first resolved address (could be IPv4 or IPv6) */
  char addr_str[INET6_ADDRSTRLEN];
  if (res->ai_family == AF_INET) {
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
              addr_str, sizeof(addr_str));
  } else {
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
              addr_str, sizeof(addr_str));
  }

  LOG_INFO("DNS resolved %s:%d to %s for session %d\n", cr->target_host,
           cr->target_port, addr_str, sidx);

  /* Initiate TCP connection using the actual ai_addr (supports IPv6) */
  uv_tcp_connect(&cr->connect, &sess->upstream_tcp, res->ai_addr,
                 on_upstream_connect);

  uv_freeaddrinfo(res);
  free(resolver);
}

static void on_upstream_connect(uv_connect_t *req, int status) {
  connect_req_t *cr = (connect_req_t *)req;
  int sidx = cr->session_idx;
  srv_session_t *sess = &g_sessions[sidx];

  if (status != 0) {
    LOG_ERR("Upstream connect failed for session %d: %s\n", sidx,
            uv_strerror(status));

    /* Map connect errors to SOCKS5 codes */
    uint8_t socks_err = 0x01; /* General failure */
    if (status == UV_ECONNREFUSED)
      socks_err = 0x05;
    else if (status == UV_ETIMEDOUT)
      socks_err = 0x04;
    else if (status == UV_ENETUNREACH)
      socks_err = 0x03;

    session_send_status(sidx, socks_err);
    free(cr->payload);
    free(cr);
    /* Don't close session immediately; let client receive the error byte */
    return;
  }
  LOG_INFO("Upstream connected for session %d\n", sidx);

  sess->tcp_connected = true;
  static int sidx_store[SRV_MAX_SESSIONS];
  sidx_store[sidx] = sidx;
  sess->upstream_tcp.data = &sidx_store[sidx];

  uv_read_start((uv_stream_t *)&sess->upstream_tcp, on_upstream_alloc,
                on_upstream_read);

  if (cr->payload && cr->payload_len > 0)
    upstream_write_and_read(sidx, cr->payload, cr->payload_len);

  /* Queue SOCKS5 ACK byte (0x00=success) for next DNS response */
  session_send_status(sidx, 0x00);

  free(cr->payload);
  free(cr);
}

/* ────────────────────────────────────────────── */
/*  Build DNS TXT Reply                           */
/* ────────────────────────────────────────────── */

/* Encode data using configured downstream encoding (base64 by default) */
static size_t encode_downstream_data(char *out, const uint8_t *in,
                                     size_t inlen) {
  /* Use base64 encoding by default for better compatibility with intermediate
   * resolvers. Raw binary data often gets dropped or mangled by DNS
   * infrastructure. */
  if (g_cfg.downstream_encoding == 1) {
    /* Hex encoding (for debugging) */
    return hex_encode(out, in, inlen);
  }
  /* Default: base64 encoding for better DNS compatibility */
  return base64_encode(out, in, inlen);
}

static int build_txt_reply_with_seq(uint8_t *outbuf, size_t *outlen,
                                    uint16_t query_id, const char *qname,
                                    const uint8_t *data, size_t data_len,
                                    uint16_t mtu, uint16_t seq,
                                    uint8_t session_id) {
  /* [Fix] MTU Adjustment: Ensure the final Base64-encoded record
   * stays within the requested MTU limit (e.g. 220 characters).
   * Binary size = MTU * 3 / 4. */
  size_t overhead = 12 + strlen(qname) + 6 + 16 + 20;
  size_t safe_txt_len = (mtu > overhead + 64) ? (mtu - overhead) : 64;
  size_t max_packet_len = (safe_txt_len * 3) / 4;
  size_t binary_mtu = max_packet_len > 4 ? max_packet_len - 4 : 0;
  if (data_len > binary_mtu)
    data_len = binary_mtu;

  /* Build header with sequence number */
  server_response_header_t hdr = {0};
  hdr.session_id = session_id;
  hdr.flags = 0;                  /* base64 encoding (default) */
  hdr.flags |= RESP_FLAG_HAS_SEQ; /* Mark as sequenced */
  hdr.seq = seq;

  /* Build packet: header + payload */
  uint8_t packet[4096];
  size_t packet_len = 0;

  /* Copy header */
  memcpy(packet, &hdr, sizeof(hdr));
  packet_len += sizeof(hdr);

  /* Copy payload */
  if (data_len > 0 && data != NULL) {
    if (packet_len + data_len > sizeof(packet)) {
      data_len = sizeof(packet) - packet_len;
    }
    memcpy(packet + packet_len, data, data_len);
    packet_len += data_len;
  }

  /* Encode complete packet for TXT record */
  char encoded[4096];
  size_t encoded_len = encode_downstream_data(encoded, packet, packet_len);
  if (encoded_len >= sizeof(encoded))
    encoded_len = sizeof(encoded) - 1;
  encoded[encoded_len] = '\0';

  dns_question_t q = {0};
  q.name = qname;
  q.type = RR_TXT;
  q.class = CLASS_IN;

  dns_answer_t ans = {0};
  ans.txt.name = qname;
  ans.txt.type = RR_TXT;
  ans.txt.class = CLASS_IN;
  ans.txt.ttl = 0;
  ans.txt.len = (uint16_t)encoded_len;
  ans.txt.text = encoded;

  dns_query_t resp = {0};
  resp.id = query_id;
  resp.query = false;
  resp.rd = true;
  resp.ra = true;
  resp.qdcount = 1;
  resp.ancount = 1;
  resp.questions = &q;
  resp.answers = &ans;

  size_t sz = *outlen;
  dns_rcode_t rc = dns_encode((dns_packet_t *)outbuf, &sz, &resp);
  if (rc != RCODE_OKAY)
    return -1;
  *outlen = sz;
  return 0;
}

/* ────────────────────────────────────────────── */
/*  Main UDP receive handler                      */
/* ────────────────────────────────────────────── */
typedef struct {
  uv_udp_send_t send_req;
  struct sockaddr_in dest;
  uint8_t reply_buf[4096]; /* Larger buffer for EDNS0 / multi-RR replies */
  size_t reply_len;
} udp_reply_t;

static void on_udp_send_done(uv_udp_send_t *r, int status) {
  (void)status;
  udp_reply_t *rep = (udp_reply_t *)r;
  free(rep);
}

static void send_udp_reply(const struct sockaddr_in *dest, const uint8_t *data,
                           size_t len) {
  udp_reply_t *rep = malloc(sizeof(*rep));
  if (!rep)
    return;
  memcpy(&rep->dest, dest, sizeof(*dest));
  /* DEBUG: Log truncation if data exceeds buffer */
  if (len > sizeof(rep->reply_buf)) {
    fprintf(stderr,
            "[WARN] send_udp_reply: TRUNCATING %zu bytes to %zu (buffer too "
            "small!)\n",
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

static uint8_t s_recv_buf[65536];

static void on_server_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
  (void)h;
  (void)sz;
  buf->base = (char *)s_recv_buf;
  buf->len = sizeof(s_recv_buf);
}

static void on_server_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                           const struct sockaddr *addr, unsigned flags) {
  (void)h;
  (void)flags;
  if (nread <= 0 || !addr) {
    if (nread < 0) {
      LOG_ERR("UDP recv error: %zd\n", nread);
    }
    return;
  }

  const struct sockaddr_in *src = (const struct sockaddr_in *)addr;
  char src_ip[46];
  uv_inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
  g_stats.queries_recv++;

  /* Record source IP in swarm (src_ip already defined above) */
  swarm_record_ip(src_ip);

  /* Decode DNS query */
  dns_decoded_t decoded[DNS_DECODEBUF_4K];
  size_t decsz = sizeof(decoded);
  if (dns_decode(decoded, &decsz, (const dns_packet_t *)buf->base,
                 (size_t)nread) != RCODE_OKAY) {
    g_stats.queries_lost++;
    return;
  }

  dns_query_t *qry = (dns_query_t *)decoded;
  if (qry->qdcount < 1)
    return;

  const char *qname = qry->questions[0].name;
  uint16_t query_id = qry->id;
  uint16_t qtype = qry->questions[0].type;

  /* For non-TXT queries (e.g. Cloudflare QNAME minimization A probes):
   * Respond with NOERROR + empty answer (no records). This tells the resolver
   * "this name exists, but has no A record" - so it proceeds to send the actual
   * TXT query. Silently dropping these caused Cloudflare to never forward TXT. */
  if (qtype != RR_TXT) {
      LOG_DEBUG("Non-TXT query (qtype=%u) from %s for %s - sending NOERROR empty\n",
                qtype, src_ip, qname);
      /* Build a minimal DNS NOERROR response with 0 answers.
       * This tells Cloudflare's QNAME minimization: "name exists, no A record"
       * so it continues and sends the actual TXT query to us. */
      uint8_t noerr[512];
      /* DNS header (12 bytes): ID + flags + counts */
      noerr[0] = query_id >> 8; noerr[1] = query_id & 0xFF;
      noerr[2] = 0x84; noerr[3] = 0x00; /* QR=1 AA=1 RA=0 RCODE=NOERROR */
      noerr[4] = 0x00; noerr[5] = 0x01; /* QDCOUNT=1 */
      noerr[6] = 0x00; noerr[7] = 0x00; /* ANCOUNT=0 */
      noerr[8] = 0x00; noerr[9] = 0x00; /* NSCOUNT=0 */
      noerr[10] = 0x00; noerr[11] = 0x00; /* ARCOUNT=0 */
      /* Copy question section verbatim from the raw request */
      size_t q_len = (size_t)nread > 12 ? (size_t)nread - 12 : 0;
      if (q_len > sizeof(noerr) - 12) q_len = sizeof(noerr) - 12;
      memcpy(noerr + 12, buf->base + 12, q_len);
      send_udp_reply(src, noerr, 12 + q_len);
      return;
  }

  /* Parse QNAME: <payload>.<configured_domain>
   * No delimiter needed - server strips known domain suffix to extract payload.
   * The configured domain is in g_cfg.domains[0..g_cfg.domain_count-1].
   */
  char tmp[DNSTUN_MAX_QNAME_LEN + 1];
  strncpy(tmp, qname, sizeof(tmp) - 1);

  char *parts[16] = {0};
  int part_count = 0;
  char *tok = strtok(tmp, ".");
  while (tok && part_count < 16) {
    parts[part_count++] = tok;
    tok = strtok(NULL, ".");
  }

  /* Find domain suffix in QNAME to determine payload start.
   * Strategy: Try stripping domain labels from the end and check if remaining
   * parts look like valid base32 data (non-empty, starts with alphanumeric).
   * Use case-insensitive comparison (DNS is case-insensitive). */
  int domain_parts = 2; /* Default: assume domain like "example.com" */
  bool is_mtu_probe = false;
  bool is_crypto_probe = false;

  /* Try to match against configured domains first */
  for (int d = 0; d < g_cfg.domain_count; d++) {
    const char *domain = g_cfg.domains[d];
    char domain_tmp[256];
    strncpy(domain_tmp, domain, sizeof(domain_tmp) - 1);

    /* Parse domain into labels */
    char *domain_labels[8];
    int dparts = 0;
    char *dtok = strtok(domain_tmp, ".");
    while (dtok && dparts < 8) {
      domain_labels[dparts++] = dtok;
      dtok = strtok(NULL, ".");
    }

    /* Check if QNAME ends with this domain (last dparts labels) */
    if (part_count >= dparts) {
      bool match = true;
      for (int j = 0; j < dparts; j++) {
        const char *qpart = parts[part_count - dparts + j];
#ifdef _WIN32
        if (_stricmp(qpart, domain_labels[j]) != 0) {
#else
        if (strcasecmp(qpart, domain_labels[j]) != 0) {
#endif
          match = false;
          break;
        }
      }
      if (match) {
        domain_parts = dparts;
        break;
      }
    }
  }

  /* Ensure we don't strip more parts than exist */
  if (domain_parts > part_count - 1) { /* Keep at least 1 part for payload */
    domain_parts = part_count - 1;
  }

  /* payload_start_idx is where our data starts (everything before domain
   * suffix) */
  int payload_start_idx = part_count - domain_parts;

  /* Check for special probe formats in first label */
  if (payload_start_idx >= 1 && parts[0] != NULL) {
    const char *first_label = parts[0];
    if (strncmp(first_label, "mtu-req-", 8) == 0) {
      is_mtu_probe = true;
    } else if (strncmp(first_label, "CRYPTO_", 7) == 0) {
      is_crypto_probe = true;
    }
  }

  /* Handle MTU probe: mtu-req-[N].domain.com */
  if (is_mtu_probe && parts[0] != NULL) {
    /* Parse requested MTU size */
    int requested_mtu = atoi(parts[0] + 8);
    if (requested_mtu > 0 && requested_mtu <= 4096) {
      /* Generate random payload of requested size */
      uint8_t mtu_payload[4096];
      for (int i = 0; i < requested_mtu && i < (int)sizeof(mtu_payload); i++) {
        mtu_payload[i] = (uint8_t)(rand() & 0xFF);
      }

      /* Send response with MTU-sized payload */
      uint8_t reply[5120];
      size_t rlen = sizeof(reply);
      if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, mtu_payload,
                                   requested_mtu, 512, 0, 0) == 0) {
        send_udp_reply(src, reply, rlen);
      }
      return; /* MTU probe handled */
    }
  }

  /* Handle CRYPTO probe: CRYPTO_<nonce_hex>.domain.com */
  if (is_crypto_probe && parts[0] != NULL) {
    /* Extract nonce from CRYPTO_<nonce_hex> and echo it back signed */
    const char *nonce_hex = parts[0] + 7; /* Skip "CRYPTO_" */
    /* TODO: Server should sign this nonce with shared secret and echo back */
    /* For now, just echo the nonce back as-is to prove reachability */
    LOG_INFO("CRYPTO probe received: nonce=%s\n", nonce_hex);
    /* TODO: Implement challenge-response with HMAC signing */
    return; /* Placeholder - needs server-side signing implementation */
  }

  /* Normal tunnel traffic: extract b32 payload from parts[0 ..
   * payload_start_idx-1] CRITICAL: Do NOT add dots back - they were DNS label
   * separators, not part of base32 data! The client's inline_dotify adds dots
   * every 57 chars to split into DNS labels. When strtok parses the QNAME, dots
   * are removed as delimiters. We must concatenate parts WITHOUT dots to
   * reconstruct the original base32. */
  char b32_payload[512] = {0};
  for (int i = 0; i < payload_start_idx; i++) {
    strncat(b32_payload, parts[i],
            sizeof(b32_payload) - strlen(b32_payload) - 1);
  }

  LOG_INFO("DEBUG QNAME parse: qname='%s', parts=%d, domain_parts=%d, "
           "payload_start=%d, payload='%s'\n",
           qname, part_count, domain_parts, payload_start_idx, b32_payload);

  /* If no payload (empty query), ignore */
  if (b32_payload[0] == '\0' && !is_mtu_probe) {
    LOG_ERR("DEBUG: Empty payload after parsing QNAME, ignoring\n");
    return;
  }

  /* Decode b32 payload → raw bytes (chunk_header + data)
   * Increased to 512 to safely handle max-length Base32 QNAMEs (253 chars). */
  uint8_t raw[512];
  size_t b32_len = strlen(b32_payload);
  ssize_t rawlen = base32_decode(raw, b32_payload, b32_len);
  if (rawlen < (ssize_t)sizeof(chunk_header_t)) {
    LOG_ERR("Base32 decode failed from %s: ret=%zd, expected >=%zu\n", src_ip,
            rawlen, sizeof(chunk_header_t));
    return;
  }

  LOG_INFO("DEBUG decode: rawlen=%zd, sizeof(chunk_header_t)=%zu, "
           "first_bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
           rawlen, sizeof(chunk_header_t), raw[0], raw[1], raw[2], raw[3],
           raw[4], raw[5], raw[6], raw[7]);

  /* Parse extended 20-byte header with OTI for FEC decoding */
  chunk_header_t hdr;
  memcpy(&hdr, raw, sizeof(hdr));
  const uint8_t *payload = raw + sizeof(hdr);
  size_t payload_len = (size_t)(rawlen - (ssize_t)sizeof(hdr));

  LOG_INFO(
      "DEBUG header: session_id=%u, flags=0x%02x, seq=%u, chunk_info=0x%08x\n",
      hdr.session_id, hdr.flags, hdr.seq, hdr.chunk_info);
  LOG_INFO("DEBUG OTI: oti_common=0x%016llx, oti_scheme=0x%08x\n",
           (unsigned long long)hdr.oti_common, (unsigned int)hdr.oti_scheme);

  /* Extract fields from new 8-bit header */
  bool is_poll = (hdr.flags & CHUNK_FLAG_POLL) != 0;
  bool is_encrypted = (hdr.flags & CHUNK_FLAG_ENCRYPTED) != 0;
  bool is_sync = false;
  uint8_t session_id = chunk_get_session_id(&hdr);
  uint16_t seq = hdr.seq;

  /* chunk_info: high nibble = chunk_total-1, low nibble = fec_k */
  uint8_t chunk_total = chunk_get_total(hdr.chunk_info);
  uint8_t fec_k = chunk_get_fec_k(hdr.chunk_info);
  LOG_INFO(
      "DEBUG FEC: chunk_total=%u, fec_k=%u, flags=0x%02x, payload_len=%zu\n",
      chunk_total, fec_k, hdr.flags, payload_len);

  /* Extract capability header from payload (if present).
   * ONLY for non-FEC packets (chunk_total == 1). FEC data symbols do not carry
   * a capability header — the client sends them raw to avoid corrupting the
   * fixed-size (110-byte) FEC symbols with truncation. */
  uint16_t client_upstream_mtu = 0;
  uint16_t client_downstream_mtu = g_cfg.downstream_mtu; /* Default fallback */
  bool has_capability_header = false;
  if (chunk_total == 1 && payload_len >= sizeof(capability_header_t)) {
    capability_header_t cap;
    memcpy(&cap, payload, sizeof(cap));
    if (cap.version == DNSTUN_VERSION) {
      client_upstream_mtu = cap.upstream_mtu;
      client_downstream_mtu = cap.downstream_mtu;
      /* Skip capability header when processing payload */
      payload += sizeof(capability_header_t);
      payload_len -= sizeof(capability_header_t);
      has_capability_header = true;
      LOG_DEBUG("Got capability header: upstream=%u, downstream=%u, enc=%u, "
                "loss=%u%%\n",
                client_upstream_mtu, client_downstream_mtu, cap.encoding,
                cap.loss_pct);
    }
  }

  /* SYNC command: payload starts with "SYNC" (ASCII) */
  if (payload_len >= 4 && memcmp(payload, "SYNC", 4) == 0)
    is_sync = true;

  /* Handshake detection: version matches and length is correct */
  bool is_handshake = (payload_len == 5 && payload[0] == DNSTUN_VERSION);

  /* DEBUG packet: payload starts with standardized test prefix - echo back
   * through normal pipeline */
  bool is_debug =
      (payload_len >= strlen(DNSTUN_DEBUG_PREFIX) &&
       memcmp(payload, DNSTUN_DEBUG_PREFIX, strlen(DNSTUN_DEBUG_PREFIX)) == 0);
  LOG_INFO("DEBUG check: payload_len=%zu, is_debug=%d, session_id=%u, seq=%u\n",
           payload_len, is_debug, session_id, seq);
  if (is_debug) {
    /* Echo the payload back through the normal response path */
    uint8_t reply[512];
    size_t rlen = sizeof(reply);
    if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, payload,
                                 payload_len, 512, 0, session_id) == 0) {
      send_udp_reply(src, reply, rlen);
    }
    return; /* Don't process further - no session setup or upstream forwarding
             */
  }

  /* Session lookup / allocate by 4-bit session ID */
  int sidx = session_find_by_id(session_id);
  if (sidx < 0) {
    sidx = session_alloc_by_id(session_id);
    if (sidx < 0) {
      LOG_ERR("Session table full\n");
      return;
    }
    LOG_INFO("New session created: idx=%d, sid=%u, is_poll=%d, is_sync=%d, "
             "payload_len=%zu\n",
             sidx, session_id, is_poll, is_sync, payload_len);
  }

  srv_session_t *sess = &g_sessions[sidx];
  sess->last_active = time(NULL);
  sess->client_addr = *src;

  /* MTU values: use client-provided capability header, fallback to config */
  if (client_downstream_mtu > 0) {
    sess->cl_downstream_mtu = client_downstream_mtu;
  } else {
    sess->cl_downstream_mtu = g_cfg.downstream_mtu;
  }
  sess->cl_enc_format = 0; /* Will be determined by client request */
  sess->cl_loss_pct = 0;
  /* Store fec_k from current packet header for reference.
   * This is the redundancy count r; the actual k is derived per burst from OTI.
   * Do NOT overwrite with an adaptive formula — that corrupts k_est for the
   * burst. */
  sess->cl_fec_k = fec_k;

  /* Handle handshake MTU signaling */
  if (is_handshake) {
    handshake_packet_t hs;
    memcpy(&hs, payload, sizeof(hs));
    /* Only accept reasonable MTU values (min 128, max 4096) */
    if (hs.downstream_mtu >= 128 && hs.downstream_mtu <= 4096) {
      sess->cl_downstream_mtu = hs.downstream_mtu;
      LOG_INFO("Session %d: MTU handshake - Up=%u, Down=%u\n", sidx,
               hs.upstream_mtu, hs.downstream_mtu);
    }
    /* Reset the downstream sequence counter so the MTU-handshake reply
     * and all following data start at seq=0 — exactly what the client's
     * reorder buffer expects after it sends the capability/handshake. */
    sess->downstream_seq = 0;
    sess->handshake_done = true;
    LOG_INFO("Session %d: downstream_seq reset to 0 on handshake, handshake_done=true\n", sidx);
  }

  /* ── Handle FEC Burst Reassembly ──────────────────────────────────── */
  if (chunk_total > 1) {
    /* chunk_total > 1 means we have FEC data (k+r where r > 0)
     * chunk_total = 1 means no FEC, just a single packet */

    /* ESI (Encoding Symbol ID) = seq % chunk_total.
     * All symbols in a single FEC block share the same burst_base_seq =
     * seq - ESI, independent of arrival order. This correctly groups all
     * chunk_total symbols into one burst accumulator regardless of which
     * symbol arrives first. Previously, burst_seq_start was set to the
     * first-received seq, causing each later symbol to appear as a new burst
     * when its offset relative to the first-received seq exceeded chunk_total. */
    uint16_t esi = (uint16_t)(seq % (uint16_t)chunk_total);
    uint16_t burst_base_seq = (uint16_t)(seq - esi);
    bool is_new_burst = (sess->burst_count_needed == 0) ||
                        (burst_base_seq != sess->burst_seq_start) ||
                        (chunk_total != (uint16_t)sess->burst_count_needed);

    if (is_new_burst) {
      /* Cleanup old burst */
      if (sess->burst_symbols) {
        for (int i = 0; i < sess->burst_count_needed; i++)
          free(sess->burst_symbols[i]);
        free(sess->burst_symbols);
        sess->burst_symbols = NULL;
      }
      sess->burst_seq_start = burst_base_seq;
      sess->burst_count_needed = chunk_total;
      /* fec_k = r (number of repair symbols). K source symbols = total - r. */
      sess->cl_fec_k = fec_k;
      sess->burst_received = 0;
      sess->burst_symbols = calloc(chunk_total, sizeof(uint8_t *));
      sess->burst_symbol_len = payload_len;
      sess->burst_oti_common = hdr.oti_common;
      sess->burst_oti_scheme = hdr.oti_scheme;
      sess->burst_has_oti = (hdr.oti_common != 0 && hdr.oti_scheme != 0);
      sess->burst_decoded = false;
      LOG_INFO("FEC burst start: base_seq=%u esi=%u total=%u fec_k(r)=%u OTI common=0x%llx "
               "scheme=0x%x has_oti=%d\n",
               burst_base_seq, esi, chunk_total, fec_k,
               (unsigned long long)sess->burst_oti_common,
               sess->burst_oti_scheme, sess->burst_has_oti);
    }

    /* Store symbol at its ESI slot within the burst buffer */
    if (esi < (uint16_t)sess->burst_count_needed &&
        sess->burst_symbols && !sess->burst_symbols[esi]) {
      sess->burst_symbols[esi] = malloc(payload_len);
      if (sess->burst_symbols[esi]) {
        memcpy(sess->burst_symbols[esi], payload, payload_len);
        sess->burst_received++;
      }
    }

    /* K = source symbols needed to decode. fec_k from the chunk header IS K
     * (not the repair count r). chunk_total = K + r. So r = chunk_total - K.
     * The server must accumulate K symbols before decoding. */
    int k_est = (int)sess->cl_fec_k; /* K source symbols */
    if (k_est < 1)
      k_est = 1;
    /* Clamp to total (can't need more than total symbols) */
    if (k_est > sess->burst_count_needed)
      k_est = sess->burst_count_needed;

    LOG_INFO("FEC burst status: received=%d need=%d (total=%d r=%d base_seq=%u esi=%u)\n",
             sess->burst_received, k_est, sess->burst_count_needed,
             sess->cl_fec_k, burst_base_seq, esi);

    if (sess->burst_received >= k_est) {
      /* Guard: skip re-decoding if this burst was already decoded and
       * forwarded upstream. With k=1 (single-symbol RaptorQ), every one of
       * the r redundant chunks independently satisfies burst_received>=k_est,
       * which without this gate causes 10+ duplicate decodes that burn
       * downstream_seq slots before any client poll can receive them. */
      if (sess->burst_decoded) {
        LOG_DEBUG("FEC burst seq=%u already decoded, discarding duplicate symbol\n",
                  sess->burst_seq_start);
        goto skip_fec_processing;
      }
      LOG_INFO("DEBUG FEC: Starting decode with %d symbols (need %d)\n",
               sess->burst_received, k_est);
      /* Mark this burst as decoded NOW to prevent re-entry on subsequent
       * symbol arrivals. Without this, each new symbol would re-trigger
       * a decode (since burst_decoded was only set on SOCKS5 success path). */
      sess->burst_decoded = true;
      fec_encoded_t fec = {0};
      fec.symbols = sess->burst_symbols;
      fec.symbol_len = sess->burst_symbol_len;
      fec.total_count = sess->burst_count_needed;
      fec.k_source = k_est;
      fec.oti_common = sess->burst_oti_common;
      fec.oti_scheme = sess->burst_oti_scheme;
      fec.has_oti = sess->burst_has_oti;

      LOG_INFO("DEBUG FEC: has_oti=%d, using codec_fec_decode_oti\n",
               fec.has_oti);

      codec_result_t fdec;
      if (fec.has_oti) {
        /* Use OTI-based decoding - this handles size automatically */
        fdec = codec_fec_decode_oti(&fec);
      } else {
        /* Fallback to size-based decoding */
        size_t orig_len_est = sess->burst_symbol_len;
        LOG_INFO(
            "DEBUG FEC: no OTI, using legacy decode with orig_len_est=%zu\n",
            orig_len_est);
        fdec = codec_fec_decode(&fec, orig_len_est);
      }
      LOG_INFO("DEBUG FEC: decode result: error=%d, len=%zu\n", fdec.error,
               fdec.len);
      if (!fdec.error) {
        const uint8_t *dec_in = fdec.data;
        size_t dec_len = fdec.len;
        codec_result_t dret = {0};

        /* 1. DECRYPT (Optional) */
        if (is_encrypted) {
          dret = codec_decrypt(fdec.data, fdec.len, g_cfg.psk);
          if (!dret.error) {
            dec_in = dret.data;
            dec_len = dret.len;
          } else {
            LOG_ERR("Decryption failed\n");
            codec_free_result(&fdec);
            /* Don't reset burst - let more symbols arrive */
            goto skip_fec_processing;
          }
        }

        /* 2. DECOMPRESS (0 = auto-detect size via decompress_bound) */
        codec_result_t zdec = codec_decompress(dec_in, dec_len, 0);
        LOG_INFO("DEBUG DECOMPRESS: result: error=%d, len=%zu\n", zdec.error,
                 zdec.len);
        if (!zdec.error) {
          /* Strip 4-byte anti-cache nonce prepended by the client before
           * compression. The nonce makes each FEC burst's QNAME unique,
           * preventing DNS resolver caching of repeated SOCKS5 connections. */
          const uint8_t *p = zdec.data;
          size_t l = zdec.len;
          if (l >= 4) {
            p += 4;
            l -= 4;
            LOG_INFO("DEBUG NONCE: stripped 4-byte nonce, remaining=%zu\n", l);
          } else {
            LOG_ERR("DEBUG NONCE: payload too short (%zu) to strip nonce\n", l);
            codec_free_result(&zdec);
            goto skip_fec_processing;
          }

          /* SUCCESS: Forward reassembled, decrypted, decompressed packet */
          if (!sess->tcp_connected) {
            /* Fix #11: SOCKS5 CONNECT is parsed ONLY from the fully
               decompressed + decrypted data.  The duplicate raw-payload
               parse path below is removed to avoid inconsistency. */
            if (l >= 10 && p[0] == 0x05 && p[1] == 0x01) {
              char target_host[256] = {0};
              uint16_t target_port = 0;
              uint8_t atype = p[3];

              if (atype == 0x01) { /* IPv4 */
                snprintf(target_host, sizeof(target_host), "%d.%d.%d.%d", p[4],
                         p[5], p[6], p[7]);
                target_port = (uint16_t)((p[8] << 8) | p[9]);
              } else if (atype == 0x03) { /* Domain */
                uint8_t dlen = p[4];
                /* Fix #5: bounds check before reading domain bytes */
                if ((size_t)(5 + dlen + 2) <= l && dlen < 255) {
                  memcpy(target_host, p + 5, dlen);
                  target_host[dlen] = '\0';
                  target_port = (uint16_t)((p[5 + dlen] << 8) | p[6 + dlen]);
                }
              } else if (atype == 0x04) { /* IPv6 */
                if (l >= 22) {
                  inet_ntop(AF_INET6, p + 4, target_host, sizeof(target_host));
                  target_port = (uint16_t)((p[20] << 8) | p[21]);
                }
              }

              if (target_host[0] && target_port > 0) {
                connect_req_t *cr = calloc(1, sizeof(*cr));
                cr->session_idx = sidx;
                strncpy(cr->target_host, target_host,
                        sizeof(cr->target_host) - 1);
                cr->target_port = target_port;
                /* SOCKS5 header sizes:
                 * - IPv4 (0x01): VER(1) + CMD(1) + RSV(1) + ATYP(1) + IP(4) +
                 * PORT(2) = 10 bytes
                 * - Domain (0x03): VER(1) + CMD(1) + RSV(1) + ATYP(1) + DLEN(1)
                 * + DOMAIN(dlen) + PORT(2) = 7 + dlen bytes
                 * - IPv6 (0x04): VER(1) + CMD(1) + RSV(1) + ATYP(1) + IP(16) +
                 * PORT(2) = 22 bytes
                 */
                size_t hdr_sz;
                if (atype == 0x01) {
                  hdr_sz = 10; /* IPv4 */
                } else if (atype == 0x03) {
                  hdr_sz = 7 + p[4]; /* Domain: 7 bytes + domain length */
                } else if (atype == 0x04) {
                  hdr_sz = 22; /* IPv6 */
                } else {
                  hdr_sz = l; /* Unknown, treat all as header */
                }
                if (l > hdr_sz) {
                  cr->payload_len = l - hdr_sz;
                  cr->payload = malloc(cr->payload_len);
                  memcpy(cr->payload, p + hdr_sz, cr->payload_len);
                }
                LOG_INFO("Connecting upstream for session %d to %s:%d "
                         "(hdr_sz=%zu, payload_len=%zu)\n",
                         sidx, target_host, target_port, hdr_sz,
                         cr->payload_len);

                sess->burst_decoded = true;
                uv_tcp_init(g_loop, &sess->upstream_tcp);
                /* Enable TCP_NODELAY to minimize latency for interactive
                 * traffic */
                uv_tcp_nodelay(&sess->upstream_tcp, 1);

                /* For domain names, use DNS resolution; for IPs, connect
                 * directly */
                if (atype == 0x03) {
                  /* Domain name - need to resolve */
                  struct addrinfo hints = {0};
                  hints.ai_family = AF_UNSPEC; /* Allow both IPv4 and IPv6 */
                  hints.ai_socktype = SOCK_STREAM;
                  char port_str[6];
                  snprintf(port_str, sizeof(port_str), "%d", target_port);
                  uv_getaddrinfo_t *resolver = malloc(sizeof(*resolver));
                  resolver->data = cr;
                  int r = uv_getaddrinfo(g_loop, resolver, on_upstream_resolve,
                                         target_host, port_str, &hints);
                  if (r != 0) {
                    LOG_ERR("Failed to start DNS resolution for %s:%d\n",
                            target_host, target_port);
                    free(resolver);
                    free(cr);
                  }
                } else if (atype == 0x01) {
                  /* IPv4 address - use getaddrinfo for robustness (handles
                   * invalid IPs gracefully) */
                  struct addrinfo hints = {0};
                  hints.ai_family = AF_INET; /* IPv4 only */
                  hints.ai_socktype = SOCK_STREAM;
                  char port_str[6];
                  snprintf(port_str, sizeof(port_str), "%d", target_port);
                  uv_getaddrinfo_t *resolver = malloc(sizeof(*resolver));
                  resolver->data = cr;
                  int r = uv_getaddrinfo(g_loop, resolver, on_upstream_resolve,
                                         target_host, port_str, &hints);
                  if (r != 0) {
                    LOG_ERR("Failed to resolve IPv4 address %s:%d\n",
                            target_host, target_port);
                    free(resolver);
                    free(cr);
                  }
                } else if (atype == 0x04) {
                  /* IPv6 address - use getaddrinfo for robustness */
                  struct addrinfo hints = {0};
                  hints.ai_family = AF_INET6; /* IPv6 only */
                  hints.ai_socktype = SOCK_STREAM;
                  char port_str[6];
                  snprintf(port_str, sizeof(port_str), "%d", target_port);
                  uv_getaddrinfo_t *resolver = malloc(sizeof(*resolver));
                  resolver->data = cr;
                  int r = uv_getaddrinfo(g_loop, resolver, on_upstream_resolve,
                                         target_host, port_str, &hints);
                  if (r != 0) {
                    LOG_ERR("Failed to resolve IPv6 address %s:%d\n",
                            target_host, target_port);
                    free(resolver);
                    free(cr);
                  }
                } else {
                  /* Unknown address type - reject */
                  LOG_ERR("Unknown SOCKS5 address type: %d for %s:%d\n", atype,
                          target_host, target_port);
                  free(cr);
                }
              }
            }
          } else {
            /* Session already connected — forward decompressed payload (minus
             * the 4-byte anti-cache nonce already stripped into p/l above). */
            upstream_write_and_read(sidx, p, l);
          }
          codec_free_result(&zdec);
        } else {
          codec_free_result(&zdec);
        }

        if (!dret.error && dret.data)
          codec_free_result(&dret);
        codec_free_result(&fdec);

        /* SUCCESS: Reset burst after successful decode */
        goto reset_burst;
      }

      /* FEC decode failed - don't reset burst, wait for more symbols */
      codec_free_result(&fdec);
      goto skip_fec_processing;

    reset_burst:
      /* Reset burst after successful processing */
      for (int i = 0; i < sess->burst_count_needed; i++)
        free(sess->burst_symbols[i]);
      free(sess->burst_symbols);
      sess->burst_symbols = NULL;
      sess->burst_count_needed = 0;
      sess->burst_received = 0;
      sess->burst_has_oti = false;
      sess->burst_oti_common = 0;
      sess->burst_oti_scheme = 0;

    skip_fec_processing:; /* Empty statement for label */
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
      slen += (size_t)snprintf(swarm_text + slen, sizeof(swarm_text) - slen,
                               "%s,", g_swarm_ips[i]);
    }
    uv_mutex_unlock(&g_swarm_lock);

    uint8_t reply[4096];
    size_t rlen = sizeof(reply);
    /* SWARM reply: only advance seq if handshake already done */
    uint16_t swarm_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
    if (build_txt_reply_with_seq(
            reply, &rlen, query_id, qname, (const uint8_t *)swarm_text, slen,
            sess->cl_downstream_mtu, swarm_seq,
            sess->session_id) == 0) {
      send_udp_reply(src, reply, rlen);
    }
    return;
  }

  /* ── Forward payload to upstream (non-FEC path) ──────────────── */
  /* Fix #11: Only forward to already-connected sessions. SOCKS5 CONNECT
     must arrive via the FEC+decompress path to be decoded correctly. */
  if (!is_poll && payload_len > 0 && sess->tcp_connected) {
    upstream_write_and_read(sidx, payload, payload_len);
  }

  /* ── Build reply — stuff any pending upstream data ───────────── */
  uint8_t reply[4096];
  size_t rlen = sizeof(reply);
  uint16_t mtu = sess->cl_downstream_mtu;
  if (mtu < 16 || mtu > 4096)
    mtu = 512;

  if (sess->upstream_len > 0) {
    /* Calculate exact safe capacity to prevent data drop */
    size_t overhead = 12 + strlen(qname) + 6 + 16 + 20;
    size_t safe_txt_len = (mtu > overhead + 64) ? (mtu - overhead) : 64;
    size_t max_packet_len = (safe_txt_len * 3) / 4;
    size_t binary_mtu = max_packet_len > 4 ? max_packet_len - 4 : 0;
    size_t sz = sess->upstream_len;
    if (sz > binary_mtu)
      sz = binary_mtu;

    /* DEBUG: Log upstream data being sent */
    fprintf(stderr,
            "[DEBUG] Server sending: upstream_len=%zu sz=%zu mtu=%u "
            "reply_buf=%zu\n",
            sess->upstream_len, sz, mtu, sizeof(reply));

    /* Only advance downstream_seq if the client has completed the MTU
     * handshake (has_capability_header). Pre-handshake probe polls get seq=0
     * without consuming a slot so the MTU-handshake reply is always seq=0. */
    uint16_t out_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
    if (build_txt_reply_with_seq(
            reply, &rlen, query_id, qname, sess->upstream_buf, sz, mtu,
            out_seq, sess->session_id) == 0) {
      /* Save to retransmit slot BEFORE consuming from upstream_buf */
      if (sz <= sizeof(sess->retx_buf)) {
        memcpy(sess->retx_buf, sess->upstream_buf, sz);
        sess->retx_len = sz;
        sess->retx_seq = out_seq;
      }
      /* Shift consumed bytes out of upstream buffer */
      memmove(sess->upstream_buf, sess->upstream_buf + sz,
              sess->upstream_len - sz);
      sess->upstream_len -= sz;
      send_udp_reply(src, reply, rlen);
    }
  } else if (sess->retx_len > 0) {
    /* upstream_buf is empty but we have a retransmit slot — the previous
     * reply at retx_seq may have been dropped by DNS. Re-send it at the
     * SAME seq (do NOT advance downstream_seq) so the client's reorder
     * buffer can fill the gap. Once new upstream data appears, the retx
     * slot is overwritten and downstream_seq advances normally. */
    fprintf(stderr,
            "[DEBUG] Server retransmitting seq=%u len=%zu\n",
            sess->retx_seq, sess->retx_len);
    if (build_txt_reply_with_seq(
            reply, &rlen, query_id, qname, sess->retx_buf, sess->retx_len,
            mtu, sess->retx_seq, sess->session_id) == 0) {
      send_udp_reply(src, reply, rlen);
    }
  } else {
    /* Empty reply — acknowledge the query with NO payload */
    uint16_t out_seq = sess->handshake_done ? sess->downstream_seq++ : 0;
    if (build_txt_reply_with_seq(reply, &rlen, query_id, qname, NULL, 0, mtu,
                                 out_seq, sess->session_id) == 0)
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
    if (!s->used)
      continue;
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
    if (g_sessions[i].used)
      n++;
  g_stats.active_sessions = n;

  uv_mutex_lock(&g_swarm_lock);
  g_stats.active_resolvers = g_swarm_count;
  uv_mutex_unlock(&g_swarm_lock);

  tui_render(&g_tui);

  /* Broadcast telemetry to connected management clients */
  if (g_mgmt) {
    mgmt_broadcast_telemetry(g_mgmt, &g_stats);
  }
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
      uv_ip4_name(&g_sessions[i].client_addr, out[count].ip,
                  sizeof(out[count].ip));
      out[count].downstream_mtu = g_sessions[i].cl_downstream_mtu;
      out[count].loss_pct = g_sessions[i].cl_loss_pct;
      out[count].fec_k = g_sessions[i].cl_fec_k;
      out[count].enc_format = g_sessions[i].cl_enc_format;
      out[count].idle_sec = (uint32_t)(now - g_sessions[i].last_active);
      strncpy(out[count].user_id, g_sessions[i].user_id,
              sizeof(out[count].user_id) - 1);
      out[count].user_id[sizeof(out[count].user_id) - 1] = '\0';
      count++;
    }
  }
  return count;
}

/* ────────────────────────────────────────────── */
/*  TUI Input (TTY)                               */
/* ────────────────────────────────────────────── */
static uv_tty_t g_tty;

static void on_tty_alloc(uv_handle_t *handle, size_t suggested_size,
                         uv_buf_t *buf) {
  (void)handle;
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

static void on_tty_read(uv_stream_t *stream, ssize_t nread,
                        const uv_buf_t *buf) {
  (void)stream;
  if (nread > 0) {
    for (ssize_t i = 0; i < nread; i++) {
      tui_handle_key(&g_tui, buf->base[i]);
      if (!g_tui.running)
        uv_stop(g_loop);
    }
  }
  if (buf->base)
    free(buf->base);
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
  char bind_ip[64] = "0.0.0.0";
  int bind_port = 53;
  char tmp[64];
  char *colon;
  struct sockaddr_in srv_addr;
  int r;
  static resolver_pool_t dummy_pool;

  /* Parse arguments */
  for (int i = 1; i < argc; i++) {
    if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) &&
        i + 1 < argc) {
      config_path = argv[i + 1];
      break;
    }
  }

  if (!config_path) {
    /* Auto-locate server.ini */
    const char *candidates[] = {"server.ini", "../server.ini",
                                "../../server.ini", "../../../server.ini",
                                "/etc/dnstun/server.ini"};
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
      char exe_path[2048];
      size_t size = sizeof(exe_path);
      if (uv_exepath(exe_path, &size) == 0) {
        char *eslash = strrchr(exe_path, '/');
#ifdef _WIN32
        char *ebslash = strrchr(exe_path, '\\');
        if (ebslash > eslash)
          eslash = ebslash;
#endif
        if (eslash) {
          *eslash = '\0';
          const char *rel[] = {"", "/..", "/../..", "/../../.."};
          for (int i = 0; i < 4; i++) {
            int written = snprintf(auto_config_path, sizeof(auto_config_path),
                                   "%s%s/server.ini", exe_path, rel[i]);
            if (written < 0 || written >= (int)sizeof(auto_config_path)) {
              continue; /* Path too long or error */
            }
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
    if (!config_path)
      config_path = "server.ini";
  }

  if (config_path && config_path != auto_config_path) {
    strncpy(auto_config_path, config_path, sizeof(auto_config_path) - 1);
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
  if (g_cfg.domain_count == 0 ||
      (g_cfg.domain_count == 1 &&
       strcmp(g_cfg.domains[0], "tun.example.com") == 0)) {
    printf("\n  No tunnel domain configured (or default tun.example.com is in "
           "use).\n");
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
      fprintf(stderr, "[WARN] No domain configured. Server will accept queries "
                      "for any domain.\n");
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
  strncpy(g_swarm_file, config_path, sizeof(g_swarm_file) - 1);
  slash = strrchr(g_swarm_file, '/');
#ifdef _WIN32
  bslash = strrchr(g_swarm_file, '\\');
  if (bslash > slash)
    slash = bslash;
#endif
  if (slash)
    strncpy(slash + 1, "server_resolvers.txt",
            sizeof(g_swarm_file) - (slash - g_swarm_file) - 1);
  else
    strcpy(g_swarm_file, "server_resolvers.txt");

  uv_mutex_init(&g_swarm_lock);
  if (g_cfg.swarm_save_disk)
    swarm_load();

  /* Parse bind address */
  if (g_cfg.server_bind[0]) {
    strncpy(tmp, g_cfg.server_bind, sizeof(tmp) - 1);
    colon = strrchr(tmp, ':');
    if (colon) {
      *colon = '\0';
      bind_port = atoi(colon + 1);
      strncpy(bind_ip, tmp, sizeof(bind_ip) - 1);
    }
  }

  /* Bind UDP port 53 */
  uv_ip4_addr(bind_ip, bind_port, &srv_addr);
  uv_udp_init(g_loop, &g_udp_server);
  r = uv_udp_bind(&g_udp_server, (const struct sockaddr *)&srv_addr,
                  UV_UDP_REUSEADDR);
  if (r != 0) {
    LOG_ERR("Cannot bind UDP %s:%d — %s\n", bind_ip, bind_port, uv_strerror(r));
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
  uv_timer_init(g_loop, &g_idle_timer);
  uv_timer_start(&g_idle_timer, on_idle_timer, 1000, 1000);

  uv_timer_init(g_loop, &g_tui_timer);
  uv_timer_start(&g_tui_timer, on_tui_timer, 1000, 1000);

  /* Management server for headless TUI connections */
  {
    mgmt_config_t mgmt_cfg = {0};
    strncpy(mgmt_cfg.bind_addr, "127.0.0.1", sizeof(mgmt_cfg.bind_addr) - 1);
    mgmt_cfg.port = 9090;
    mgmt_cfg.telemetry_interval_ms = 1000;
    mgmt_cfg.callbacks.on_connect = NULL;
    mgmt_cfg.callbacks.on_disconnect = NULL;
    mgmt_cfg.callbacks.on_command = NULL;
    g_mgmt = mgmt_server_create(g_loop, &mgmt_cfg);
    if (g_mgmt) {
      mgmt_server_start(g_mgmt);
      LOG_INFO("  Management : 127.0.0.1:9090 (connect TUI here)\n");
    }
  }

  LOG_INFO("dnstun-server listening on %s:%d\n", bind_ip, bind_port);
  LOG_INFO("  Workers  : %d\n", g_cfg.workers);
  LOG_INFO("  Swarm    : %d known resolvers\n", g_swarm_count);
  LOG_INFO("  Swarm serve: %s\n", g_cfg.swarm_serve ? "yes" : "no");

  /* Bind STDIN */
  uv_tty_init(g_loop, &g_tty, 0, 1);
  uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
  uv_read_start((uv_stream_t *)&g_tty, on_tty_alloc, on_tty_read);

  uv_run(g_loop, UV_RUN_DEFAULT);

  tui_shutdown(&g_tui);
  if (g_cfg.swarm_save_disk)
    swarm_save();

  uv_mutex_destroy(&g_swarm_lock);
  codec_pool_shutdown(); /* Shutdown buffer pool */

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
