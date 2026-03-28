#pragma once
#ifndef DNSTUN_MGMT_PROTOCOL_H
#define DNSTUN_MGMT_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ──────────────────────────────────────────────
   Management Protocol - Frame-Based Communication
   
   This protocol enables decoupled TUI/Core architecture:
   - Core runs headless with a management server
   - TUI connects via TCP socket (127.0.0.1:9090) or Unix socket
   - Telemetry flows: Core → TUI (periodic stats updates)
   - Commands flow: TUI → Core (admin actions)
 ────────────────────────────────────────────── */

/* Protocol Constants */
#define MGMT_PROTOCOL_VERSION  1
#define MGMT_MAGIC             0x444E5354  /* 'DNST' */
#define MGMT_DEFAULT_PORT      9090
#define MGMT_MAX_CLIENTS       16

/* Frame Types */
typedef enum {
    MGMT_FRAME_HELLO          = 0x01,  /* Initial handshake */
    MGMT_FRAME_TELEMETRY      = 0x02,  /* Core → TUI: periodic stats */
    MGMT_FRAME_COMMAND        = 0x03,  /* TUI → Core: admin command */
    MGMT_FRAME_RESPONSE      = 0x04,  /* Core → TUI: command result */
    MGMT_FRAME_GOODBYE        = 0x05,  /* Graceful disconnect */
    MGMT_FRAME_PING           = 0x06,  /* Keepalive */
    MGMT_FRAME_PONG           = 0x07   /* Keepalive response */
} mgmt_frame_type_t;

/* Command Types (TUI → Core) */
typedef enum {
    MGMT_CMD_NOOP             = 0x00,  /* No-op for keepalive testing */
    MGMT_CMD_GET_STATS        = 0x01,  /* Request immediate telemetry */
    MGMT_CMD_GET_CONFIG       = 0x02,  /* Get current configuration */
    MGMT_CMD_SET_CONFIG       = 0x03,  /* Set configuration value */
    MGMT_CMD_TOGGLE_ENCRYPTION= 0x10,  /* Toggle encryption on/off */
    MGMT_CMD_SET_BANDWIDTH_LIMIT= 0x11, /* Set bandwidth limit */
    MGMT_CMD_CLOSE_SESSION    = 0x20,  /* Close specific session */
    MGMT_CMD_CLOSE_ALL_SESSIONS= 0x21, /* Close all sessions */
    MGMT_CMD_FLUSH_LOGS       = 0x30,  /* Flush log buffer */
    MGMT_CMD_SHUTDOWN         = 0xFF   /* Shutdown core (dangerous!) */
} mgmt_command_type_t;

/* Response Status Codes */
typedef enum {
    MGMT_OK                   = 0x00,
    MGMT_ERR_INVALID_CMD      = 0x01,
    MGMT_ERR_INVALID_PAYLOAD  = 0x02,
    MGMT_ERR_PERMISSION       = 0x03,
    MGMT_ERR_NOT_FOUND        = 0x04,
    MGMT_ERR_INTERNAL         = 0xFF
} mgmt_status_t;

/* ──────────────────────────────────────────────
   Frame Header (12 bytes - common to all frames)
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint32_t  magic;          /* MGMT_MAGIC for validation */
    uint16_t  version;       /* Protocol version */
    uint16_t  frame_type;    /* Frame type enum */
    uint32_t  length;        /* Payload length (excluding header) */
    uint32_t  sequence;     /* Monotonic sequence number */
} mgmt_frame_header_t;
#pragma pack(pop)

#define MGMT_FRAME_HEADER_SIZE  sizeof(mgmt_frame_header_t)

/* ──────────────────────────────────────────────
   HELLO Frame (Client → Server on connect)
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    mgmt_frame_header_t header;
    
    /* Client info */
    uint8_t   client_type;   /* 0=TUI, 1=API client, 2=web proxy */
    uint8_t   client_version_major;
    uint8_t   client_version_minor;
    uint8_t   reserved;
    
    /* Client capabilities (bitfield) */
    uint32_t  capabilities;   /* 0x01=JSON mode, 0x02=binary mode */
    
    /* Auth token (optional, for multi-user scenarios) */
    uint8_t   auth_token[32];
} mgmt_hello_frame_t;
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Telemetry Frame (Server → Client - periodic)
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    mgmt_frame_header_t header;
    
    /* Timestamp */
    uint64_t  timestamp_ns;  /* High-resolution timestamp */
    
    /* Throughput */
    double    tx_bytes_sec;
    double    rx_bytes_sec;
    uint64_t  tx_total;
    uint64_t  rx_total;
    
    /* Sessions */
    uint32_t  active_sessions;
    uint32_t  max_sessions;
    
    /* Resolvers (client) or Swarm (server) */
    uint32_t  active_resolvers;
    uint32_t  dead_resolvers;
    uint32_t  penalty_resolvers;
    
    /* DNS Stats */
    uint64_t  queries_sent;
    uint64_t  queries_recv;
    uint64_t  queries_lost;
    uint64_t  queries_dropped;
    
    /* Server-specific */
    uint32_t  server_connected;  /* Client: connected to server */
    uint32_t  last_server_rx_ms; /* Client: latency to server */
    
    /* Core state flags */
    uint8_t   encryption_enabled;
    uint8_t   jitter_enabled;
    uint8_t   padding_enabled;
    uint8_t   chaffing_enabled;
    
    /* Mode indicator */
    char      mode[16];          /* "CLIENT" or "SERVER" */
    
    /* Reserved for future use */
    uint8_t   reserved[32];
} mgmt_telemetry_frame_t;
#pragma pack(pop)

#define MGMT_TELEMETRY_SIZE  sizeof(mgmt_telemetry_frame_t)

/* ──────────────────────────────────────────────
   Command Frame (Client → Server)
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    mgmt_frame_header_t header;
    
    uint32_t  command_type;   /* mgmt_command_type_t */
    uint32_t  command_id;     /* For matching responses */
    
    /* Command-specific payload follows this header */
    /* Use flexible array member for payload */
    uint8_t   payload[];
} mgmt_command_frame_t;
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Response Frame (Server → Client)
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    mgmt_frame_header_t header;
    
    uint32_t  command_id;     /* Matches the request */
    uint32_t  status;         /* mgmt_status_t */
    uint32_t  error_code;     /* Platform-specific error if needed */
    
    /* Response payload length */
    uint32_t  payload_len;
    
    /* Response payload (JSON or binary data) */
    uint8_t   payload[];
} mgmt_response_frame_t;
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Config Set Command Payload
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    char      section[64];    /* INI section name */
    char      key[64];        /* INI key name */
    char      value[256];     /* New value */
} mgmt_config_set_payload_t;
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Close Session Command Payload
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t   session_id;     /* 0-15 for 4-bit session ID */
    uint8_t   reserved[3];
} mgmt_close_session_payload_t;
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Bandwidth Limit Command Payload
 ────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint32_t  limit_kbps;     /* 0 = no limit */
    uint8_t   direction;      /* 0=both, 1=upload only, 2=download only */
    uint8_t   reserved[3];
} mgmt_bandwidth_limit_payload_t;
#pragma pack(pop)

/* ──────────────────────────────────────────────
   Utility Functions
 ────────────────────────────────────────────── */

/* Calculate total frame size (header + payload) */
static inline size_t mgmt_frame_total_size(const mgmt_frame_header_t *hdr) {
    return MGMT_FRAME_HEADER_SIZE + hdr->length;
}

/* Validate frame magic and version */
static inline int mgmt_frame_valid(const mgmt_frame_header_t *hdr) {
    return hdr->magic == MGMT_MAGIC && 
           hdr->version <= MGMT_PROTOCOL_VERSION;
}

/* ──────────────────────────────────────────────
   Binary Encoding/Decoding Helpers
   
   All multi-byte values are in network byte order (big-endian)
   for cross-platform compatibility.
 ────────────────────────────────────────────── */

/* Read 16-bit big-endian value */
static inline uint16_t mgmt_read_be16(const uint8_t *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

/* Write 16-bit big-endian value */
static inline void mgmt_write_be16(uint8_t *buf, uint16_t val) {
    buf[0] = (uint8_t)(val >> 8);
    buf[1] = (uint8_t)(val & 0xFF);
}

/* Read 32-bit big-endian value */
static inline uint32_t mgmt_read_be32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8)  | ((uint32_t)buf[3]);
}

/* Write 32-bit big-endian value */
static inline void mgmt_write_be32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val >> 24);
    buf[1] = (uint8_t)(val >> 16);
    buf[2] = (uint8_t)(val >> 8);
    buf[3] = (uint8_t)(val & 0xFF);
}

/* Read 64-bit big-endian value */
static inline uint64_t mgmt_read_be64(const uint8_t *buf) {
    return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
           ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
           ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
           ((uint64_t)buf[6] << 8)  | ((uint64_t)buf[7]);
}

/* Write 64-bit big-endian value */
static inline void mgmt_write_be64(uint8_t *buf, uint64_t val) {
    buf[0] = (uint8_t)(val >> 56);
    buf[1] = (uint8_t)(val >> 48);
    buf[2] = (uint8_t)(val >> 40);
    buf[3] = (uint8_t)(val >> 32);
    buf[4] = (uint8_t)(val >> 24);
    buf[5] = (uint8_t)(val >> 16);
    buf[6] = (uint8_t)(val >> 8);
    buf[7] = (uint8_t)(val & 0xFF);
}

/* Read double (network order for cross-platform) */
static inline double mgmt_read_double(const uint8_t *buf) {
    uint64_t bits = mgmt_read_be64(buf);
    double val;
    memcpy(&val, &bits, sizeof(double));
    return val;
}

/* Write double (network order for cross-platform) */
static inline void mgmt_write_double(uint8_t *buf, double val) {
    uint64_t bits;
    memcpy(&bits, &val, sizeof(double));
    mgmt_write_be64(buf, bits);
}

#endif /* DNSTUN_MGMT_PROTOCOL_H */
