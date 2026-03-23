# New Protocol Design (Asymmetric Encoding)

## Overview
- **Upstream** (Client → Server): Base32 in QNAME (DNS-safe, case-insensitive)
- **Downstream** (Server → Client): Base64 or Hex in TXT record (configurable, more efficient)

---

## Upstream: Client → Server (Base32 in QNAME)

### Handshake Packet (Sent Once Per Resolver)
```c
#pragma pack(push, 1)
typedef struct {
    uint8_t version;         /* Protocol version */
    uint16_t upstream_mtu;   /* Client's upstream MTU */
    uint16_t downstream_mtu; /* Requested downstream MTU */
} handshake_packet_t;        /* 5 bytes - sent once */
#pragma pack(pop)
```

### Data Packet Header (4 bytes)
```c
#pragma pack(push, 1)
typedef struct {
    uint8_t flags;           /* Bit layout:
                             *   [0] encrypted
                             *   [1] compressed  
                             *   [2] fec_enabled
                             *   [3] poll_query
                             *   [4-7] session_id (4 bits = 0-15)
                             */
    uint16_t seq;            /* Sequence number (2 bytes) */
    uint8_t chunk_info;      /* chunk_total(4)|fec_k(4) */
} chunk_header_t;            /* Total: 4 bytes (was 32 bytes) */
#pragma pack(pop)
```

### QNAME Format
```
<base32(chunk_header + payload)>.tun.<domain>.
```

---

## Downstream: Server → Client (TXT Record)

### Server Response Header (2 bytes)
```c
#pragma pack(push, 1)
typedef struct {
    uint8_t flags;           /* Bit layout:
                             *   [0] encoding_type (0=base64, 1=hex)
                             *   [1-7] reserved
                             */
    uint8_t session_id;      /* Session ID (0-15) */
} server_response_header_t;  /* Total: 2 bytes */
#pragma pack(pop)

#define ENC_TYPE_BASE64     0x00
#define ENC_TYPE_HEX        0x01
```

### TXT Record Format
```
TXT: <base64_or_hex(flags, session_id, payload)>
```

---

## Encoding Configuration

### Config Options
```c
typedef struct {
    /* Upstream encoding (always base32 for DNS compatibility) */
    /* No option - always base32 */
    
    /* Downstream encoding (configurable) */
    int downstream_encoding;  /* 0=base64 (default), 1=hex */
    
    /* Buffer sizes for large downstream MTU */
    size_t downstream_buffer_size;  /* Default: 8192, Max: 65536 */
    
} dnstun_config_t;
```

### INI Configuration
```ini
[encoding]
downstream = base64      ; Options: base64, hex
downstream_buffer = 8192 ; Buffer size for downstream (default: 8192)
```

---

## Increased Buffer Sizes

### Server Buffer (for downstream up to 4096 bytes)
```c
#define DNSTUN_MAX_DOWNSTREAM_MTU   4096
#define DNSTUN_SERVER_BUFFER_SIZE   65536  /* 64KB for large responses */

typedef struct {
    /* ... other fields ... */
    
    /* Large downstream buffer */
    uint8_t *upstream_buf;      /* Buffer for data from target server */
    size_t upstream_len;
    size_t upstream_cap;        /* Up to DNSTUN_SERVER_BUFFER_SIZE */
    
    /* Response assembly buffer */
    uint8_t *response_buf;      /* Buffer for building TXT responses */
    size_t response_len;
    size_t response_cap;        /* Up to DNSTUN_SERVER_BUFFER_SIZE */
    
} session_t;
```

### Client Buffer (for receiving large downstream)
```c
#define DNSTUN_CLIENT_BUFFER_SIZE   65536  /* 64KB for large responses */

typedef struct {
    /* ... other fields ... */
    
    /* Large receive buffer */
    uint8_t *recv_buf;          /* Buffer for received data from server */
    size_t recv_len;
    size_t recv_cap;            /* Up to DNSTUN_CLIENT_BUFFER_SIZE */
    
} session_t;
```

---

## Protocol Flow

### 1. Handshake
```
Client → Server (Base32 in QNAME)
---------------------------------
QNAME: handshake.<base32(ver,mtu)>.tun.example.com.

Server stores:
- version
- upstream_mtu (for decoding base32 QNAMEs)
- downstream_mtu (for encoding TXT responses)
- client IP for session matching
```

### 2. Client → Server (Data)
```
Client → Server (Base32 in QNAME)
---------------------------------
QNAME: <base32(flags,seq,chunk_info,payload)>.tun.example.com.

chunk_header_t {
    flags = encrypted | compressed | fec | poll | session_id(4)
    seq = packet_number
    chunk_info = chunk_total | fec_k
}
```

### 3. Server → Client (Response)
```
Server → Client (Base64 or Hex in TXT)
--------------------------------------
TXT Record: <encoding><session_id><payload>

If downstream_encoding = base64 (default):
  TXT: <base64(flags|session_id|payload)>

If downstream_encoding = hex:
  TXT: <hex(flags|session_id|payload)>

First byte indicates encoding type to client.
```

---

## Encoding Examples

### Base64 Downstream (Default)
```
Server response:
- Header: flags=0x00 (base64), session_id=3
- Payload: "Hello World"

TXT: "AENlbGxvIFdvcmxk"  /* base64("\x00\x03Hello World") */

Client decodes:
- flags = 0x00 → base64 encoding
- session_id = 0x03 → session 3
- payload = "Hello World"
```

### Hex Downstream
```
Server response:
- Header: flags=0x01 (hex), session_id=5
- Payload: "Hello World"

TXT: "010548656c6c6f20576f726c64"  /* hex("\x01\x05Hello World") */

Client decodes:
- flags = 0x01 → hex encoding
- session_id = 0x05 → session 5
- payload = "Hello World"
```

---

## Size Comparison

| Direction | Old | New | Savings |
|-----------|-----|-----|---------|
| Upstream (Base32) | 32 bytes | 4 bytes | **28 bytes** |
| Downstream (Base64) | 32 bytes | 2 bytes | **30 bytes** |
| **Total per round-trip** | 64 bytes | 6 bytes | **58 bytes** |

### Payload Capacity

**Upstream (Base32)**:
```
QNAME limit: 253 bytes
Overhead: ~27 bytes
Base32 overhead: 4 bytes × 8/5 = 7 chars
Payload: (253 - 27 - 7) × 5/8 = 137 bytes
```

**Downstream (Base64)**:
```
TXT record limit: 65535 bytes (theoretical)
Practical: 4096 bytes (MTU limit)
Base64 overhead: 2 bytes × 4/3 = 3 chars
Payload: (4096 - 3) × 3/4 = 3070 bytes
```

**Downstream (Hex)**:
```
Hex overhead: 2 bytes × 2 = 4 chars
Payload: (4096 - 4) / 2 = 2046 bytes
```

---

## Implementation Files

### 1. [`shared/types.h`](shared/types.h)
```c
/* New headers */
typedef struct { /* 4 bytes */ } chunk_header_t;
typedef struct { /* 2 bytes */ } server_response_header_t;

/* Buffer sizes */
#define DNSTUN_MAX_DOWNSTREAM_MTU   4096
#define DNSTUN_SERVER_BUFFER_SIZE   65536
#define DNSTUN_CLIENT_BUFFER_SIZE   65536

/* Encoding types */
#define DNSTUN_ENC_BASE64   0
#define DNSTUN_ENC_HEX      1
```

### 2. [`shared/config.h`](shared/config.h)
```c
typedef struct {
    /* ... existing fields ... */
    int downstream_encoding;        /* 0=base64, 1=hex */
    size_t downstream_buffer_size;  /* Default: 8192 */
} dnstun_config_t;
```

### 3. [`client/main.c`](client/main.c)
```c
/* Decode downstream based on encoding type */
void decode_downstream(const char *txt, size_t len, uint8_t *out, size_t *outlen) {
    uint8_t flags = decode_first_byte(txt, len);
    if (flags & ENC_TYPE_HEX) {
        hex_decode(out, outlen, txt + 1, len - 1);
    } else {
        base64_decode(out, outlen, txt + 1, len - 1);
    }
}
```

### 4. [`server/main.c`](server/main.c)
```c
/* Encode downstream based on config */
void encode_downstream(uint8_t session_id, const uint8_t *payload, size_t len,
                       char *out, size_t *outlen) {
    uint8_t flags = (g_cfg.downstream_encoding == DNSTUN_ENC_HEX) ? ENC_TYPE_HEX : ENC_TYPE_BASE64;
    
    if (g_cfg.downstream_encoding == DNSTUN_ENC_HEX) {
        hex_encode(out, outlen, &flags, 1);
        hex_encode(out + 2, outlen, &session_id, 1);
        hex_encode(out + 4, outlen, payload, len);
    } else {
        /* Base64 default */
        uint8_t header[2] = {flags, session_id};
        base64_encode(out, outlen, header, 2);
        base64_encode(out + *outlen, outlen, payload, len);
    }
}
```

---

## Backward Compatibility

If needed for migration:
- Version 1: Old protocol (32-byte header)
- Version 2: New protocol (4-byte header, asymmetric encoding)
- Handshake includes version
- Server rejects unsupported versions gracefully
