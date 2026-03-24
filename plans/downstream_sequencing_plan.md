# Downstream Sequencing Fix - Implementation Plan

## Problem
The downstream direction (Server → Client) has no sequence numbers in responses. If DNS TXT responses arrive out-of-order, the client appends data incorrectly, causing application-level data corruption.

**Current Header:**
```c
typedef struct {
    uint8_t  flags;       /* bit 0: encoding_type, bits 1-7: reserved */
    uint8_t  session_id;  /* session ID (0-15) */
} server_response_header_t;   /* Total: 2 bytes */
```

---

## Solution Overview

Add 2-byte sequence numbers to downstream packets and implement a reordering buffer on the client side.

### New Protocol Header

```c
#pragma pack(push, 1)
typedef struct {
    uint8_t  flags;       /* bit 0: encoding_type (0=base64, 1=hex)
                           * bit 1: has_sequence (1 = seq field is valid)
                           * bits 2-7: reserved */
    uint8_t  session_id;  /* session ID (0-15) */
    uint16_t seq;         /* sequence number (NEW - 2 bytes) */
} server_response_header_t;   /* Total: 4 bytes (was 2 bytes) */
#pragma pack(pop)
```

**Backward Compatibility:**
- Set `has_sequence` flag to indicate new format
- Legacy clients ignore the extra 2 bytes (base64 decode will handle it)

---

## Design Decisions

### 1. Window Size: 32 packets
- **Rationale:** DNS responses typically arrive in bursts; 32 provides enough buffer for reordering without excessive memory
- **Wrap-around handling:** Use `uint16_t` modulo arithmetic (standard TCP-style)

### 2. Reordering Buffer per Session
```c
typedef struct {
    uint8_t  *data;       /* Buffered packet data */
    size_t    len;        /* Data length */
    uint16_t  seq;        /* Sequence number */
    time_t    received_at; /* Timestamp for expiry */
    bool      valid;      /* Slot occupied */
} rx_buffer_slot_t;

#define RX_REORDER_WINDOW 32

typedef struct reorder_buffer {
    rx_buffer_slot_t slots[RX_REORDER_WINDOW];
    uint16_t expected_seq;    /* Next expected sequence number */
} reorder_buffer_t;
```

### 3. Server-Side Tracking
Add to `srv_session_t`:
```c
uint16_t downstream_seq;   /* Next seq to assign for downstream */
```

---

## Implementation Steps

### Phase 1: Protocol Update (shared/types.h)

1. Update `server_response_header_t` to include sequence number
2. Add flag constants:
   ```c
   #define RESP_FLAG_ENC_MASK     0x01  /* 0=base64, 1=hex */
   #define RESP_FLAG_HAS_SEQ      0x02  /* 1 = seq field valid */
   ```
3. Add reorder buffer structures

### Phase 2: Server Changes (server/main.c)

1. Add `downstream_seq` to `srv_session_t` initialization
2. Modify `build_txt_reply()` to accept sequence number parameter
3. Update all call sites to pass sequence number:
   - MTU test responses
   - DEBUG echo responses  
   - SYNC responses
   - Data responses (from upstream TCP)
   - ACK responses
4. Increment sequence number after each response

### Phase 3: Client Changes (client/main.c)

1. Add reorder buffer to `session_t` structure
2. Modify DNS response handler to:
   - Extract sequence number from header
   - If in-order (seq == expected): deliver immediately
   - If out-of-order within window: buffer
   - If out-of-window: drop (or optionally deliver if ahead)
3. Implement `reorder_buffer_insert()` and `reorder_buffer_flush()`
4. Add periodic flush for stale buffered packets

### Phase 4: Testing

1. Unit tests for reorder buffer
2. Integration test with simulated out-of-order responses
3. Backward compatibility test with old clients

---

## Key Code Sections

### Server: Sending with Sequence
```c
/* In build_txt_reply or wrapper function */
server_response_header_t hdr = {0};
hdr.flags = encoding_type | RESP_FLAG_HAS_SEQ;
hdr.session_id = session_id;
hdr.seq = sess->downstream_seq++;

/* Prepend header to payload before base64 encoding */
uint8_t packet[4096];
size_t packet_len = 0;
memcpy(packet, &hdr, sizeof(hdr));
packet_len += sizeof(hdr);
memcpy(packet + packet_len, payload, payload_len);
packet_len += payload_len;

/* Encode and send */
encode_downstream_data(encoded, packet, packet_len);
```

### Client: Reordering Logic
```c
void handle_downstream_packet(session_t *s, uint8_t *data, size_t len, uint16_t seq) {
    reorder_buffer_t *rb = &s->reorder_buf;
    
    if (seq == rb->expected_seq) {
        /* In-order: deliver immediately */
        deliver_to_socks5(s, data, len);
        rb->expected_seq++;
        
        /* Check if buffered packets can now be delivered */
        flush_sequential_packets(s);
    }
    else if (is_within_window(seq, rb->expected_seq)) {
        /* Out-of-order but within window: buffer */
        buffer_packet(rb, seq, data, len);
    }
    else {
        /* Outside window: drop or update expected if ahead */
        if (seq > rb->expected_seq + RX_REORDER_WINDOW) {
            /* Large gap - reset expected and deliver */
            rb->expected_seq = seq;
            deliver_to_socks5(s, data, len);
        }
        /* else: duplicate or old packet, drop */
    }
}
```

---

## Memory Impact

| Component | Size per Session | Max Sessions | Total Memory |
|-----------|------------------|--------------|--------------|
| Reorder buffer slots | 32 × (8+ ptr) ≈ 320 bytes | 16 | ~5 KB |
| Buffered data (avg) | 256 bytes × 16 slots | 16 | ~65 KB |
| **Total** | | | **~70 KB** |

*Well within the existing 10MB per-session limit.*

---

## Backward Compatibility Strategy

1. **Old client + New server:** Server detects client version during handshake and can fall back to 2-byte headers
2. **New client + Old server:** Client checks for `RESP_FLAG_HAS_SEQ`; if not set, treats entire payload as data (no sequencing)

---

## Timeline

| Phase | Files Changed | Estimated Effort |
|-------|---------------|------------------|
| 1. Protocol | types.h | Low |
| 2. Server | server/main.c | Medium |
| 3. Client | client/main.c | Medium |
| 4. Tests | tests/ | Medium |

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| MTU increase from +2 bytes | Reduce max payload by 2 bytes; stays within 512 byte DNS limit |
| Sequence number wraparound | Use uint16_t with proper modulo comparison |
| Buffer exhaustion | Drop oldest packets when buffer full; limit max buffered data |
| Latency from buffering | Set max wait time (e.g., 50ms) before delivering available packets |
