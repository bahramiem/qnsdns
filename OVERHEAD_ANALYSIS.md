# DNS Tunnel Overhead Analysis

## Current Overhead Breakdown

### 1. Chunk Header (32 bytes → ~52 bytes after base32)
```c
chunk_header_t (32 bytes):
  - version: 1 byte
  - flags: 1 byte  
  - session_id: 4 bytes
  - seq: 2 bytes
  - chunk_total: 2 bytes
  - original_size: 2 bytes
  - upstream_mtu: 2 bytes
  - downstream_mtu: 2 bytes
  - enc_format: 1 byte
  - loss_pct: 1 byte
  - fec_k: 1 byte
  - user_id: 12 bytes
  - reserved: 1 byte
```

**After base32 encoding**: 32 × 8/5 = **52 bytes**

### 2. QNAME Structure Overhead
```
QNAME: <seq_hex>.<b32>.<sid>.tun.<domain>.

Example: 0001.ABCD...EFGH.12345678.tun.example.com.

- seq_hex: 4 chars
- dots between base32 labels: ~5 chars (base32/57)
- sid_hex: 8 chars  
- "tun": 3 chars
- domain: ~15 chars
- trailing dot: 1 char
- label dots: ~4 chars

Total QNAME overhead: ~40 bytes
```

### 3. DNS Protocol Overhead
- DNS header: 12 bytes
- Question section: ~20 bytes
- UDP/IP headers: 28 bytes

### 4. Base32 Encoding Overhead
Base32 increases data size by **60%** (8/5 ratio).

For 93 bytes payload:
- Raw: 32 (header) + 93 = 125 bytes
- Base32: 125 × 8/5 = **200 bytes**
- QNAME total: 200 + 40 = **240 bytes** (near 253 limit!)

## Optimization Recommendations

### 1. Reduce Chunk Header Size (High Impact)

**Current**: 32 bytes → 52 bytes base32
**Optimized**: 12 bytes → 20 bytes base32

**Remove/Simplify**:
- Remove `user_id[12]` - Use session_id only (-12 bytes)
- Remove `reserved` (-1 byte)
- Combine MTU fields into one (-2 bytes)
- Remove `original_size` from header (infer from payload) (-2 bytes)
- Remove `loss_pct` (use per-resolver tracking) (-1 byte)
- Remove `enc_format` (use flags) (-1 byte)

**New minimal header (12 bytes)**:
```c
typedef struct {
    uint8_t  version;        /* 1 byte */
    uint8_t  flags;          /* 1 byte */
    uint8_t  session_id[4];  /* 4 bytes */
    uint16_t seq;            /* 2 bytes */
    uint16_t chunk_total;    /* 2 bytes */
    uint8_t  fec_k;          /* 1 byte */
    uint16_t mtu;            /* 2 bytes (combined up/down) */
} chunk_header_t;            /* Total: 13 bytes */
```

**Payload gain**: 32 - 13 = **19 more bytes per packet**

### 2. Use Base64 instead of Base32 (Medium Impact)

Base64 encoding is more efficient: increases size by only 33% (4/3 ratio) vs 60% for base32.

**Trade-offs**:
- Base32: DNS-safe (case-insensitive)
- Base64: Case-sensitive (some resolvers may lowercase)

**Solution**: Use base64 with lowercase encoding + case-insensitive decoding.

**Payload gain**: For 100 bytes: Base32=160 chars, Base64=134 chars = **26 fewer chars**

### 3. Remove Inline Session ID (Medium Impact)

**Current**: sid_hex (8 chars) embedded in QNAME
**Optimized**: Use only session_id from header (4 bytes → 7 chars base32)

**QNAME format**: `<seq>.<b32_with_sid>.tun.<domain>.`

**Payload gain**: 8 - 4 = **4 bytes saved**

### 4. Optimize QNAME Structure (Low Impact)

**Current**: `seq.b32.sid.tun.domain.`
**Optimized**: `s.b32.t.domain.`
  - Shorten "seq" to "s" (2 chars saved)
  - Remove "tun" if domain includes it (3 chars saved)
  - Combine seq and sid into b32 payload

**Payload gain**: ~5 bytes

### 5. Compress Header Fields (High Impact)

For small values, use variable-length encoding:
- seq: Often < 256, use 1 byte instead of 2
- chunk_total: Often < 16, use 4 bits
- fec_k: Often < 8, use 3 bits

**Payload gain**: 2-4 bytes per packet

### 6. Use Binary Labels (High Impact, Risky)

Some DNS resolvers support binary labels (RFC 2673).
This would eliminate base32 overhead entirely.

**Risk**: Many resolvers don't support this.

### 7. Aggregate Small Packets (High Impact)

**Current**: Each DNS query carries one chunk
**Optimized**: Pack multiple chunks into one QNAME

```
QNAME: <seq1>.<b1>.<seq2>.<b2>.sid.tun.domain.
```

**Payload gain**: Amortize header overhead over multiple chunks

### 8. Remove Poll Queries (Medium Impact)

**Current**: Send empty poll queries every 100ms
**Optimized**: Use longer poll interval or adaptive polling

**Trade-off**: Latency vs bandwidth

## Summary of Potential Gains

| Optimization | Bytes Saved | Complexity | Risk |
|--------------|-------------|------------|------|
| Reduce header | 19 bytes | Low | Low |
| Use Base64 | 26 bytes | Medium | Medium |
| Remove inline SID | 4 bytes | Low | Low |
| Optimize QNAME | 5 bytes | Low | Low |
| Compress fields | 3 bytes | Medium | Low |
| Binary labels | 60% reduction | High | High |
| Aggregate packets | Variable | Medium | Low |
| Adaptive polling | 12 bytes/query | Low | Low |

**Conservative estimate**: 19 + 4 + 5 + 3 = **31 more payload bytes per packet**

With these optimizations, DNSTUN_CHUNK_PAYLOAD could increase from 93 to ~124 bytes (**33% more throughput**).

## Recommended Implementation Priority

1. **Reduce chunk header** (immediate, low risk)
2. **Remove inline SID** (immediate, low risk)
3. **Optimize QNAME structure** (immediate, low risk)
4. **Aggregate small packets** (medium term, good gain)
5. **Adaptive polling** (medium term, reduces queries)
6. **Consider Base64** (long term, needs testing)
