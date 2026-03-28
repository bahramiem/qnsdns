# Full Implementation Plan - Missing Features

## Overview
This document tracks the implementation of all missing features from the original plan.

## Feature 1: Cryptographic Challenge (Anti-Hijack)
**Priority**: HIGH
**Plan**: Add Phase 0 to resolver testing that sends a random nonce to the server, which must be signed and echoed back.

### Implementation Steps:
1. Add `PROBE_TEST_CRYPTO_CHALLENGE` to probe_test_type_t enum
2. Add `crypto_challenge_passed` field to resolver_test_result_t
3. Add `challenge_nonce[32]` and `challenge_sent_ms` to probe_req_t
4. Implement `send_crypto_challenge()` using libsodium
5. Implement `verify_crypto_response()` to validate signed nonce
6. Add server-side challenge handling in on_server_recv
7. Integrate as Phase 0 before existing tests

### Files to Modify:
- `client/main.c`: Add challenge test type, nonce generation, verification
- `server/main.c`: Add challenge response handling
- `shared/types.h`: Add challenge-related structures

---

## Feature 2: Cooldown Measurement
**Priority**: MEDIUM
**Plan**: When a resolver is rate-limited, measure the cooldown duration.

### Implementation Steps:
1. Add `cooldown_until_ms` field to resolver_t
2. When SERVFAIL/REFUSED detected, start cooldown timer
3. Periodically probe cooldown resolvers
4. When response received, record cooldown duration

### Files to Modify:
- `client/main.c`: Cooldown timer and measurement
- `shared/resolver_pool.h`: Add cooldown fields

---

## Feature 3: Fail Probability (Packet Loss Rate)
**Priority**: MEDIUM
**Plan**: Burst test to measure inherent packet loss rate.

### Implementation Steps:
1. Add `loss_rate` field to resolver_test_result_t
2. Send burst of N probes
3. Count responses received
4. Calculate loss_rate = (N - received) / N

### Files to Modify:
- `client/main.c`: Burst loss test implementation

---

## Feature 4: Penalty Box Timer
**Priority**: MEDIUM
**Plan**: Route around rate-limited resolvers automatically.

### Implementation Steps:
1. Add `penalty_until_ms` field to resolver_t
2. On rate-limit detection, set penalty timeout
3. Exclude penalty resolvers from rpool_next()
4. Re-enable after penalty expires

### Files to Modify:
- `client/main.c`: Penalty box logic
- `shared/resolver_pool.c`: Exclude penalty resolvers

---

## Feature 5: Capability Header in Query
**Priority**: HIGH
**Plan**: Embed `mtu:220,enc:bin,loss:5` in Base32 query payload.

### Implementation Steps:
1. Create capability header struct: `{uint8_t mtu, uint8_t encoding, uint8_t loss_pct}`
2. Prepend capability header to all queries
3. Server extracts and uses for response sizing

### Files to Modify:
- `shared/types.h`: Add capability_header_t
- `client/main.c`: Include header in queries
- `server/main.c`: Extract from payload

---

## Feature 6: Chrome Cover Traffic
**Priority**: LOW
**Plan**: Mimic Chromium DNS behavior exactly.

### Implementation Steps:
1. Complete implementation of A+AAAA+HTTPS query triplets
2. Add proper EDNS flags (AD=1)
3. Add EDNS0 UDP size 1452
4. Implement page-load burst timing (5-15 queries then silence)

### Files to Modify:
- `client/main.c`: Complete chrome_cover_traffic()

---

## Feature 7: DNS Flux (Time-Sliced Domain Rotation)
**Priority**: MEDIUM
**Plan**: Deterministic time-based domain selection.

### Implementation Steps:
1. Implement epoch / flux_period_sec hash
2. Select domain subset based on current time window
3. Both client and server compute same selection

### Files to Modify:
- `client/main.c`: Domain selection logic
- `shared/config.c`: DNS flux settings

---

## Feature 8: OTA Config Push
**Priority**: LOW
**Plan**: Fetch config updates from server.

### Implementation Steps:
1. Add periodic CONFIG query
2. Server returns compressed/encrypted config blob
3. Client validates signature and applies

### Files to Modify:
- `client/main.c`: Config fetch timer
- `server/main.c`: Config push handling

---

## Feature 9: Noise_NK Authentication
**Priority**: LOW
**Plan**: Curve25519 keypair for forward secrecy.

### Implementation Steps:
1. Add `--gen-key` server option
2. Implement Noise_NK_25519_ChaChaPoly_BLAKE2s
3. Client embeds server public key

### Files to Modify:
- `client/main.c`: Public key embedding
- `server/main.c`: Key generation and Noise handshake
- `shared/codec.c`: Noise protocol

---

## Feature 10: DoH/DoT Transport
**Priority**: MEDIUM
**Plan**: DNS-over-HTTPS and DNS-over-TLS support.

### Implementation Steps:
1. Add libcurl/h2load for DoH
2. Implement DoT connection
3. Add transport mode selection
4. Handle HTTPS frames

### Files to Modify:
- `CMakeLists.txt`: Add curl dependency
- `client/main.c`: Transport layer abstraction
- `shared/transport.c`: New transport module

---

## Implementation Order
1. **Feature 5**: Capability Header (enables better MTU utilization)
2. **Feature 1**: Crypto Challenge (security)
3. **Feature 4**: Penalty Box (reliability)
4. **Feature 2**: Cooldown Measurement (reliability)
5. **Feature 3**: Fail Probability (measurement)
6. **Feature 7**: DNS Flux (obfuscation)
7. **Feature 6**: Chrome Cover (obfuscation)
8. **Feature 8**: OTA Config (management)
9. **Feature 9**: Noise_NK (security)
10. **Feature 10**: DoH/DoT (transport)
