# qnsdns — High-Performance DNS Tunnel VPN

Welcome to **qnsdns**, a modular, high-performance DNS tunnel proxy. It is designed to help you bypass restrictive firewalls or captive portals by encapsulating your internet traffic within standard DNS queries.

This project is built from the ground up to be **educational, modular, and fast**. If you are a junior programmer or a networking enthusiast, the codebase is meticulously documented with clear examples and separated concerns to help you understand how a modern VPN protocol works.

---

## 🚀 Key Features

- **Standard SOCKS5 Interface**: Exposes a local SOCKS5 proxy (default `127.0.0.1:1080`) that seamlessly integrates with any browser, Telegram, or application.
- **Advanced Forward Error Correction (FEC)**: Uses industry-standard RaptorQ (RFC 6330) and Reed-Solomon encoding to mathematically recover lost packets. This means we can drop retransmissions entirely and achieve high speeds even on terrible connections.
- **Multipath Scattering**: Automatically distributes your tunnel traffic across hundreds of public DNS resolvers (like 1.1.1.1 or 8.8.8.8) to bypass per-resolver strict rate limits.
- **Binary MTU Discovery**: Automatically finds the maximum safe packet size for your network to prevent silent packet drops and sequence desynchronization.
- **Real-Time TUI Dashboard**: A professional, dynamic terminal interface to monitor latency, throughput, session health, and FEC recovery rates.

---

## 🛠 For the End User: Configuration & Setup

Once installed, `qnsdns` is driven by simple configuration files (`client.ini` and `server.ini`). The most critical setting for a stable connection is your **FEC Redundancy**.

### Understanding FEC (Forward Error Correction)
DNS is fundamentally lossy. Firewalls often drop large or frequent DNS queries. Instead of waiting to realize a packet was dropped and asking the server to resend it (which is incredibly slow over DNS), `qnsdns` sends mathematically redundant "extra" packets alongside your data. If the server drops 10% of your packets, but you sent 10% extra redundant symbols, the server can perfectly reconstruct the original data without ever asking for a retransmission!

#### 🟢 Scenario: Low-Loss Networks (Home Wi-Fi, Fiber, Corporate LAN)
If your network is relatively stable and just happens to restrict certain traffic, you don't need much redundancy. Set a low FEC overhead to maximize your throughput and minimize DNS spam.
**In `client.ini`:**
```ini
[Tunnel]
# 10% extra symbols. Very little overhead, fast speeds.
fec_redundancy = 10    
# Standard safe size for most modern networks.
symbol_size = 110      
```

#### 🟡 Scenario: Medium-Loss Networks (Public Wi-Fi, Captive Portals)
If you are on a hotel Wi-Fi or airport portal, they often strictly rate-limit UDP packets or drop anything slightly unusual. Increase the redundancy to guarantee delivery.
**In `client.ini`:**
```ini
[Tunnel]
# 30% extra symbols. Modest overhead, survives burst packet loss.
fec_redundancy = 30
# Slightly smaller chunks to avoid generic packet inspection filters.
symbol_size = 90
```

#### 🔴 Scenario: High-Loss Environments (3G/4G Mobile Data, Heavily Censored Networks)
Cellular networks and heavily censored environments will savagely drop UDP packets and fragment large payloads. Here, reliability is more important than raw speed.
**In `client.ini`:**
```ini
[Tunnel]
# 50% extra symbols. Massive overhead, but practically guarantees delivery even if half your packets are destroyed.
fec_redundancy = 50
# Smallest chunks. Highly evasive, avoids almost all MTU fragmentation drops.
symbol_size = 64
```

---

## 📁 Architecture (Modular Design)

The project has been aggressively refactored to separate concerns. Each major file starts with a **Usage Example** in its header, making it easy to learn from.

### `shared/` — The Foundation
- **`fec/`**: The error-correction core. Contains drivers for `raptorq` and `reedsolomon`. Abstracted so the main app doesn't need to care about the math.
- **`window/`**: Unified sliding window and sequence reorder logic to ensure out-of-order UDP packets arrive perfectly sequenced at the SOCKS5 proxy.
- **`tui/`**: A professional Terminal UI engine built with raw ANSI escapes.
- **`codec.c`**: Maps payload data to robust Base32/64 text ready for DNS transit.

### `server/` — The Bridge
- **`dns_handler.c`**: Parses incoming DNS queries, decodes Base32, runs the FEC decoder to recover payloads, and acknowledges sequences.
- **`session.c`**: Manages the actual TCP connections to the real internet websites you are requesting.
- **`swarm.c`**: Tracks the dynamic IP addresses of the client and resolver pool.

### `client/` — The Entry Point
- **`socks5.c`**: Speaks the SOCKS5 proxy protocol to your local browser.
- **`agg.c (Aggregator)`**: The "Burster". Gathers your browse traffic, chunks it into `symbol_size` pieces, and runs the FEC encoder to attach `fec_redundancy` blocks.
- **`dns_tx.c`**: The transmitter. Takes the encoded burst symbols and sends them rapidly outwards utilizing multipath resolver scattering.
- **`resolver_mod.c`**: Tests public resolvers behind the scenes to find the fastest and most reliable paths.

---

## 💻 Building the Project

Ensure you have `cmake`, `ninja`, and a C/C++ compiler installed.
**Dependencies:** `libuv` (async IO), `zstd` (compression), `libsodium` (encryption), `RaptorQ` (FEC).

```bash
mkdir build && cd build
cmake -G Ninja -D BUILD_SERVER=ON ..
cmake --build . --config Release
```
This will produce `dnstun-client` and `dnstun-server` executables in the `build/` directory!

---
*Created with ❤️ for the privacy community. Stay safe, stay connected.*
