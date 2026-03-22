# ⚙️ Comprehensive Configuration Guide

This document provides a deep dive into every configuration parameter available in `dnstun`.

---

## 💻 Client Configuration (`client.ini`)

### `[core]`
- **`socks5_bind`**: (IP:Port) The local endpoint for your browser/apps. Use `0.0.0.0:1080` to allow other devices on your LAN to use the proxy.
- **`workers`**: Number of internal IO workers. Increase on high-core CPUs if throughput is capped.
- **`log_level`**: `silent` | `info` | `debug`. Debug mode shows real-time discovery of RTT, MTU, and Hijack detection.

### `[resolvers]`
- **`seed_list`**: Initial resolvers. The client will "blast" these to find more siblings.
- **`cidr_scan`**: (bool) Enables scanning of sibling IPs. Turning this `true` can find low-latency "hidden" resolvers near your seeds.
- **`cidr_prefix`**: `24` (256 IPs) or `16` (65k IPs). Use `24` for faster startup.
- **`swarm_sync`**: (bool) Pulls the "Swarm" list from the server. This is the fastest way to get vetted, high-speed resolvers.
- **`background_recovery_rate`**: Frequency of re-probing resolvers in the penalty/dead pool.

### `[tuning]`
- **`poll_interval_ms`**: Downstream latency control.
    - `50`: Ultra-responsive, high query count.
    - `100`: Balanced (default).
    - `500`: Stealthy, low query count.
- **`fec_window`**: Number of packets before FEC parity is calculated. Larger windows handle burst loss better but add slight delay.
- **`cwnd_init`**: Starting queries-in-flight per resolver.
- **`cwnd_max`**: Maximum queries-in-flight. Crucial for speed; 512 is usually safe for public DNS like Cloudflare.

### `[obfuscation]`
- **`jitter`**: Randomizes the exact millisecond queries are sent. Defeats timing-signature DPI.
- **`chaffing`**: Sends "white noise" DNS queries when you aren't doing anything. This masks the "bursty" nature of web browsing.
- **`chrome_cover`**: Adjusts the DNS header and OPT records to perfectly match Google Chrome's native resolver.

---

## 🖥️ Server Configuration (`server.ini`)

### `[core]`
- **`listen_ip`**: Usually `0.0.0.0`.
- **`listen_port`**: Must be `53` for standard DNS tunneling. Requires `sudo` or `setcap`.
- **`domain`**: The delegated zone you own (e.g., `tun.yourdomain.com`).

### `[swarm]`
- **`enabled`**: (bool) Whether to share the server's known-good resolver list with clients.
- **`max_clients`**: Connection limit for the server node.

### `[security]`
- **`encryption_key`**: Must match the client's `psk`.
- **`allowed_users`**: Comma-separated list of `user_id`s allowed to connect.
