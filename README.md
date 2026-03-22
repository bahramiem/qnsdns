# DNS Tunnel VPN Walkthrough

The DNS Tunnel VPN project is a high-performance SOCKS5 proxy that encapsulates traffic within DNS queries. It is optimized for speed, reliability, and evading deep packet inspection (DPI).

## 🚀 Key Features

- **Multipath Scatter-Gather**: Concurrent DNS queries are blasted across an entire pool of resolvers simultaneously to maximize bandwidth.
- **RaptorQ FEC & Zstd**: Real-world forward error correction and high-ratio compression ensure stability on lossy paths and minimal query overhead.
- **AIMD Congestion Control**: Like TCP Cubic, the client dynamically slides its send rate up and down based on live network performance per resolver.
- **Advanced Obfuscation**: Optional timing jitter, chaffing, and "Chrome mimicry" mode disguise the tunnel as normal web traffic.
- **Resolver Swarm**: Client and server automatically synchronize known-good resolver IPs to bypass DNS discovery blocks.

---

## 🛠️ Installation Guide

### Fast Install (Pre-compiled Binaries)

For a streamlined installation on Ubuntu/Debian x86_64 machines without compiling anything via CMake, run the fast installation pipeline. It autonomously fetches the newest cutting-edge build off the GitHub Releases page:

```bash
curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/fast_install.sh | bash
```

### Full Source Build (Automated)

If you prefer to natively build all components from source, you can run the standard installer script:

```bash
curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/install.sh | bash
```


### Manual Build

The project uses CMake and fetches all dependencies automatically via secure tarball URLs for maximum reliability and speed.

1.  **Dependencies**: Install `build-essential`, `cmake`, and `ninja-build`.
2.  **Build**:
    ```bash
    rm -rf build # Clear old cache
    mkdir build && cd build
    cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
    ninja
    ```

---

# ⚙️ Configuration Guide

For a detailed explanation of every configuration parameter, please see the [**CONFIG.md**](file:///d:/qns/qnsdns/CONFIG.md) guide.

# 🧠 Smart DNS Scanning & Selection

The client features a sophisticated 4-stage initialization pipeline to ensure maximum performance and security:

1.  **Hijack Detection**: Automatically flags and isolates resolvers that return "fake" A-records for non-existent domains (NXDOMAIN hijacking).
2.  **EDNS0 Support**: Explicitly probes for EDNS0 support to utilize larger UDP payloads (up to 4096 bytes if supported).
3.  **Empirical MTU Discovery**: Tests 512, 1024, and 1400 byte payloads to establish a baseline.
4.  **MTU Binary Search Refinement**: Performs a 3-step binary search to find the *exact* maximum payload size each resolver can handle, significantly boosting data efficiency.

# 🛡️ Reliability & Health

- **Packet Duplication**: Critical handshake (seq 0) and control packets are sent to the top 3 resolvers simultaneously. This ensures a fast, reliable connection even if your primary resolver is jittery.
- **Windowed Health Tracking**: Uses a 30-sample sliding window bitmask to track resolver success rates. Resolvers with low success rates are automatically demoted, preventing "flapping" during temporary network congestion.

# ⚙️ Configuration Guide (`client.ini`)

### `[core]`
- `socks5_bind`: The local address and port for the SOCKS5 proxy (default: `127.0.0.1:1080`).
- `log_level`: Verbosity (`silent`, `info`, `debug`). Use `debug` to see live RTT/MTU discovery logs.

### `[resolvers]`
- `seed_list`: Comma-separated list of initial "bootstrap" DNS resolvers.
- `cidr_scan`: If `true`, the client scans the `/24` or `/16` subnet around each seed to find faster sibling resolvers.
- `swarm_sync`: If `true`, the client pulls a list of vetted, high-performance resolvers from the server.
- `background_recovery_rate`: How many "dead" resolvers to re-probe per second to check if they've come back online.

### `[tuning]`
- `poll_interval_ms`: Frequency of downstream POLL queries. Lower values reduce latency but increase query overhead.
- `cwnd_max`: The maximum number of concurrent in-flight queries per resolver. Higher values increase throughput but can trigger rate-limiting.

### `[obfuscation]`
- `jitter`: Adds random 0-50ms delays to queries to defeat timing-based DPI analysis.
- `chaffing`: Sends periodic decoy DNS queries when idle to hide the fact that you are tunneling.
- `chrome_cover`: Mimics the specific DNS query fingerprint of the Google Chrome browser.

---

## ⚙️ Configuration

Fully documented sample INI files are provided:
- [server.ini](https://github.com/bahramiem/qnsdns/blob/main/server.ini)

**First-Run Prompt**:
If you don't configure a tunnel domain in the INI file, both binaries will interactively prompt you for the delegated tunnel zone on your first launch and automatically save it into the INI file for future runs.

**User Identification**:
You can define a `user_id = your_name` variable in the `[core]` section of both configurations. The highly optimized 32-byte DNS tunnel chunk payloads will autonomously embed this identity during the first connection chunks without inflating packet overhead, allowing the Server node to identify precisely who is communicating.

> [!TIP]
> You can edit configuration values **live** while the client is running using the TUI configuration panel (press `3`).
> Press **`m`** on the config panel to edit your domains via an inline text bar; this cleanly restarts the background networking engines to apply it instantly. 
> Press **`r`** on the Resolver panel (press `2`) to enter a new IPv4/IPv6 resolver and dynamically append it to your `client_resolvers.txt`.

---

## 📖 Usage Guide

### 1. Start the Server
Run the server on a machine with a public IP (port 53 UDP must be open). The `server.ini` file will be automatically loaded from your current directory, parent directories, or `/etc/dnstun/`:
```bash
sudo ./build/server/dnstun-server
```

### 2. Start the Client
Run the client on your local machine. The `client.ini` config file is also auto-located:
```bash
./build/client/dnstun-client
```

### 3. Connect via SOCKS5
Configure your browser or application to use the SOCKS5 proxy at `127.0.0.1:1080`.
Or test with curl:
```bash
curl -x socks5h://127.0.0.1:1080 http://example.com
```

---

## 📊 Dashboard (TUI)

Both the client and server feature a powerful 3-panel ANSI dashboard (use `Number Keys` to switch):

1.  **Stats Panel (`1`)**: Monitor live throughput (KB/s), active SOCKS5 sessions, and global query health.
2.  **Resolver Table (`2`)**: Real-time view of every resolver:
    - **RTT**: Current round-trip time in milliseconds.
    - **MTU**: The discovered maximum payload size for that specific path.
    - **Hlth**: Success rate over the last 30 queries (e.g., `28/30`).
    - **EDNS**: Whether the resolver supports EDNS0 extensions.
3.  **Config View (`3`)**: Toggle features like `jitter` or `encryption` live on the fly.

---

## 🛡️ CI Build & Build Artifacts
A comprehensive [.gitignore](https://github.com/bahramiem/qnsdns/blob/main/.gitignore) is included to ensure build artifacts and local configurations are not tracked by git, ensuring clean CI runs in GitHub Actions.
