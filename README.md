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

### Automated One-Liner (Recommended)

You can run the interactive installation script on Linux (Ubuntu/Debian) to install either the server or the client:

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

## ⚙️ Configuration

Fully documented sample INI files are provided:
- [client.ini](https://github.com/bahramiem/qnsdns/blob/main/client.ini)
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
Run the server on a machine with a public IP (port 53 UDP must be open):
```bash
sudo ./build/server/dnstun-server -c server.ini
```

### 2. Start the Client
Run the client on your local machine:
```bash
./build/client/dnstun-client -c client.ini
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

1.  **Stats Panel (`1`)**: Monitor live throughput (KB/s), active SOCKS5 sessions, global query health, and swarm limits.
2.  **Resolver Table (`2` - Client)**: See the health of every resolver IP loaded via your config, their current AIMD transport window (`cwnd`), measured round-trip time (`RTT`), and MTU. 
3.  **Clients Scoreboard (`2` - Server)**: Because the server doesn't "query" resolvers, opening panel 2 tracks your live inbound users! View a pristine table showing connected IP addresses, their reported `User ID`s, requested MTU limitations, Packet Loss %, and background Encoding mode.
4.  **Config View (`3`)**: Toggle features like `jitter` or `encryption` instantly on the fly.

---

## 🛡️ CI Build & Build Artifacts
A comprehensive [.gitignore](https://github.com/bahramiem/qnsdns/blob/main/.gitignore) is included to ensure build artifacts and local configurations are not tracked by git, ensuring clean CI runs in GitHub Actions.
