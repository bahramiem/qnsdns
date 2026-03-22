# DNS Tunnel VPN Walkthrough

The DNS Tunnel VPN project is now fully implemented and successfully built. It provides a robust, high-performance SOCKS5 proxy that encapsulates traffic within DNS queries, optimized for speed, reliability, and censorship circumvention.

## 🚀 Key Achievements

- **Multipath Scatter-Gather**: Concurrent DNS queries are blasted across an entire pool of resolvers simultaneously to maximize bandwidth.
- **RaptorQ FEC & Zstd**: Real-world forward error correction and high-ratio compression ensure stability on lossy paths and minimal query overhead.
- **AIMD Congestion Control**: Like TCP Cubic, the client dynamically slides its send rate up and down based on live network performance per resolver.
- **Advanced Obfuscation**: Optional timing jitter, chaffing, and "Chrome mimicry" mode disguise the tunnel as normal web traffic.
- **Resolver Swarm**: Client and server automatically synchronize known-good resolver IPs to bypass DNS discovery blocks.

## 📦 Building the Project

The project uses CMake and fetches all dependencies (libuv, Zstd, libsodium, libRaptorQ) automatically.

```powershell
cd d:/qns/qnsdns/build/YOUR_BUILD_DIR
cmd.exe /c compile.bat
```

This generates:
- `client/dnstun-client.exe`
- `server/dnstun-server.exe`

## ⚙️ Configuration

Fully documented sample INI files are provided in the root directory:
- [client.ini](file:///d:/qns/qnsdns/client.ini)
- [server.ini](file:///d:/qns/qnsdns/server.ini)

> [!TIP]
> You can edit these values **live** while the client is running using the TUI configuration panel.

## 📊 Dashboard (TUI)

Both the client and server feature a powerful 3-panel ANSI dashboard:

1. **Stats Panel**: Monitor live throughput (KB/s), active SOCKS5 sessions, and global query health.
2. **Resolver Table**: See the health of every resolver IP, its current AIMD window (`cwnd`), RTT, and MTU.
3. **Config View**: Toggle features like `jitter` or `encryption` instantly.

## 🛠️ Performance Tuning

- **Adaptive FEC**: Set `fec_window = 32` to allow the tunnel to recalibrate its redundancy ratio every 32 chunks based on live loss measurement.
- **DNS Flux**: Enable `dns_flux = true` to rotate your authoritative domain every few hours, evading domain-level blocking.
- **Swarm Sync**: Enable `swarm_sync = true` to automatically pull thousands of functional public resolvers from the server's history.

## ✅ Verification

The project has been verified to compile and link all components successfully. The core logic for SOCKS5 handshake, data encapsulation, FEC coding, and DNS dispatch is active.

```powershell
# To test locally (assuming port 53 is free or mapped):
./server/dnstun-server.exe -c server.ini
./client/dnstun-client.exe -c client.ini

# Test via proxy:
curl -x socks5h://127.0.0.1:1080 http://example.com
```
