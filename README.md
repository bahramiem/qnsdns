# qnsdns: High-Performance DNS Tunnel VPN 🚀

**qnsdns** (also referred to as `dnstun`) is a cutting-edge SOCKS5 proxy that encapsulates all your real web traffic inside standard DNS queries. It is meticulously engineered for speed, absolute reliability, and evading Deep Packet Inspection (DPI) in heavily restricted environments.

By hiding your traffic inside identical-looking DNS TXT queries, `qnsdns` allows you to bypass captive portals, public Wi-Fi limitations, and national firewalls.

---

## 🧠 How It Works (Implementation Details)

Unlike traditional OpenVPN or WireGuard which use a dedicated port, modern network firewalls often block unknown UDP/TCP traffic. However, almost all networks allow **DNS (Port 53)** traffic because without it, the internet simply doesn't work.

1. **Scatter-Gather Multiplexing**: Instead of sending all queries to a single DNS server (which would look suspicious and run very slowly), the client "scatters" concurrent DNS queries across a huge swarm of public resolvers (like `8.8.8.8` and `1.1.1.1`).
2. **Forward Error Correction (FEC)**: DNS protocols natively drop packets over UDP. Instead of relying on slow TCP-like retransmissions, this implementation uses advanced Forward Error Correction (Forward Error Correction - RaptorsQ / Reed-Solomon) to send "parity" math equations alongside the data. If a packet drops, the receiver solves the math equation to permanently recover the lost data without asking for it again!
3. **AIMD Congestion Control**: Similar to TCP Cubic, the active client tracks the health of every single DNS resolver. If a resolver gets overloaded, the client smoothly slides down the allowed requests (Congestion Window) and shifts the traffic to faster resolvers in real time.
4. **Active Obfuscation**: The tunnel optionally adds randomized time delays (Jitter), fake decoy queries (Chaffing), and disguises its query structure to look perfectly identical to a vanilla Google Chrome browser.

---

## ⚙️ Configuration & Network Tuning

When you run the binaries, the system utilizes the `client.ini` and `server.ini` files. 
You can edit these files dynamically—press `3` on your keyboard while the client is running to open the live configuration panel!

### 🛡️ Forward Error Correction (FEC) Settings
Because DNS is carried over UDP, packet loss is entirely normal. The `[tuning]` section in `client.ini` determines how aggressively the application fights packet loss.

* **`fec_window`**: How many data chunks are combined together before a parity equation is generated. Smaller windows fix losses *faster* but use more CPU.
* **`fec_repair_rate`**: Fixed percentage of overhead "repair" symbols to automatically generate (e.g. `25` = 25% mathematical overhead). Set this to `0` to let the system auto-adapt based on live latency.

#### 🌍 Profiles for Different Networks

**1. Fast & Stable Networks (Ethernet / Good Home Wi-Fi)**
Your internet rarely drops packets. You prioritize max bandwidth.
```ini
[tuning]
fec_window       = 64    ; Larger window (saves CPU overhead)
fec_repair_rate  = 0     ; Auto-adapt (minimal overhead)
poll_interval_ms = 50    ; High responsiveness
cwnd_max         = 512   ; High parallelism
```

**2. Lossy Networks (Coffee Shop Public Wi-Fi / Overloaded Cellular)**
Your connection frequently drops data. You prioritize stability over raw bandwidth.
```ini
[tuning]
fec_window       = 16    ; Small window (recovers lost packets instantly)
fec_repair_rate  = 25    ; Pre-send 25% redundant repair packets
poll_interval_ms = 100   ; Balanced polling
cwnd_max         = 256   ; Prevent overloading the fragile router
```

**3. High-Latency Networks (Satellite / Remote Deep Cellular)**
Packets don't drop, but they take 600ms+ to arrive. You need to blast as much info as possible simultaneously.
```ini
[tuning]
fec_window       = 32    ; Balanced window
fec_repair_rate  = 5     ; Minimal static repair overhead
poll_interval_ms = 200   ; Slower polling (saves bandwidth over satellite)
cwnd_max         = 1024  ; Blast enormous amounts of queries simultaneously
```

---

## 🚀 Installation Guide

### Fast Install (Ubuntu / Debian x86_64)
Run this single command to fetch the latest pre-compiled binaries:
```bash
curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/fast_install.sh | bash
```

### Manual Compilation
For security enthusiasts who want to compile from source natively:
```bash
sudo apt install build-essential cmake ninja-build
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
```

---

## 📖 Usage Guide

Both nodes feature an integrated ANSI Dashboard. Use your `Number Keys` (1, 2, 3) to switch panels and monitor health, live resolvers, and config!

### 1. Launch the Server
The Server must be run on a cloud VPS with port 53 UDP open. Remember to edit `server.ini`, or let the app prompt you for your Domain.
```bash
sudo ./build/server/dnstun-server
```

### 2. Launch the Client
Run your client locally. It will auto-locate `client.ini`.
```bash
./build/client/dnstun-client
```

### 3. Connect Apps!
Configure Firefox, Chrome, or any application to use the SOCKS5 proxy running precisely at `127.0.0.1:1080`!

```bash
# Test command!
curl -x socks5h://127.0.0.1:1080 http://example.com
```

---

### Security Note
If you want to prevent unauthorized users from using your Server, define a custom string in the `[encryption]` -> `psk` section of both your `client.ini` and `server.ini`. Any clients not providing this Pre-Shared Key will be silently dropped.
