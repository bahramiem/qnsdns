#!/usr/bin/env bash
# Quick Install (run from an empty directory):
# curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/install_client.sh | bash
# ========================================================
set -euo pipefail

echo "==> Installing dnstun-client..."

# ── 1. OS check ────────────────────────────────────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "ERROR: This script only supports Linux (Debian/Ubuntu)." >&2
    exit 1
fi

# ── 2. Install system dependencies ─────────────────────────────────────────
echo "==> Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y git build-essential cmake ninja-build liblz4-dev

# ── 3. Clone source code if not already present ────────────────────────────
REPO_DIR="qnsdns"
if [ ! -f "CMakeLists.txt" ]; then
    if [ ! -d "$REPO_DIR" ]; then
        echo "==> Cloning repository..."
        git clone --depth 1 https://github.com/bahramiem/qnsdns.git "$REPO_DIR"
    fi
    cd "$REPO_DIR"
fi

# ── 4. Build ────────────────────────────────────────────────────────────────
echo "==> Building dnstun-client..."
# Only wipe build dir if it is stale (CMakeCache.txt missing)
if [ ! -f "build/CMakeCache.txt" ]; then
    rm -rf build
fi
mkdir -p build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja dnstun-client
cd ..

# ── 5. Create default config if missing ────────────────────────────────────
if [ ! -f "client.ini" ]; then
    echo "==> Creating default client.ini..."
    # PSK placeholder — replace with the value from your server.ini
    cat > client.ini <<'EOF'
[core]
socks5_bind              = 127.0.0.1:1080
workers                  = 4
threads                  = 2
log_level                = info

[resolvers]
seed_list                = 8.8.8.8, 1.1.1.1, 9.9.9.9
cidr_scan                = false
swarm_sync               = false

[tuning]
poll_interval_ms         = 100
fec_window               = 32
cwnd_init                = 16
cwnd_max                 = 512

[domains]
list                     = tun.example.com
dns_flux                 = false

[encryption]
enabled                  = false
psk                      = REPLACE_WITH_SERVER_PSK
EOF
    echo ""
    echo "    IMPORTANT: edit client.ini and set:"
    echo "      [domains] list      = your.server.domain"
    echo "      [encryption] psk    = (copy from server.ini)"
fi

# ── Done ────────────────────────────────────────────────────────────────────
BINARY="$(pwd)/build/dnstun-client"
echo ""
echo "==> Done!"
echo "    Binary : $BINARY"
echo "    Config : $(pwd)/client.ini"
echo ""
echo "    Run:"
echo "      $BINARY -c $(pwd)/client.ini"
echo ""
echo "    Configure proxy: socks5h://127.0.0.1:1080"
