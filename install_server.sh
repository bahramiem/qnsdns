#!/usr/bin/env bash
# Quick Install (run from an empty directory):
# curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/install_server.sh | bash
# ========================================================
set -euo pipefail

echo "==> Installing dnstun-server..."

# ── 1. OS check ────────────────────────────────────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "ERROR: This script only supports Linux (Debian/Ubuntu)." >&2
    exit 1
fi

# ── 2. Install system dependencies ─────────────────────────────────────────
echo "==> Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y git build-essential cmake ninja-build pkg-config libuv1-dev libzstd-dev liblz4-dev libsodium-dev

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
echo "==> Building dnstun-server..."
# Only wipe build dir if it is stale (CMakeCache.txt missing)
if [ ! -f "build/CMakeCache.txt" ]; then
    rm -rf build
fi
mkdir -p build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja dnstun-server
cd ..

# ── 5. Create default config if missing ────────────────────────────────────
if [ ! -f "server.ini" ]; then
    echo "==> Creating default server.ini..."
    # Generate a random 32-char hex PSK so users don't deploy with 'changeme'
    RANDOM_PSK=$(head -c 16 /dev/urandom | xxd -p)
    cat > server.ini <<EOF
[core]
server_bind              = 0.0.0.0:53
workers                  = 4
threads                  = 2
log_level                = info

[tuning]
idle_timeout_sec         = 120

[domains]
list                     = tun.example.com

[encryption]
enabled                  = false
cipher                   = chacha20
psk                      = ${RANDOM_PSK}

[swarm]
serve                    = true
save_to_disk             = true
EOF
    echo "    PSK written to server.ini: ${RANDOM_PSK}"
    echo "    Copy this PSK into your client.ini [encryption] psk ="
fi

# ── Done ────────────────────────────────────────────────────────────────────
BINARY="$(pwd)/build/dnstun-server"
echo ""
echo "==> Done!"
echo "    Binary : $BINARY"
echo "    Config : $(pwd)/server.ini"
echo ""
echo "    Run (requires root to bind UDP port 53):"
echo "      sudo $BINARY -c $(pwd)/server.ini"
