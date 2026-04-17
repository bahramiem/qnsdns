#!/usr/bin/env bash
# Fast Install (Pre-compiled Binary):
# curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/fast_install.sh | bash
# ========================================================
set -euo pipefail

echo "==========================================================="
echo "  dnstun Fast Installation Script (Pre-compiled)"
echo "==========================================================="
echo ""
echo "Please select what you want to install:"
echo "  1) dnstun-server (for the remote VPS/server)"
echo "  2) dnstun-client (for your local machine/router)"
echo "  3) Cancel"
echo ""

# When piping script via 'curl | bash', stdin is closed. We must read from /dev/tty.
read -p "Enter choice [1-3]: " choice < /dev/tty

if [ "$choice" == "1" ]; then
    INSTALL_TYPE="server"
    TARGET_BIN="dnstun-server-linux-amd64"
    FINAL_BIN="dnstun-server"
elif [ "$choice" == "2" ]; then
    INSTALL_TYPE="client"
    TARGET_BIN="dnstun-client-linux-amd64"
    FINAL_BIN="dnstun-client"
else
    echo "Installation cancelled."
    exit 0
fi

echo ""
echo "==> OS Architecture Check..."
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "ERROR: Pre-compiled binaries are for Linux only." >&2
    exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "ERROR: Pre-compiled binaries generated are currently for x86_64/amd64 architecture only." >&2
    exit 1
fi

echo "==> Installing runtime dependencies..."
sudo apt-get update -qq
# Note: Since the releases are built dynamically on Ubuntu-latest, we need
# the runtime versions of the developer libraries:
sudo apt-get install -y curl xxd libuv1 libzstd1 libsodium23

echo "==> Downloading latest release binary..."
DOWNLOAD_URL="https://github.com/bahramiem/qnsdns/releases/download/latest/$TARGET_BIN"
echo "    Downloading from $DOWNLOAD_URL"
if ! curl -f -sSL "$DOWNLOAD_URL" -o "$FINAL_BIN"; then
    echo "ERROR: Failed to download the executable! (Has the GitHub Action finished building 'latest'?)" >&2
    exit 1
fi
chmod +x "$FINAL_BIN"

# ── Create default config if missing ────────────────────────────────────────
if [ "$INSTALL_TYPE" == "server" ]; then
    if [ ! -f "server.ini" ]; then
        echo "==> Creating default server.ini..."
        RANDOM_PSK=$(head -c 16 /dev/urandom | xxd -p)
        cat > server.ini <<EOF
[core]
server_bind              = 0.0.0.0:53
workers                  = 4
threads                  = 2
log_level                = info
user_id                  = default

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
else
    if [ ! -f "client.ini" ]; then
        echo "==> Creating default client.ini..."
        cat > client.ini <<'EOF'
[core]
socks5_bind              = 127.0.0.1:1080
workers                  = 4
threads                  = 2
log_level                = info
user_id                  = laptop_1

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
fi

# ── Done ────────────────────────────────────────────────────────────────────
BINARY="$(pwd)/$FINAL_BIN"
echo ""
echo "==> Fast Install Done!"
echo "    Binary : $BINARY"
if [ "$INSTALL_TYPE" == "server" ]; then
    echo "    Config : $(pwd)/server.ini"
    echo ""
    echo "    Run (requires root to bind UDP port 53):"
    echo "      sudo $BINARY"
else
    echo "    Config : $(pwd)/client.ini"
    echo ""
    echo "    Run:"
    echo "      $BINARY"
    echo ""
    echo "    Configure proxy: socks5h://127.0.0.1:1080"
fi

echo ""
read -p "==> Do you want to start $FINAL_BIN now? [y/N] " run_now < /dev/tty
if [[ "$run_now" =~ ^[Yy]$ ]]; then
    echo "    Starting $FINAL_BIN..."
    if [ "$INSTALL_TYPE" == "server" ]; then
        sudo ./$FINAL_BIN
    else
        ./$FINAL_BIN
    fi
else
    echo "    To start later, run: $( [ "$INSTALL_TYPE" == "server" ] && echo "sudo " )./$FINAL_BIN"
fi
