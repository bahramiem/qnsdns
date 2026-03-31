#!/usr/bin/env bash
# Fast Install (Pre-compiled Binary):
# curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/fast_install.sh | bash
# ========================================================
set -euo pipefail

echo "==========================================================="
echo "  dnstun Fast Installation Script (Pre-compiled)"
echo "==========================================================="
echo ""
echo "Please select architecture:"
echo "  1) Original Architecture"
echo "  2) Redesigned Architecture (AI-enhanced, server-side SOCKS5)"
echo ""

# When piping script via 'curl | bash', stdin is closed. We must read from /dev/tty.
read -p "Enter choice [1-2]: " arch_choice < /dev/tty

if [ "$arch_choice" == "1" ]; then
    ARCH_TYPE="original"
    echo ""
    echo "Please select what you want to install:"
    echo "  1) dnstun-server (for the remote VPS/server)"
    echo "  2) dnstun-client (for your local machine/router)"
    echo "  3) Cancel"
elif [ "$arch_choice" == "2" ]; then
    ARCH_TYPE="redesigned"
    echo ""
    echo "Please select what you want to install:"
    echo "  1) dnstun-server-redesigned (SOCKS5 proxy + DNS encoder)"
    echo "  2) dnstun-client-redesigned (tunnel endpoint)"
    echo "  3) Cancel"
else
    echo "Invalid architecture choice."
    exit 1
fi

echo ""
# When piping script via 'curl | bash', stdin is closed. We must read from /dev/tty.
read -p "Enter choice [1-3]: " choice < /dev/tty

if [ "$choice" == "1" ]; then
    INSTALL_TYPE="server"
    if [ "$ARCH_TYPE" == "original" ]; then
        TARGET_BIN="dnstun-server-linux-amd64"
        FINAL_BIN="dnstun-server"
    else
        TARGET_BIN="dnstun-server-redesigned-linux-amd64"
        FINAL_BIN="dnstun-server-redesigned"
    fi
elif [ "$choice" == "2" ]; then
    INSTALL_TYPE="client"
    if [ "$ARCH_TYPE" == "original" ]; then
        TARGET_BIN="dnstun-client-linux-amd64"
        FINAL_BIN="dnstun-client"
    else
        TARGET_BIN="dnstun-client-redesigned-linux-amd64"
        FINAL_BIN="dnstun-client-redesigned"
    fi
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
if [ "$ARCH_TYPE" == "redesigned" ]; then
    # Redesigned architecture configuration
    if [ "$INSTALL_TYPE" == "server" ]; then
        if [ ! -f "server_redesigned.ini" ]; then
            echo "==> Creating default server_redesigned.ini..."
            RANDOM_PSK=$(head -c 16 /dev/urandom | xxd -p)
            cat > server_redesigned.ini <<EOF
[core]
socks5_bind              = 0.0.0.0:1080
server_bind              = 0.0.0.0:53
is_server               = true
workers                  = 4
threads                  = 2
log_level                = info

[tuning]
idle_timeout_sec         = 120

[domains]
domain1                  = tun.example.com

[encryption]
enabled                  = false
cipher                   = chacha20
psk                      = ${RANDOM_PSK}

[ai]
enabled                  = true
ai_model_type            = 0
ai_optimization_interval_ms = 1000
ai_learning_rate         = 0.001
EOF
            echo "    PSK written to server_redesigned.ini: ${RANDOM_PSK}"
            echo "    Copy this PSK into your client_redesigned.ini [encryption] psk ="
        fi
        CONFIG_FILE="server_redesigned.ini"
    else
        if [ ! -f "client_redesigned.ini" ]; then
            echo "==> Creating default client_redesigned.ini..."
            cat > client_redesigned.ini <<'EOF'
[core]
is_server               = false
workers                  = 4
threads                  = 2
log_level                = info

[tuning]
idle_timeout_sec         = 120

[domains]
domain1                  = tun.example.com

[encryption]
enabled                  = false
psk                      = REPLACE_WITH_SERVER_PSK

[ai]
enabled                  = true
ai_model_type            = 0
ai_optimization_interval_ms = 1000
ai_learning_rate         = 0.001
EOF
            echo ""
            echo "    IMPORTANT: edit client_redesigned.ini and set:"
            echo "      [domains] domain1   = your.server.domain"
            echo "      [encryption] psk    = (copy from server_redesigned.ini)"
        fi
        CONFIG_FILE="client_redesigned.ini"
    fi
else
    # Original architecture configuration
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
        CONFIG_FILE="server.ini"
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
        CONFIG_FILE="client.ini"
    fi
fi

# ── Done ────────────────────────────────────────────────────────────────────
BINARY="$(pwd)/$FINAL_BIN"
echo ""
echo "==> Fast Install Done!"
echo "    Binary : $BINARY"
echo "    Config : $(pwd)/$CONFIG_FILE"
echo ""

if [ "$ARCH_TYPE" == "redesigned" ]; then
    if [ "$INSTALL_TYPE" == "server" ]; then
        echo "    Run (may require root to bind UDP port 53):"
        echo "      $BINARY $CONFIG_FILE"
        echo ""
        echo "    External applications connect to: socks5h://your-server:1080"
    else
        echo "    Run:"
        echo "      $BINARY $CONFIG_FILE"
        echo ""
        echo "    This client acts as a tunnel endpoint and makes outbound connections."
    fi
else
    if [ "$INSTALL_TYPE" == "server" ]; then
        echo "    Run (requires root to bind UDP port 53):"
        echo "      sudo $BINARY"
    else
        echo "    Run:"
        echo "      $BINARY"
        echo ""
        echo "    Configure proxy: socks5h://127.0.0.1:1080"
    fi
fi
