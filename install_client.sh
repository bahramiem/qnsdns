#!/bin/bash
# ========================================================
# dnstun-client EASY INSTALLER (Ubuntu/Debian/MacOS)
# ========================================================
set -e

echo "Installing dnstun-client..."

# 1. Install system dependencies (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential cmake ninja-build
fi

# 2. Build the project
mkdir -p build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja dnstun-client
cd ..

# 3. Create default config if missing
if [ ! -f "client.ini" ]; then
    echo "Creating default client.ini..."
    cat <<EOF > client.ini
[core]
socks5_bind              = 127.0.0.1:1080
workers                  = 4
threads                  = 2
log_level                = info

[resolvers]
seed_list                = 8.8.8.8, 1.1.1.1, 9.9.9.9
cidr_scan                = false
swarm_sync               = true

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
psk                      = changeme
EOF
fi

echo "Done! Start with: ./build/client/dnstun-client"
echo "Configure your browser to use SOCKS5 proxy: 127.0.0.1:1080"
