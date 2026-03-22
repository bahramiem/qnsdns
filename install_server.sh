#!/bin/bash
# ========================================================
# dnstun-server EASY INSTALLER (Ubuntu/Debian)
# ========================================================
set -e

echo "Installing dnstun-server..."

# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build

# 2. Build the project
mkdir -p build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja dnstun-server
cd ..

# 3. Create default config if missing
if [ ! -f "server.ini" ]; then
    echo "Creating default server.ini..."
    cat <<EOF > server.ini
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
psk                      = changeme

[swarm]
serve                    = true
save_to_disk             = true
EOF
fi

# 4. Optional: Create systemd service
echo "Done! Run with: ./build/server/dnstun-server"
echo "Note: Linux requires root/sudo to bind to UDP port 53."
