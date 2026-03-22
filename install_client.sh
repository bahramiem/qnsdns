# Quick Install:
# curl -sSL https://raw.githubusercontent.com/bahramiem/qnsdns/main/install_client.sh | bash
# ========================================================
set -e

echo "Installing dnstun-client..."

# Force clear build directory to purge any old Git configuration for dependencies.
rm -rf build 

# 1. Ensure git is installed (required for cloning)
if ! command -v git &> /dev/null; then
    echo "Installing git..."
    sudo apt-get update
    sudo apt-get install -y git
fi

# 2. Download source code if not present
if [ ! -f "CMakeLists.txt" ]; then
    echo "Source code not found. Initializing repository..."
    git clone --depth 1 https://github.com/bahramiem/qnsdns.git qnsdns
    cd qnsdns
fi

# 3. Install system dependencies (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential cmake ninja-build liblz4-dev
fi

# 3. Build the project
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
