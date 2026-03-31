# DNS Tunnel - Redesigned Architecture

## Overview

This document describes the redesigned DNS tunneling system that moves SOCKS5 proxy functionality from the client to the server, with enhanced AI-driven optimizations and modular architecture.

## Architecture Comparison

### Original Architecture
```
Applications → Client (SOCKS5 proxy + DNS encoder) → DNS → Server (DNS decoder + TCP) → Targets
```

### Redesigned Architecture
```
Applications → Server (SOCKS5 proxy + DNS encoder) → DNS → Client (DNS decoder + TCP) → Targets
```

## Key Changes

### 1. Server-Side SOCKS5 Proxy
- Server now handles SOCKS5 protocol parsing and connection management
- External applications connect directly to server via SOCKS5
- Server multiplexes multiple SOCKS5 clients efficiently

### 2. Client as Tunnel Endpoint
- Client focuses solely on DNS tunneling and outbound connections
- Simplified client logic with no SOCKS5 protocol handling
- Client makes direct TCP connections to target hosts

### 3. AI Integration
- Intelligent resolver selection based on network conditions
- Adaptive FEC parameter optimization
- Congestion control using reinforcement learning
- Traffic pattern analysis for compression optimization

### 4. Modular Design
- Separated concerns into distinct modules
- Easy to extend and maintain
- Clear APIs between components

## Building

### Prerequisites
- CMake 3.16+
- C11 compiler
- libuv, libsodium, zstd, libRaptorQ

### Build Commands
```bash
mkdir build
cd build
cmake ..
make
```

### Build Options
- `BUILD_SERVER=ON/OFF` - Build server component
- `BUILD_REDESIGNED=ON/OFF` - Build redesigned architecture versions

### Executables
- `dnstun-server-redesigned` - Redesigned server with SOCKS5 proxy
- `dnstun-client-redesigned` - Redesigned client as tunnel endpoint
- `dnstun-server` - Original server (legacy)
- `dnstun-client` - Original client (legacy)

## Configuration

### Server Configuration (server.ini)
```ini
[core]
socks5_bind = 0.0.0.0:1080    # SOCKS5 listening address
server_bind = 0.0.0.0:53      # DNS listening address
is_server = true

[ai]
enabled = true
ai_model_type = 0              # 0=neural, 1=decision_tree, 2=rl, 3=statistical
ai_model_path = /path/to/models
ai_optimization_interval_ms = 1000
ai_learning_rate = 0.001
ai_max_training_samples = 10000
ai_resolver_selection_weight = 0.7

[domains]
domain1 = example.com
domain2 = tunnel.net
```

### Client Configuration (client.ini)
```ini
[core]
is_server = false

[ai]
enabled = true
# ... same AI options as server
```

## Usage

### Server
```bash
./dnstun-server-redesigned server.ini
```

The server will:
- Listen for SOCKS5 connections on configured port
- Accept DNS queries from clients
- Parse SOCKS5 CONNECT requests
- Tunnel target information to client via DNS
- Forward responses back to SOCKS5 clients

### Client
```bash
./dnstun-client-redesigned client.ini
```

The client will:
- Listen for DNS queries from server
- Decode target connection requests
- Establish outbound TCP connections to targets
- Encode responses back via DNS

### Application Connection
```bash
# Connect to server SOCKS5 proxy
curl --socks5-hostname 127.0.0.1:1080 https://target-website.com
```

## Module Architecture

### Core Modules

#### DNS Tunnel (`shared/dns_tunnel.h/c`)
- Handles encoding/decoding of data through DNS
- Supports bidirectional communication
- FEC and compression integration
- Session management for multiple concurrent tunnels

#### SOCKS5 Proxy (`shared/socks5_proxy.h/c`)
- RFC 1928 compliant SOCKS5 implementation
- Server-side connection handling
- Authentication method negotiation
- Command processing (CONNECT, BIND, UDP ASSOCIATE)

#### Session Manager (`shared/session_mgr.h/c`)
- Manages tunnel sessions and state
- Session lifecycle (create, update, destroy)
- Statistics collection
- Resource cleanup

#### AI Optimizer (`shared/ai_optimizer.h/c`)
- Machine learning driven optimizations
- Network metrics analysis
- Resolver performance prediction
- Adaptive parameter tuning

### Server Modules

#### SOCKS5 Handler (`server/socks5_handler.h/c`)
- Integration between SOCKS5 proxy and DNS tunnel
- Session correlation
- Data forwarding between SOCKS5 clients and tunnels

### Client Modules

#### Target Connector (`client/target_connector.h/c`)
- Outbound TCP connection management
- Connection pooling
- Error handling and retry logic
- Traffic forwarding to/from DNS tunnel

## AI Features

### Intelligent Resolver Selection
- Analyzes network latency, packet loss, and bandwidth
- Predicts resolver performance using ML models
- Balances AI recommendations with traditional metrics

### Adaptive FEC
- Dynamically adjusts Forward Error Correction parameters
- Learns optimal K/M values based on network conditions
- Improves reliability in lossy environments

### Congestion Control
- Reinforcement learning for optimal window sizing
- Adapts to varying network capacities
- Maintains high throughput with low latency

### Traffic Optimization
- Detects application protocols (HTTP, HTTPS, etc.)
- Applies protocol-aware compression
- Optimizes encoding based on traffic patterns

## API Reference

### DNS Tunnel API
```c
// Initialize tunnel module
int dns_tunnel_init(uv_loop_t *loop);

// Create tunnel session
dns_tunnel_session_t* dns_tunnel_session_create(const dns_tunnel_config_t *config);

// Send data through tunnel
int dns_tunnel_send(dns_tunnel_session_t *session, const uint8_t *data, size_t len);

// Process incoming DNS packet
int dns_tunnel_process_packet(dns_tunnel_session_t *session, const uint8_t *packet, size_t len);
```

### SOCKS5 Proxy API
```c
// Initialize proxy module
int socks5_proxy_init(uv_loop_t *loop);

// Create proxy server
socks5_server_t* socks5_server_create(const socks5_config_t *config);

// Start proxy server
int socks5_server_start(socks5_server_t *server);

// Send reply to client
int socks5_client_send_reply(socks5_client_t *client, uint8_t reply_code);
```

### AI Optimizer API
```c
// Initialize AI optimizer
int ai_optimizer_init(const ai_config_t *config);

// Optimize resolver selection
int ai_optimize_resolver_selection(const network_metrics_t *metrics, ai_result_t *result);

// Update AI model with data
int ai_update_model(const network_metrics_t *metrics, const session_stats_t *stats);
```

## Migration Guide

### From Original Architecture

1. **Update Configuration**
   - Move `socks5_bind` from client to server config
   - Add AI configuration sections
   - Update domain settings

2. **Change Deployment**
   - Deploy server with internet access for SOCKS5 connections
   - Deploy client in environments needing outbound access
   - Update application proxy settings to point to server

3. **Update Build Process**
   - Enable `BUILD_REDESIGNED` option
   - Use new executable names
   - Update startup scripts

## Performance Considerations

### Advantages
- **Server Efficiency**: Server can optimize resource usage across multiple clients
- **Client Simplicity**: Reduced client complexity improves stability
- **AI Optimization**: Intelligent adaptation to network conditions
- **Scalability**: Better support for many concurrent connections

### Considerations
- **Server Load**: SOCKS5 proxy increases server-side processing
- **Network Requirements**: Client needs outbound TCP access to targets
- **AI Overhead**: ML computations add CPU overhead (configurable)

## Troubleshooting

### Common Issues

#### SOCKS5 Connection Refused
- Check server SOCKS5 bind address and port
- Verify firewall allows connections to server
- Check server logs for authentication errors

#### DNS Tunnel Not Working
- Verify DNS server (port 53) is accessible
- Check domain configuration
- Monitor DNS query/response patterns

#### AI Optimization Not Working
- Ensure AI is enabled in configuration
- Check model file paths
- Verify training data availability

### Debug Logging
Enable debug logging in configuration:
```ini
[core]
log_level = 2  # 0=silent, 1=info, 2=debug
```

### Performance Monitoring
Use the built-in TUI for real-time monitoring:
- Session counts and statistics
- Network throughput metrics
- AI optimization status
- Error rates and patterns

## Future Enhancements

### Planned Features
- **Advanced ML Models**: Deep learning for traffic classification
- **Protocol Detection**: Automatic protocol-aware optimization
- **Multi-Region Support**: Geographic load balancing
- **Security Enhancements**: Advanced encryption options
- **Cloud Integration**: Managed service deployment

### Research Areas
- **Quantum-Resistant Crypto**: Post-quantum encryption integration
- **Edge Computing**: Client-side AI inference
- **5G Optimization**: Mobile network-specific adaptations
- **IoT Support**: Low-power device optimizations

## Contributing

### Development Setup
1. Fork the repository
2. Create feature branch
3. Implement changes following modular architecture
4. Add comprehensive tests
5. Update documentation
6. Submit pull request

### Code Standards
- Follow C11 standards
- Use libuv asynchronous patterns
- Implement proper error handling
- Add Doxygen-style documentation
- Maintain thread safety

### Testing
- Unit tests for each module
- Integration tests for end-to-end functionality
- Performance benchmarks
- AI model validation tests

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: GitHub issue tracker
- **Discussions**: GitHub discussions
- **Documentation**: This README and inline code documentation
- **Community**: DNS tunneling and censorship circumvention forums