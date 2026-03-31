# Redesigned DNS Tunnel Architecture

## Overview
This document outlines the redesigned architecture for the DNS tunneling system, shifting from client-side SOCKS5 proxy to server-side SOCKS5 proxy with AI integration capabilities.

## Current Architecture Problems
- **Client Complexity**: Client handles both SOCKS5 protocol parsing and complex DNS tunneling logic (FEC, congestion control, multipath)
- **Server Simplicity**: Server only handles DNS decoding and TCP connections to targets
- **Limited AI Integration**: No structured points for AI-driven optimizations

## New Architecture: Server-Side SOCKS5 Proxy

### Component Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SOCKS5 Apps   │────│   Server        │────│   Client        │
│                 │    │ (SOCKS5 Proxy)  │    │ (Tunnel Endpoint)│
│ curl, browsers  │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                              │                        │
                              ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  DNS Tunnel     │    │  DNS Tunnel     │
                       │  (Encoding)     │    │  (Decoding)     │
                       └─────────────────┘    └─────────────────┘
                              │                        │
                              │                        │
                              ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  DNS Resolvers  │    │ Target Hosts     │
                       └─────────────────┘    └─────────────────┘
```

### Data Flow

1. **SOCKS5 Connection**: External applications connect to server via SOCKS5
2. **Protocol Parsing**: Server parses SOCKS5 CONNECT request, extracts target host/port
3. **DNS Encoding**: Server encodes target info + application data into DNS queries
4. **Tunnel Transmission**: DNS queries travel through resolver network to client
5. **Target Connection**: Client decodes DNS queries, establishes TCP connections to targets
6. **Response Tunneling**: Client encodes responses back through DNS to server
7. **SOCKS5 Response**: Server forwards responses to SOCKS5 clients

### Modular File Structure

```
shared/
├── dns_tunnel.c/.h      # Core DNS encoding/decoding logic
├── socks5_proxy.c/.h    # SOCKS5 protocol implementation
├── session_mgr.c/.h     # Session state management
├── ai_optimizer.c/.h    # AI-driven optimization hooks
└── config.c/.h          # Configuration management

server/
├── main.c               # Server entry point with SOCKS5 listener
├── socks5_handler.c/.h  # SOCKS5 connection management
└── dns_encoder.c/.h     # DNS query generation

client/
├── main.c               # Client entry point as tunnel endpoint
├── target_connector.c/.h # Outbound connection handling
└── dns_decoder.c/.h     # DNS response processing
```

### AI Integration Points

#### 1. Intelligent Resolver Selection
- ML model predicts resolver performance based on:
  - Historical latency measurements
  - Geographic location
  - Network conditions
- API: `ai_select_resolvers(session_id, target_info, resolver_pool)`

#### 2. Adaptive FEC Configuration
- AI adjusts FEC parameters based on:
  - Packet loss patterns
  - Bandwidth measurements
  - Session requirements
- API: `ai_optimize_fec(session_id, current_stats)`

#### 3. Congestion Control Optimization
- Reinforcement learning for congestion window management
- Predicts optimal window sizes based on network conditions
- API: `ai_adjust_congestion(session_id, network_metrics)`

#### 4. Traffic Pattern Analysis
- Detects application protocols for optimization
- Applies protocol-specific compression/encoding
- API: `ai_analyze_traffic(session_data, traffic_stats)`

### Configuration Changes

```ini
[core]
# Server now handles SOCKS5 binding
socks5_bind = 0.0.0.0:1080  # Server listens for SOCKS5 connections
server_bind = 0.0.0.0:53    # DNS listener (unchanged)

[ai]
enabled = true
model_path = /path/to/models
optimization_interval_ms = 1000
learning_rate = 0.001

[resolver_selection]
ai_weight = 0.7  # Balance between AI prediction and traditional metrics
fallback_mode = latency  # latency, random, round_robin
```

### Session Management

#### Server Sessions
- Track SOCKS5 client connections
- Maintain mapping between SOCKS5 sessions and DNS tunnel sessions
- Handle SOCKS5 protocol state machines

#### Client Sessions
- Track target host connections
- Maintain DNS query/response correlation
- Handle outbound connection pooling

### Benefits of New Architecture

1. **Simplified Client**: Client focuses solely on DNS tunneling and target connections
2. **Centralized Control**: Server manages all SOCKS5 connections and can apply policies
3. **AI Integration**: Structured hooks for machine learning optimizations
4. **Scalability**: Server can multiplex multiple SOCKS5 clients efficiently
5. **Deployment Flexibility**: Server can be deployed as a service, client as lightweight endpoint

### Migration Strategy

1. **Phase 1**: Implement server-side SOCKS5 proxy alongside existing client proxy
2. **Phase 2**: Move DNS encoding logic to server
3. **Phase 3**: Simplify client to tunnel-only operation
4. **Phase 4**: Add AI optimization modules
5. **Phase 5**: Remove legacy client SOCKS5 code

### Compatibility Considerations

- **DNS Protocol**: Maintain backward compatibility with existing DNS tunneling format
- **SOCKS5 Compliance**: Full RFC 1928 compliance for maximum compatibility
- **Configuration**: Support both old and new configuration formats during transition