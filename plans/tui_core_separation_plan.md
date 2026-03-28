# DNSTUN TUI/Core Separation Architecture Plan

## Executive Summary

This document outlines the technical plan for decoupling the DNSTUN Text User Interface (TUI) from the core tunnel logic using a **Control Socket Model**. This architecture enables carrier-grade stability by ensuring the tunnel continues operating even if the TUI crashes or is disconnected.

---

## Current State (Monolithic Architecture)

Both client and server currently run TUI code directly in the same process as the tunnel logic:

- **TUI Timer**: 1-second libuv timer calling `tui_render()`
- **TTY Handler**: Raw mode stdin reading for keyboard input
- **Shared Memory**: Direct access to `tui_stats_t`, `resolver_pool_t`, etc.
- **Single Point of Failure**: TUI crash kills the entire tunnel

### Problems

1. **No Remote Management**: Cannot manage headless servers
2. **Resource Contention**: TUI rendering competes with I/O workers
3. **Limited Concurrency**: Only one TUI instance per core
4. **Uptime Risk**: Terminal disconnect kills tunnel

---

## Target State (Decoupled Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│                     Control Socket Model                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐      Telemetry      ┌──────────────────┐  │
│  │   TUI Client     │ ◄────────────────── │   dnstun-core    │  │
│  │  (Standalone)    │                     │   (Headless)     │  │
│  │                  │ ──────────────────► │                  │  │
│  │  • Rendering     │      Commands       │  • Tunnel Logic  │  │
│  │  • User Input    │                     │  • Management    │  │
│  │  • State Cache   │                     │    Server        │  │
│  └──────────────────┘                     └──────────────────┘  │
│           ▲                                          │           │
│           │                                          │           │
│           └────────────── TCP/Unix ──────────────────┘           │
│                      127.0.0.1:9090                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Benefits

1. **Zero Impact on Uptime**: TUI disconnect doesn't affect traffic flow
2. **Multiple TUIs**: Several administrators can monitor simultaneously
3. **Remote Management**: SSH tunnel the control port for remote TUI
4. **Security**: Localhost-only binding prevents unauthorized access

---

## Phase-by-Phase Implementation

### Phase 0: Foundation - Protocol Definitions

Create `shared/mgmt_protocol.h` with frame structures:

**Telemetry Frame (Core → TUI)**:
```c
typedef struct {
    uint32_t magic;          /* 'DNST' = 0x444E5354 */
    uint16_t version;        /* Protocol version */
    uint16_t frame_type;     /* 0x01 = TELEMETRY */
    uint32_t sequence;       /* Monotonic counter */
    uint64_t timestamp_ns;   /* High-res timestamp */
    
    /* Stats payload */
    double   tx_bytes_sec;
    double   rx_bytes_sec;
    uint64_t tx_total;
    uint64_t rx_total;
    uint32_t active_sessions;
    uint32_t active_resolvers;
    /* ... more fields ... */
} mgmt_telemetry_frame_t;
```

**Command Frame (TUI → Core)**:
```c
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t frame_type;     /* 0x02 = COMMAND */
    uint32_t command_id;     /* Unique ID for response matching */
    uint32_t cmd_type;       /* TOGGLE_ENCRYPTION, etc. */
    uint32_t payload_len;
    /* payload follows... */
} mgmt_command_frame_t;
```

**Command Types**:
- `CMD_TOGGLE_ENCRYPTION`
- `CMD_SET_BANDWIDTH_LIMIT`
- `CMD_CLOSE_SESSION`
- `CMD_FLUSH_LOGS`
- `CMD_GET_CONFIG`
- `CMD_SET_CONFIG_KEY`

---

### Phase 1: Core Management Module

Create `shared/mgmt.h` and `shared/mgmt.c`:

**Server-side API**:
```c
/* Initialize management server on specified bind address */
int mgmt_init(uv_loop_t *loop, const char *bind_addr, 
              int port, mgmt_callbacks_t *callbacks);

/* Shutdown management server */
void mgmt_cleanup(void);

/* Push telemetry update to all connected TUI clients */
void mgmt_broadcast_telemetry(const tui_stats_t *stats);

/* Register command handler */
void mgmt_register_handler(uint32_t cmd_type, 
                           mgmt_handler_fn handler);
```

**Implementation Details**:
- Use libuv `uv_tcp_t` for cross-platform compatibility
- Support both TCP (127.0.0.1:9090) and Unix Domain Sockets
- Frame-based protocol with length prefix
- JSON for human-readable debugging, binary for performance

---

### Phase 2: Server Integration

Modify `server/main.c`:

1. **Add management initialization**:
```c
static void on_mgmt_command(uint32_t cmd_type, const void *payload, 
                            size_t len, mgmt_response_t *resp);

/* In main() */
mgmt_callbacks_t cb = {
    .on_close_session = handle_close_session_cmd,
    .on_get_clients = handle_get_clients_cmd,
    .on_flush_logs = handle_flush_logs_cmd
};
mgmt_init(g_loop, "127.0.0.1", 9090, &cb);
```

2. **Wire telemetry**:
```c
static void on_tui_timer(uv_timer_t *t) {
    /* Update stats... */
    mgmt_broadcast_telemetry(&g_stats);
}
```

3. **Remove direct TUI dependency** (optional, for headless mode):
```c
#ifdef HEADLESS_MODE
    /* Skip TUI initialization, use mgmt only */
#else
    /* Keep embedded TUI for backward compatibility */
#endif
```

---

### Phase 3: Client Integration

Modify `client/main.c` similarly:

1. **Add management server** for client core
2. **Wire client-specific stats** (resolver pool, SOCKS5 sessions)
3. **Add client commands**:
   - `TOGGLE_ENCRYPTION`
   - `SET_BANDWIDTH_LIMIT`
   - `ADD_RESOLVER`
   - `REMOVE_RESOLVER`

---

### Phase 4: Standalone TUI

Create `tui-standalone/` directory:

```
tui-standalone/
├── main.c           /* Entry point, connection management */
├── mgmt_client.c    /* Management protocol client */
├── mgmt_client.h
├── renderer.c       /* Ported from shared/tui.c */
├── renderer.h
└── CMakeLists.txt
```

**Key Components**:

1. **Management Client** (`mgmt_client.c`):
```c
typedef struct {
    uv_tcp_t socket;
    tui_stats_t cached_stats;
    resolver_pool_t cached_pool;
    /* Reconnection state */
    int reconnect_attempts;
    uint64_t last_reconnect_ms;
} mgmt_client_t;

int mgmt_client_connect(const char *host, int port);
int mgmt_client_send_command(uint32_t cmd_type, const void *payload);
```

2. **State Caching**: TUI maintains local copy of stats, updated by telemetry frames

3. **Reconnection Logic**: Exponential backoff when core is unreachable

---

### Phase 5: Cross-Platform Support

**Windows Named Pipes**:
```c
#ifdef _WIN32
    /* Use named pipes for local communication */
    HANDLE pipe = CreateNamedPipe("\\\\.\\pipe\\dnstun_mgmt", ...);
#else
    /* Use Unix Domain Sockets */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_path = "/var/run/dnstun.sock"};
#endif
```

**Transport Selection**:
- Default: TCP loopback (127.0.0.1:9090) - universal
- Optional: Unix sockets on Linux/macOS for better security
- Optional: Named pipes on Windows for native feel

---

### Phase 6: Testing & Documentation

**Test Scenarios**:
1. Start core, connect TUI, verify telemetry display
2. Kill TUI, verify core continues running
3. Reconnect TUI, verify state resynchronization
4. Connect multiple TUIs simultaneously
5. SSH tunnel test: `ssh -L 9090:localhost:9090 remote-server`

**Documentation**:
- Management protocol specification
- API reference for commands
- Migration guide from monolithic
- Security hardening guide

---

## File Structure Changes

```
dnstun/
├── shared/
│   ├── mgmt_protocol.h      /* NEW: Frame definitions */
│   ├── mgmt.h               /* NEW: Server-side API */
│   ├── mgmt.c               /* NEW: Server implementation */
│   ├── tui.h                /* EXISTING: Keep for embedded mode */
│   └── tui.c                /* EXISTING: Keep for embedded mode */
├── tui-standalone/          /* NEW: Directory */
│   ├── main.c
│   ├── mgmt_client.h        /* NEW: Client-side API */
│   ├── mgmt_client.c        /* NEW: Client implementation */
│   ├── renderer.h           /* NEW: Ported rendering */
│   ├── renderer.c           /* NEW: Ported rendering */
│   └── CMakeLists.txt       /* NEW: Build config */
├── client/
│   └── main.c               /* MODIFIED: Add mgmt_init() */
├── server/
│   └── main.c               /* MODIFIED: Add mgmt_init() */
└── CMakeLists.txt           /* MODIFIED: Add tui-standalone target */
```

---

## Backward Compatibility Strategy

The monolithic TUI remains functional during migration:

1. **Phase 1-3**: Add management layer alongside existing TUI
2. **Phase 4**: Standalone TUI can connect to upgraded cores
3. **Phase 5**: Both modes coexist (compile-time or runtime flag)
4. **Phase 6**: Deprecate embedded TUI (optional)

---

## Security Considerations

1. **Bind Address**: Default to 127.0.0.1 only (localhost)
2. **Authentication**: Optional token-based auth for multi-user
3. **Encryption**: TLS optional for remote management scenarios
4. **Rate Limiting**: Prevent command flooding

---

## Performance Impact

| Metric | Before | After | Impact |
|--------|--------|-------|--------|
| Core CPU | ~5% TUI overhead | ~0% | Improved |
| Latency | Direct memory access | ~1ms socket | Negligible |
| Memory | Shared structs | Duplicated cache | +~50KB per TUI |
| Throughput | Unchanged | Unchanged | None |

---

## Success Criteria

- [ ] Tunnel continues running when TUI is killed
- [ ] Multiple TUIs can connect to single core
- [ ] Remote management via SSH tunnel works
- [ ] CPU usage reduced when TUI is disconnected
- [ ] All existing TUI features preserved
- [ ] Cross-platform (Linux, macOS, Windows)
