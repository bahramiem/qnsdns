# Detailed Extraction Guide

This document maps specific functions and types from `server/main.c` and `client/main.c` to their target modules.

## Server Module Extraction

### server/session/session.c & session.h

**From server/main.c, extract:**

**Types:**
```c
// Lines 85-125: srv_session_t struct
typedef struct srv_session {
  bool used;
  uint8_t session_id;
  uv_tcp_t upstream_tcp;
  bool tcp_connected;
  uint8_t *upstream_buf;
  size_t upstream_len;
  size_t upstream_cap;
  struct sockaddr_in client_addr;
  uint16_t cl_downstream_mtu;
  uint8_t cl_enc_format;
  uint8_t cl_loss_pct;
  uint8_t cl_fec_k;
  char user_id[16];
  uint16_t burst_seq_start;
  int burst_count_needed;
  int burst_received;
  uint8_t **burst_symbols;
  size_t burst_symbol_len;
  uint64_t burst_oti_common;
  uint32_t burst_oti_scheme;
  bool burst_has_oti;
  uint16_t downstream_seq;
  bool status_sent;
  time_t last_active;
} srv_session_t;
```

```c
// Lines 266-273: connect_req_t struct
typedef struct connect_req {
  uv_connect_t connect;
  int session_idx;
  uint8_t *payload;
  size_t payload_len;
  char target_host[256];
  uint16_t target_port;
} connect_req_t;
```

**Functions:**
- `session_find_by_id()` (Lines 221-226)
- `session_alloc_by_id()` (Lines 229-241)
- `session_close()` (Lines 243-261)
- `upstream_write_and_read()` (Lines 284-300)
- `on_upstream_write()` (Lines 303-305)
- `on_upstream_alloc()` (Lines 308-323)
- `on_upstream_read()` (Lines 325-356)
- `session_send_status()` (Lines 358-385)
- `on_upstream_resolve()` (Lines 386-428)
- `on_upstream_connect()` (Lines 430-476)

**Globals to expose:**
```c
extern srv_session_t g_sessions[SRV_MAX_SESSIONS];
extern tui_stats_t g_stats;
```

---

### server/swarm/swarm.c & swarm.h

**From server/main.c, extract:**

**Globals:**
```c
// Lines 131-134
#define SWARM_MAX 16384
static char g_swarm_ips[SWARM_MAX][46];
static int g_swarm_count = 0;
static uv_mutex_t g_swarm_lock;

// Line 185
static char g_swarm_file[1024];
```

**Functions:**
- `swarm_record_ip()` (Lines 170-183)
- `swarm_save()` (Lines 187-198)
- `swarm_load()` (Lines 200-214)

---

### server/dns/protocol.c & protocol.h

**From server/main.c, extract:**

**Functions:**
- `encode_downstream_data()` (Lines 479-489)
- `build_txt_reply_with_seq()` (Lines 492-574)
- `on_udp_send_done()` (Lines 576-579)
- `send_udp_reply()` (Lines 582-606)
- `on_server_alloc()` (Lines 609-613)
- `on_server_recv()` (Lines 616-1281) - This is a LARGE function

---

### server/tui/callbacks.c & callbacks.h

**From server/main.c, extract:**

**Globals:**
```c
static uv_tty_t g_tty;  // Line 1364
```

**Functions:**
- `on_idle_timer()` (Lines 1284-1308)
- `on_tui_timer()` (Lines 1313-1332)
- `get_active_clients()` (Lines 1340-1359)
- `on_tty_alloc()` (Lines 1366-1371)
- `on_tty_read()` (Lines 1373-1385)

---

## Client Module Extraction

### client/socks5/proxy.c & proxy.h

**From client/main.c, extract:**

**Types:**
```c
// Need to identify socks5_client_t struct definition
// Related to on_socks5_close, on_socks5_read, etc.
```

**Functions:**
- `on_socks5_close()` (Lines 1874-1881)
- `on_socks5_write_done()` (Lines 1883-1887)
- `socks5_send()` (Lines 1889-1929)
- `socks5_flush_recv_buf()` (Lines 2059-2070)
- `socks5_handle_data()` (Lines 2073-2270)
- `on_socks5_read()` (Lines 2272-2310)
- `on_socks5_alloc()` (Lines 2312-2318)
- `on_socks5_connection()` (Lines 2320-2356)

---

### client/dns/query.c & query.h

**From client/main.c, extract:**

**Functions:**
- `inline_dotify()` (Lines 177-213)
- `build_dns_query()` (Lines 215-426)
- `on_dns_query_close()` (Lines 2359-2362)
- `on_dns_timeout()` (Lines 2364-2372)
- `on_dns_recv()` (Lines 2374-2615)
- `on_dns_send()` (Lines 2617-2630)
- `on_dns_alloc()` (Lines 2632-2646)
- `send_mtu_handshake()` (Lines 2666-2706)
- `fire_dns_chunk_symbol()` (Lines 2709-2853)

---

### client/session/session.c & session.h

**From client/main.c, extract:**

**Types:**
```c
// reorder_buffer_t struct (referenced in reorder_buffer_* functions)
```

**Functions:**
- `reorder_buffer_init()` (Lines 1931-1940)
- `reorder_buffer_free()` (Lines 1942-1950)
- `reorder_buffer_find_slot()` (Lines 1952-1958)
- `reorder_buffer_insert()` (Lines 1960-2003)
- `reorder_buffer_flush()` (Lines 2005-2057)

---

### client/resolver/init.c & init.h

**From client/main.c, extract:**

**Functions:**
- `resolvers_save()` (Lines 129-141)
- `resolvers_load()` (Lines 143-168)
- `on_init_phase_timeout()` (Lines 1591-1593)
- `run_event_loop_ms()` (Lines 1596-1602)
- `resolver_init_phase()` (Lines 1605-1858)

---

### client/resolver/probe.c & probe.h

**From client/main.c, extract:**

**Types:**
```c
// probe_req_t struct
// probe_test_type_t enum
// resolver_test_result_t struct
```

**Functions:**
- `on_probe_close()` (Lines 573-576)
- `on_probe_timeout()` (Lines 578-585)
- `on_probe_recv()` (Lines 587-749)
- `on_probe_alloc()` (Lines 751-756)
- `on_probe_send()` (Lines 758-766)
- `fire_probe_ext()` (Lines 769-804)
- `fire_probe()` (Lines 806-813)
- `build_test_dns_query()` (Lines 816-877)
- `fire_test_probe()` (Lines 1025-1118)

---

### client/resolver/mtu.c & mtu.h

**From client/main.c, extract:**

**Types:**
```c
// mtu_binary_search_t struct (Lines 1121+)
```

**Functions:**
- `init_mtu_binary_search()` (Lines 1121-1139)
- `is_mtu_tested()` (Lines 1141-1145)
- `mark_mtu_tested()` (Lines 1147-1155)
- `free_mtu_binary_search()` (Lines 1157-1163)
- `get_next_mtu_to_test()` (Lines 1165-1201)
- `perform_mtu_binary_search()` (Lines 1203-1231)
- `fire_mtu_test_probe()` (Lines 1233-1278)
- `run_mtu_binary_search_tests()` (Lines 1280-1312)
- `find_max_upstream_mtu()` (Lines 1314-1337)
- `find_max_downstream_mtu()` (Lines 1339-1360)
- `build_mtu_test_query()` (Lines 879-1023)

---

### client/aggregation/packet.c & packet.h

**From client/main.c, extract:**

**Types:**
```c
// agg_packet_t struct
```

**Functions:**
- `calc_symbols_per_packet()` (Lines 1361-1369)
- `agg_packet_init()` (Lines 1371-1382)
- `agg_packet_add_symbol()` (Lines 1384-1397)
- `get_optimal_packet_size()` (Lines 1400-1415)
- `calc_packing_efficiency()` (Lines 1417-1423)
- `encode_aggregated_packet()` (Lines 1426-1493)
- `decode_aggregated_packet()` (Lines 1496-1523)
- `log_aggregation_stats()` (Lines 1526-1564)

---

### client/debug/packet.c & packet.h

**From client/main.c, extract:**

**Types:**
```c
// debug_pkt_ctx_t struct
```

**Functions:**
- `on_debug_close()` (Lines 428-431)
- `on_debug_timeout()` (Lines 433-440)
- `on_debug_alloc()` (Lines 442-447)
- `on_debug_send()` (Lines 449-451)
- `on_debug_recv()` (Lines 454-571)

---

### client/tui/callbacks.c & callbacks.h

**From client/main.c, extract:**

**Globals:**
```c
static uv_tty_t g_tty;  // Line 3014
```

**Functions:**
- `on_poll_timer()` (Lines 2856-2939)
- `fire_chrome_cover_traffic()` (Lines 2941-2958)
- `on_recovery_timer()` (Lines 2961-2996)
- `on_tui_timer()` (Lines 2998-3009)
- `on_tty_alloc()` (Lines 3016-3020)
- `on_tty_read()` (Lines 3022-3031)

---

## Shared TUI Module Extraction

### shared/tui/render.c & render.h

**From shared/tui.c, extract:**

**Functions:**
- `tui_render()` - Main render function
- `clear_screen()` - Screen clearing
- All panel render functions

### shared/tui/input.c & input.h

**From shared/tui.c, extract:**

**Functions:**
- `tui_handle_key()` - Keyboard handling
- Menu navigation functions
- Input mode handling

### shared/tui/panels.c & panels.h

**From shared/tui.c, extract:**

**Functions:**
- Stats panel rendering
- Resolvers panel rendering
- Config panel rendering
- Debug panel rendering
- Help panel rendering
- Protocol test panel rendering

### shared/tui/log.c & log.h

**From shared/tui.c, extract:**

**Functions:**
- `tui_debug_log()` - Log buffer management
- Log scrolling functions

### shared/tui/ansi.h

**From shared/tui.c, extract:**

All ANSI escape code constants (Lines 30-70 approximately):
```c
#define ANSI_RESET "\033[0m"
#define ANSI_BOLD "\033[1m"
// ... etc
```

All box drawing characters (Lines 72-98):
```c
#define BOX_HORZ "─"
#define BOX_VERT "│"
// ... etc
```

## Common Patterns for Extraction

### 1. Header File Template

```c
#ifndef MODULE_NAME_H
#define MODULE_NAME_H

#include <stdint.h>
#include <stdbool.h>
// other needed includes

/* Forward declarations for types defined elsewhere */
struct some_external_type;

/* Type definitions */
typedef struct { ... } module_type_t;

/* Function declarations */
void module_init(void);
void module_cleanup(void);
...

/* External globals this module needs */
extern external_type_t g_external;

#endif
```

### 2. Source File Template

```c
#include "module_name.h"
#include "../other_module/other.h"  // for sibling modules
#include "../../shared/types.h"     // for shared types

/* Module-private globals */
static module_private_t g_private;

/* Function implementations */
...
```

### 3. Global State Management

Many functions access global state. When extracting:

1. **Option A**: Pass globals as parameters
2. **Option B**: Expose globals via extern in header
3. **Option C**: Create a context struct passed to all functions

For minimal changes, use **Option B** (extern) initially.

### 4. Cross-Module Dependencies

Some functions in one module may need to call functions in another:

```c
// In server/session/session.c
#include "../swarm/swarm.h"  // for swarm_record_ip()
```

Document these cross-dependencies in module headers.
