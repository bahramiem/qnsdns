# DNS Tunnel Optimization Plan

## Overview
This plan outlines optimization opportunities identified in the client and server main entry points (`client/main.c` and `server/main.c`). The focus is on reducing CPU usage, improving efficiency, and making the system more configurable.

## Optimization Opportunities

### 1. Timer Interval Configuration
**Issue**: Hard-coded timer intervals prevent runtime tuning for different network conditions or power constraints.

**Files**: `client/main.c`, `server/main.c`

**Current State**:
- Server: idle_timer (1000ms), tui_timer (1000ms)
- Client: poll_timer (configurable but min 100ms enforced), agg_timer (50ms), bg_timer (1000ms), tui_timer (1000ms)

**Solution**: 
- Add configuration options for all timer intervals in `shared/config.h`
- Make timer intervals configurable via INI file under a `[timing]` section
- Maintain sensible defaults but allow customization

### 2. Client Session Polling Optimization
**Issue**: The client poll timer (`on_tick_poll`) scans all 256 possible session slots every poll interval, regardless of how many are actually active.

**Files**: `client/main.c` (lines 54-59), `client/session.h`

**Current State**:
```c
for (int i = 0; i < DNSTUN_MAX_SESSIONS; i++) {
    session_t *s = session_get(i);
    if (s && !s->closed) {
        dns_tx_send_poll(i);
    }
}
```

**Solution**:
- Maintain a list/bitmap of active sessions to avoid full scans
- Modify session allocation/deallocation to update this tracking structure
- Change poll timer to iterate only over active sessions

### 3. Timer Consolidation
**Issue**: Multiple timers with similar or related functions could be combined to reduce libuv overhead.

**Files**: `client/main.c`, `server/main.c`

**Analysis**:
- Server: idle_timer (session cleanup) and tui_timer (UI update) both at 1000ms
- Client: bg_timer (maintenance/stats) and tui_timer (UI refresh) both at 1000ms
- Client: agg_timer (50ms) and poll_timer (variable) serve different purposes but could be evaluated

**Solution**:
- Consider combining server idle_timer and tui_timer into a single 1000ms timer
- Consider combining client bg_timer and tui_timer into a single 1000ms timer
- Ensure functional separation is maintained within combined callbacks

### 4. TUI Update Frequency Optimization
**Issue**: TUI updates at fixed 1000ms interval regardless of whether data has changed.

**Files**: `client/main.c` (line 152), `server/main.c` (line 134), `shared/tui/`

**Solution**:
- Make TUI update interval configurable (related to #1)
- Consider implementing dirty flag system where TUI only updates when data changes
- Evaluate if lower update rates (e.g., 2000ms) are acceptable for most use cases

### 5. Initialization/Cleanup Review
**Issue**: Some initialization and cleanup sequences may have redundancy or ordering issues.

**Files**: `client/main.c` (lines 102-135, 158-166), `server/main.c` (lines 88-125, 144-150)

**Observations**:
- Both client and server set up global pointers to local stack variables
- Cleanup sequences appear complete but could be audited for missing items
- Consider if any initialization steps can be deferred or done lazily

**Solution**:
- Audit initialization sequences for potential reordering benefits
- Verify cleanup completeness (e.g., check if all initialized modules have corresponding shutdown)
- Consider moving non-critical initialization to background threads where appropriate

## Recommended Implementation Order

1. **Add timer configuration options** (foundational change that enables others)
2. **Optimize client session polling** (high impact for clients with few sessions)
3. **Consolidate compatible timers** (reduces libuv overhead)
4. **Make TUI update frequency configurable** (power saving for idle scenarios)
5. **Review initialization/cleanup sequences** (correctness and potential improvements)

## Expected Benefits

- Reduced CPU usage especially in idle/low-traffic scenarios
- Better adaptability to different deployment environments (servers vs embedded clients)
- More predictable resource usage through configurability
- Improved battery life for mobile/portable implementations
- Better scalability as session counts vary

## Configuration Additions Needed

In `shared/config.h`, add to `dnstun_config_t`:
```c
/* [timing] */
int      idle_timer_ms;        /* Server: session cleanup interval */
int      tui_update_ms;        /* TUI refresh interval */
int      agg_timer_ms;         /* Client: aggregation burst driver */
int      bg_timer_ms;          /* Client: background maintenance */
```

With corresponding defaults in `config_defaults()` and parsing in `config_set_key()`.

## Implementation Notes

All suggested changes maintain backward compatibility through sensible defaults.
Performance impact should be measured before and after implementation.
Care must be taken to ensure timer consolidation doesn't negatively impact responsiveness where timing is critical.