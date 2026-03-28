#pragma once
#ifndef DNSTUN_TUI_RENDERER_H
#define DNSTUN_TUI_RENDERER_H

#include <stdbool.h>
#include "../shared/mgmt_protocol.h"

/* ──────────────────────────────────────────────
   TUI Renderer API
   
   Simplified rendering for standalone TUI executable.
 ────────────────────────────────────────────── */

/* Initialize renderer */
void renderer_init(void);

/* Shutdown renderer */
void renderer_shutdown(void);

/* Render current view with telemetry data */
void renderer_render(const mgmt_telemetry_frame_t *stats);

/* Handle keyboard input */
void renderer_handle_key(int key);

/* Check if renderer should keep running */
int renderer_is_running(void);

#endif /* DNSTUN_TUI_RENDERER_H */
