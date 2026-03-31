/*
 * dnstun-tui — Standalone Terminal User Interface
 * 
 * This executable connects to the dnstun-core management server
 * and displays real-time tunnel statistics.
 * 
 * Usage:
 *   ./dnstun-tui                  # Connect to localhost:9090
 *   ./dnstun-tui --host <addr>   # Connect to specific host
 *   ./dnstun-tui --port <port>   # Connect to specific port
 * 
 * Keyboard:
 *   1 - Dashboard view
 *   2 - Help guide
 *   Q - Quit TUI (tunnel keeps running!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "third_party/uv.h"
#include "mgmt_client.h"
#include "renderer.h"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

/* ──────────────────────────────────────────────
   Global State
 ────────────────────────────────────────────── */
static uv_loop_t  *g_loop;
static mgmt_client_t *g_client;
static uv_timer_t  g_render_timer;
static uv_tty_t    g_tty;

/* ──────────────────────────────────────────────
   Signal Handling
 ────────────────────────────────────────────── */
static void on_signal(int sig) {
    (void)sig;
    fprintf(stderr, "\n[DNSTUN-TUI] Received signal, shutting down...\n");
    renderer_shutdown();
    exit(0);
}

/* ──────────────────────────────────────────────
   Render Timer Callback
 ────────────────────────────────────────────── */
static void on_render_timer(uv_timer_t *timer) {
    (void)timer;
    const mgmt_telemetry_frame_t *stats = mgmt_client_get_stats(g_client);
    renderer_render(stats);
}

/* ──────────────────────────────────────────────
   TTY Input Handling
 ────────────────────────────────────────────── */
static void on_tty_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_tty_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)stream;
    if (nread > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            renderer_handle_key(buf->base[i]);
            if (!renderer_is_running()) {
                uv_stop(g_loop);
            }
        }
    }
    if (buf->base) free(buf->base);
}

/* ──────────────────────────────────────────────
   Telemetry Callback
 ────────────────────────────────────────────── */
static void on_telemetry(const mgmt_telemetry_frame_t *frame, void *user_data) {
    (void)frame;
    (void)user_data;
    /* Stats are cached in the client, render will pick them up */
}

/* ──────────────────────────────────────────────
   Main Entry Point
 ────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    int port = 9090;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("dnstun-tui — Standalone Terminal User Interface\n");
            printf("\nUsage: %s [options]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  --host <addr>  Management server host (default: 127.0.0.1)\n");
            printf("  --port <port>  Management server port (default: 9090)\n");
            printf("  --help, -h     Show this help message\n");
            printf("\nKeyboard:\n");
            printf("  1  Dashboard view\n");
            printf("  2  Help guide\n");
            printf("  Q  Quit (tunnel keeps running!)\n");
            return 0;
        }
    }
    
    fprintf(stderr, "dnstun-tui v1.0\n");
    fprintf(stderr, "Connecting to %s:%d...\n", host, port);
    
    /* Setup signal handlers */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    
#ifdef _WIN32
    signal(SIGABRT, on_signal);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    
    /* Create event loop */
    g_loop = uv_default_loop();
    
    /* Initialize renderer */
    renderer_init();
    
    /* Create management client */
    g_client = mgmt_client_create(g_loop);
    if (!g_client) {
        fprintf(stderr, "Failed to create management client\n");
        renderer_shutdown();
        return 1;
    }
    
    /* Set telemetry callback */
    mgmt_client_set_callback(g_client, on_telemetry, NULL);
    
    /* Connect to server */
    if (mgmt_client_connect(g_client, host, port) != 0) {
        fprintf(stderr, "Failed to initiate connection\n");
        renderer_shutdown();
        mgmt_client_destroy(g_client);
        return 1;
    }
    
    /* Setup render timer (1 second) */
    uv_timer_init(g_loop, &g_render_timer);
    uv_timer_start(&g_render_timer, on_render_timer, 0, 1000);
    
    /* Setup TTY input */
    uv_tty_init(g_loop, &g_tty, 0, 1);
    uv_tty_set_mode(&g_tty, UV_TTY_MODE_RAW);
    uv_read_start((uv_stream_t*)&g_tty, on_tty_alloc, on_tty_read);
    
    /* Run event loop */
    fprintf(stderr, "[DNSTUN-TUI] Connected! Press [Q] to quit (tunnel keeps running).\n");
    uv_run(g_loop, UV_RUN_DEFAULT);
    
    /* Cleanup */
    uv_tty_reset_mode();
    renderer_shutdown();
    mgmt_client_destroy(g_client);
    
    fprintf(stderr, "[DNSTUN-TUI] Goodbye!\n");
    return 0;
}
