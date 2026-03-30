/**
 * @file shared/tui/input.c
 * @brief Implementation of keyboard input and command handling.
 */

#include "input.h"
#include "render.h"
#include "log.h"
#include "../mgmt_protocol.h"
#include <ctype.h>
#include <string.h>
#include "../uv.h"

void tui_start_input(tui_ctx_t *t, const char *label, void (*done_cb)(tui_ctx_t*, const char*)) {
    if (!t) return;
    t->input_mode = 1;
    t->input_len = 0;
    memset(t->input_buf, 0, sizeof(t->input_buf));
    strncpy(t->input_label, label, sizeof(t->input_label) - 1);
    t->input_done_cb = done_cb;
}

void tui_handle_key(tui_ctx_t *t, int key) {
    if (!t) return;
    dnstun_config_t *c = t->cfg;

    /* 1. Handle "Input Mode" (typing a resolver IP, etc.) */
    if (t->input_mode) {
        if (key == '\r' || key == '\n') {
            /* User pressed Enter - commit the input */
            t->input_buf[t->input_len] = '\0';
            if (t->input_done_cb)
                t->input_done_cb(t, t->input_buf);
            t->input_mode = 0;
        } else if (key == 27) {
            /* User pressed Escape - cancel input */
            t->input_mode = 0;
        } else if ((key == 127 || key == '\b') && t->input_len > 0) {
            /* Backspace */
            t->input_buf[--t->input_len] = '\0';
        } else if (isprint(key) && t->input_len < (int)sizeof(t->input_buf) - 1) {
            /* Buffer any printable characters */
            t->input_buf[t->input_len++] = (char)key;
        }
        tui_render(t);
        return;
    }

    /* 2. Global Navigation Keys */
    switch (key) {
        case '1': t->panel = 0; break; /* Dashboard */
        case '2': t->panel = 1; break; /* Resolvers */
        case '3': t->panel = 2; break; /* Config */
        case '4': t->panel = 3; break; /* Debug Logs */
        case '5': t->panel = 4; break; /* Help */
        case '6': t->panel = 5; break; /* Protocol Test */
        
        case 'q': 
        case 'Q': 
            t->running = 0; /* Exit TUI */
            break;

        /* Panel-Specific Commands */
        case 't':
        case 'T':
            if (t->panel == 5 && t->send_debug_cb && !t->proto_test.test_pending) {
                t->proto_test.test_sequence++;
                snprintf(t->proto_test.test_payload, sizeof(t->proto_test.test_payload),
                         "PROTO_TEST_%u", t->proto_test.test_sequence);
                t->proto_test.last_test_sent_ms = uv_hrtime() / 1000000ULL;
                t->proto_test.test_pending = 1;
                t->send_debug_cb(t->proto_test.test_payload, t->proto_test.test_sequence);
            }
            break;

        case 'R':
            /* Restart tunnel logic */
            if (t->send_command_cb) {
                t->send_command_cb(MGMT_CMD_RESTART_TUNNEL);
            }
            break;

        /* Debug Level Controls (Panel 4) */
        case '0': if (t->panel == 3) tui_debug_set_level(t, 0); break;
        case '!': if (t->panel == 3) tui_debug_set_level(t, 1); break;
        case '@': if (t->panel == 3) tui_debug_set_level(t, 2); break;
        case '#': if (t->panel == 3) tui_debug_set_level(t, 3); break;

        /* Config Toggles (Panel 3) */
        case 'd': if (t->panel == 2) config_set_key(c,"encryption","enabled", c->encryption ? "false":"true"); break;
        case 'f': if (t->panel == 2) config_set_key(c,"obfuscation","jitter", c->jitter ? "false":"true"); break;
        case 'g': if (t->panel == 2) config_set_key(c,"obfuscation","padding", c->padding ? "false":"true"); break;
        case 'h': if (t->panel == 2) config_set_key(c,"obfuscation","chaffing", c->chaffing ? "false":"true"); break;
        case 'i': if (t->panel == 2) config_set_key(c,"obfuscation","chrome_cover", c->chrome_cover ? "false":"true"); break;
        case 'j': if (t->panel == 2) config_set_key(c,"domains","dns_flux", c->dns_flux ? "false":"true"); break;
    }
    
    tui_render(t);
}
