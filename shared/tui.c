#include "tui.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/* ANSI codes */
#define ANSI_RESET     "\033[0m"
#define ANSI_BOLD      "\033[1m"
#define ANSI_GREEN     "\033[32m"
#define ANSI_RED       "\033[31m"
#define ANSI_YELLOW    "\033[33m"
#define ANSI_CYAN      "\033[36m"
#define ANSI_MAGENTA   "\033[35m"
#define ANSI_BLUE      "\033[34m"
#define ANSI_WHITE     "\033[37m"
#define ANSI_BG_BLACK  "\033[40m"
#define ANSI_BG_BLUE   "\033[44m"
#define ANSI_CLEAR     "\033[2J\033[H"
#define ANSI_HIDE_CUR  "\033[?25l"
#define ANSI_SHOW_CUR  "\033[?25h"

static void hr(int width, const char *color) {
    printf("%s", color);
    for (int i = 0; i < width; i++) putchar('-');
    printf(ANSI_RESET "\n");
}

static const char *state_str(resolver_state_t s) {
    switch(s) {
        case RSV_ACTIVE:  return ANSI_GREEN  "ACTIVE " ANSI_RESET;
        case RSV_PENALTY: return ANSI_YELLOW "PENALTY" ANSI_RESET;
        case RSV_DEAD:    return ANSI_RED    "DEAD   " ANSI_RESET;
        case RSV_ZOMBIE:  return ANSI_RED    "ZOMBIE " ANSI_RESET;
        case RSV_TESTING: return ANSI_CYAN   "TESTING" ANSI_RESET;
        default:          return "UNKNOWN";
    }
}

/* ── Input bar (shown at bottom when input_mode == 1) ───────────────────────*/
static void render_input_bar(tui_ctx_t *t) {
    hr(72, ANSI_CYAN);
    printf(ANSI_BG_BLUE ANSI_BOLD " %s " ANSI_RESET "\n", t->input_label);
    printf(ANSI_CYAN " > " ANSI_RESET "%.*s" ANSI_BOLD "_" ANSI_RESET "\n",
           t->input_len, t->input_buf);
    printf(ANSI_YELLOW " [Enter] confirm   [Esc] cancel   [Backspace] delete"
           ANSI_RESET "\n");
}

/* ── Panel 0: Stats ─────────────────────────────────────────────────────────*/
static void render_stats(tui_ctx_t *t) {
    tui_stats_t *s = t->stats;
    printf(ANSI_BOLD ANSI_CYAN " ▌ DNSTUN %s ▌" ANSI_RESET "\n", s->mode);
    hr(72, ANSI_CYAN);

    printf(ANSI_BOLD " ↑ Upload:   " ANSI_RESET ANSI_GREEN "%8.1f KB/s" ANSI_RESET
           "   Total: %llu bytes\n",
           s->tx_bytes_sec / 1024.0,
           (unsigned long long)s->tx_total);

    printf(ANSI_BOLD " ↓ Download: " ANSI_RESET ANSI_CYAN  "%8.1f KB/s" ANSI_RESET
           "   Total: %llu bytes\n",
           s->rx_bytes_sec / 1024.0,
           (unsigned long long)s->rx_total);

    hr(72, ANSI_CYAN);

    printf(" Sessions:  " ANSI_BOLD ANSI_WHITE "%3d" ANSI_RESET
           "   Resolvers: " ANSI_GREEN "%3d active" ANSI_RESET
           " / " ANSI_YELLOW "%3d penalty" ANSI_RESET
           " / " ANSI_RED "%3d dead" ANSI_RESET "\n",
           s->active_sessions,
           s->active_resolvers,
           s->penalty_resolvers,
           s->dead_resolvers);

    printf(" Queries:   sent=%llu  recv=%llu  lost=%llu  loss=%.1f%%\n",
           (unsigned long long)s->queries_sent,
           (unsigned long long)s->queries_recv,
           (unsigned long long)s->queries_lost,
           s->queries_sent > 0
               ? 100.0 * (double)s->queries_lost / (double)s->queries_sent
               : 0.0);

    /* Show current domains */
    if (t->cfg->domain_count > 0) {
        printf(" Domains:   " ANSI_CYAN);
        for (int i = 0; i < t->cfg->domain_count; i++) {
            if (i > 0) printf(", ");
            printf("%s", t->cfg->domains[i]);
        }
        printf(ANSI_RESET "\n");
    } else {
        printf(" Domains:   " ANSI_RED "(none configured)" ANSI_RESET "\n");
    }

    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD " [1] Stats   [2] Resolvers   [3] Config   [q] Quit\n" ANSI_RESET);
}

/* ── Panel 1: Resolver table ────────────────────────────────────────────────*/
static void render_resolvers(tui_ctx_t *t) {
    if (strcmp(t->stats->mode, "SERVER") == 0) {
        if (!t->get_clients_cb) {
            printf(ANSI_BOLD ANSI_CYAN " ▌ ACTIVE CLIENT SESSIONS ▌\n" ANSI_RESET);
            hr(72, ANSI_CYAN);
            printf(" (Not initialized)\n");
            return;
        }
        tui_client_snap_t snaps[24];
        int num = t->get_clients_cb(snaps, 24);
        printf(ANSI_BOLD ANSI_CYAN " ▌ ACTIVE CLIENT SESSIONS (%d shown) ▌\n" ANSI_RESET, num);
        hr(72, ANSI_CYAN);
        printf(ANSI_BOLD "%-16s %-12s %5s %5s %5s %5s %8s\n" ANSI_RESET,
               "Client IP", "User ID", "MTU", "Loss%", "FEC", "Enc", "Idle(s)");
        hr(72, ANSI_CYAN);
        for (int i=0; i<num; i++) {
            printf("%-16s %-12s %5d %5d %5d %5s %8u\n",
                   snaps[i].ip,
                   snaps[i].user_id[0] ? snaps[i].user_id : "-",
                   snaps[i].downstream_mtu,
                   (int)snaps[i].loss_pct,
                   (int)snaps[i].fec_k,
                   snaps[i].enc_format == ENC_BINARY ? "bin" : "b64",
                   snaps[i].idle_sec);
        }
        hr(72, ANSI_CYAN);
        printf(ANSI_BOLD " Press ANY KEY to return to main menu ...\n" ANSI_RESET);
        return;
    }

    resolver_pool_t *pool = t->pool;

    /* Snapshot resolver data while locked, then print without the lock.
       This prevents printf from stalling the event loop while holding
       the mutex (fix #17). */
    typedef struct {
        char             ip[46];
        resolver_state_t state;
        double           cwnd;
        double           rtt_ms;
        double           max_qps;
        int              downstream_mtu;
        double           loss_rate;
        uint32_t         fec_k;
        enc_format_t     enc;
    } snap_t;

    snap_t snaps[24];
    int shown = 0;
    int total = 0;

    uv_mutex_lock(&pool->lock);
    total = pool->count;
    for (int i = 0; i < pool->count && shown < 24; i++) {
        resolver_t *r = &pool->resolvers[i];
        snaps[shown].state         = r->state;
        snaps[shown].cwnd          = r->cwnd;
        snaps[shown].rtt_ms        = r->rtt_ms;
        snaps[shown].max_qps       = r->max_qps;
        snaps[shown].downstream_mtu = r->downstream_mtu;
        snaps[shown].loss_rate     = r->loss_rate;
        snaps[shown].fec_k         = r->fec_k;
        snaps[shown].enc           = r->enc;
        strncpy(snaps[shown].ip, r->ip, sizeof(snaps[shown].ip) - 1);
        shown++;
    }
    uv_mutex_unlock(&pool->lock);

    printf(ANSI_BOLD ANSI_CYAN " ▌ RESOLVER POOL (%d total) ▌\n" ANSI_RESET, total);
    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD "%-16s %-8s %5s %6s %5s %4s %5s %4s %s\n" ANSI_RESET,
           "IP", "State", "cwnd", "RTT ms", "QPS", "MTU", "Loss%", "FEC", "Enc");
    hr(72, ANSI_CYAN);

    for (int i = 0; i < shown; i++) {
        snap_t *s = &snaps[i];
        printf("%-16s %s %5.0f %6.1f %5.0f %4d %5.1f %4u %s\n",
               s->ip,
               state_str(s->state),
               s->cwnd,
               s->rtt_ms,
               s->max_qps,
               s->downstream_mtu,
               s->loss_rate * 100.0,
               s->fec_k,
               s->enc == ENC_BINARY ? "bin" : "b64");
    }

    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD " [1] Stats   [2] Resolvers   [3] Config   "
           ANSI_CYAN "[r]" ANSI_RESET ANSI_BOLD " Add Resolver   [q] Quit\n" ANSI_RESET);
    if (t->input_mode)
        render_input_bar(t);
}


/* ── Panel 2: Config (live editable) ────────────────────────────────────────*/
static void render_config(tui_ctx_t *t) {
    printf(ANSI_BOLD ANSI_CYAN " ▌ LIVE CONFIG (press key to toggle/edit) ▌\n" ANSI_RESET);
    hr(72, ANSI_CYAN);
    dnstun_config_t *c = t->cfg;
    const char *ciphers[]    = { "none","chacha20","aes256gcm","noise_nk" };
    const char *transports[] = { "udp","doh","dot" };

    printf(" a) poll_interval_ms  = " ANSI_CYAN "%d" ANSI_RESET "\n",  c->poll_interval_ms);
    printf(" b) fec_window        = " ANSI_CYAN "%d" ANSI_RESET "\n",  c->fec_window);
    printf(" c) cwnd_max          = " ANSI_CYAN "%.0f" ANSI_RESET "\n", c->cwnd_max);
    printf(" d) encryption        = %s\n", c->encryption ? ANSI_GREEN "ON" ANSI_RESET : ANSI_RED "OFF" ANSI_RESET);
    printf(" e) cipher            = " ANSI_CYAN "%s" ANSI_RESET "\n",
           (c->cipher < 4) ? ciphers[c->cipher] : "?");
    printf(" f) jitter            = %s\n", c->jitter   ? ANSI_GREEN "ON" ANSI_RESET : ANSI_RED "OFF" ANSI_RESET);
    printf(" g) padding           = %s\n", c->padding  ? ANSI_GREEN "ON" ANSI_RESET : ANSI_RED "OFF" ANSI_RESET);
    printf(" h) chaffing          = %s\n", c->chaffing ? ANSI_GREEN "ON" ANSI_RESET : ANSI_RED "OFF" ANSI_RESET);
    printf(" i) chrome_cover      = %s\n", c->chrome_cover ? ANSI_GREEN "ON" ANSI_RESET : ANSI_RED "OFF" ANSI_RESET);
    printf(" j) dns_flux          = %s\n", c->dns_flux ? ANSI_GREEN "ON" ANSI_RESET : ANSI_RED "OFF" ANSI_RESET);
    printf(" k) transport         = " ANSI_CYAN "%s" ANSI_RESET "\n",
           (c->transport < 3) ? transports[c->transport] : "?");
    printf(" l) log_level         = " ANSI_CYAN "%d" ANSI_RESET "\n", c->log_level);

    /* Domain editing */
    printf(" m) domains           = " ANSI_CYAN);
    if (c->domain_count > 0) {
        for (int i = 0; i < c->domain_count; i++) {
            if (i > 0) printf(",");
            printf("%s", c->domains[i]);
        }
    } else {
        printf(ANSI_RED "(none)");
    }
    printf(ANSI_RESET "\n");

    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD " [1] Stats   [2] Resolvers   [3] Config   [q] Quit\n" ANSI_RESET);

    if (t->input_mode)
        render_input_bar(t);
}

/* ── Domain-edit callback ───────────────────────────────────────────────────*/
static void on_domain_input_done(tui_ctx_t *t, const char *value) {
    if (value && value[0]) {
        config_set_key(t->cfg, "domains", "list", value);
        if (t->config_path)
            config_save_domains(t->config_path, t->cfg);
        /* Trigger process restart */
        t->running = 0;
        t->restart = 1;
    }
}

/* ── Resolver-add callback ──────────────────────────────────────────────────*/
static void on_resolver_input_done(tui_ctx_t *t, const char *value) {
    if (!value || !value[0]) return;
    /* Trim whitespace */
    char ip[64] = {0};
    const char *p = value;
    while (*p == ' ' || *p == '\t') p++;
    strncpy(ip, p, sizeof(ip)-1);
    char *end = ip + strlen(ip) - 1;
    while (end > ip && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) *end-- = '\0';
    if (!ip[0]) return;

    rpool_add(t->pool, ip);

    /* Append to the resolver file so it persists across restarts */
    if (t->config_path) {
        /* Derive resolver file path: same dir as config, fixed name */
        char rf_path[1024];
        strncpy(rf_path, t->config_path, sizeof(rf_path)-1);
        char *slash = strrchr(rf_path, '/');
#ifdef _WIN32
        char *bslash = strrchr(rf_path, '\\');
        if (bslash > slash) slash = bslash;
#endif
        if (slash) strncpy(slash + 1, "client_resolvers.txt", sizeof(rf_path) - (slash - rf_path) - 1);
        else strcpy(rf_path, "client_resolvers.txt");

        FILE *rf = fopen(rf_path, "a");
        if (rf) { fprintf(rf, "%s\n", ip); fclose(rf); }
    }
}


/* ── Public API ─────────────────────────────────────────────────────────────*/
void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode, const char *config_path)
{
    memset(t, 0, sizeof(*t));
    t->stats       = stats;
    t->pool        = pool;
    t->cfg         = cfg;
    t->running     = 1;
    t->panel       = 0;
    t->config_path = config_path;
    strncpy(stats->mode, mode, sizeof(stats->mode)-1);
    printf(ANSI_HIDE_CUR);
}

void tui_render(tui_ctx_t *t) {
    printf(ANSI_CLEAR);
    switch (t->panel) {
        case 0: render_stats(t);     break;
        case 1: render_resolvers(t); break;
        case 2: render_config(t);    break;
        default: render_stats(t);    break;
    }
    fflush(stdout);
}

void tui_handle_key(tui_ctx_t *t, int key) {
    dnstun_config_t *c = t->cfg;

    /* ── Input mode: accumulate text ── */
    if (t->input_mode) {
        if (key == '\r' || key == '\n') {
            /* Confirm */
            t->input_buf[t->input_len] = '\0';
            if (t->input_done_cb)
                t->input_done_cb(t, t->input_buf);
            t->input_mode = 0;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
        } else if (key == 27) {
            /* Escape — cancel */
            t->input_mode = 0;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
        } else if ((key == 127 || key == '\b') && t->input_len > 0) {
            /* Backspace */
            t->input_buf[--t->input_len] = '\0';
        } else if (isprint(key) && t->input_len < (int)sizeof(t->input_buf) - 1) {
            t->input_buf[t->input_len++] = (char)key;
        }
        return;
    }

    /* ── Normal mode ── */
    if (strcmp(t->stats->mode, "SERVER") == 0 && t->panel == 1) {
        if (key == 'q') {
            t->running = 0;
        } else {
            t->panel = 0; /* Any other key returns to stats */
        }
        return;
    }

    switch (key) {
        case '1': t->panel = 0; break;
        case '2': t->panel = 1; break;
        case '3': t->panel = 2; break;
        case 'q': t->running = 0; break;

        /* Config panel live toggles */
        case 'd': config_set_key(c,"encryption","enabled", c->encryption ? "false":"true"); break;
        case 'f': config_set_key(c,"obfuscation","jitter",  c->jitter     ? "false":"true"); break;
        case 'g': config_set_key(c,"obfuscation","padding", c->padding    ? "false":"true"); break;
        case 'h': config_set_key(c,"obfuscation","chaffing",c->chaffing   ? "false":"true"); break;
        case 'i': config_set_key(c,"obfuscation","chrome_cover",c->chrome_cover?"false":"true"); break;
        case 'j': config_set_key(c,"domains","dns_flux",   c->dns_flux    ? "false":"true"); break;

        /* Domain edit — open input bar pre-filled with current domains */
        case 'm':
            t->panel = 2;   /* switch to config panel to show the bar */
            t->input_mode = 1;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
            strncpy(t->input_label,
                    "Edit domains (comma-separated, e.g. tun.example.com)",
                    sizeof(t->input_label) - 1);
            /* Pre-fill with current values */
            for (int i = 0; i < c->domain_count; i++) {
                if (i > 0 && t->input_len < (int)sizeof(t->input_buf) - 2)
                    t->input_buf[t->input_len++] = ',';
                int rem = (int)sizeof(t->input_buf) - t->input_len - 1;
                if (rem > 0) {
                    int dl = (int)strlen(c->domains[i]);
                    if (dl > rem) dl = rem;
                    memcpy(t->input_buf + t->input_len, c->domains[i], (size_t)dl);
                    t->input_len += dl;
                }
            }
            t->input_done_cb = on_domain_input_done;
            break;

        /* Add resolver — open input bar for a new IP */
        case 'r':
            t->panel = 1;   /* switch to resolver panel */
            t->input_mode = 1;
            t->input_len  = 0;
            memset(t->input_buf, 0, sizeof(t->input_buf));
            strncpy(t->input_label,
                    "Add resolver IP (e.g. 8.8.8.8)",
                    sizeof(t->input_label) - 1);
            t->input_done_cb = on_resolver_input_done;
            break;

        default: break;
    }
}

void tui_shutdown(tui_ctx_t *t) {
    t->running = 0;
    printf(ANSI_SHOW_CUR ANSI_RESET "\n");
    fflush(stdout);
}
