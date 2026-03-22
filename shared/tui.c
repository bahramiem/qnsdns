#include "tui.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD " [1] Stats   [2] Resolvers   [3] Config   [q] Quit\n" ANSI_RESET);
}

/* ── Panel 1: Resolver table ────────────────────────────────────────────────*/
static void render_resolvers(tui_ctx_t *t) {
    resolver_pool_t *pool = t->pool;
    printf(ANSI_BOLD ANSI_CYAN " ▌ RESOLVER POOL (%d total) ▌\n" ANSI_RESET,
           pool->count);
    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD "%-16s %-8s %5s %6s %5s %4s %5s %4s %s\n" ANSI_RESET,
           "IP", "State", "cwnd", "RTT ms", "QPS", "MTU", "Loss%", "FEC", "Enc");
    hr(72, ANSI_CYAN);

    int shown = 0;
    uv_mutex_lock(&pool->lock);
    for (int i = 0; i < pool->count && shown < 24; i++) {
        resolver_t *r = &pool->resolvers[i];
        printf("%-16s %s %5.0f %6.1f %5.0f %4d %5.1f %4u %s\n",
               r->ip,
               state_str(r->state),
               r->cwnd,
               r->rtt_ms,
               r->max_qps,
               r->downstream_mtu,
               r->loss_rate * 100.0,
               r->fec_k,
               r->enc == ENC_BINARY ? "bin" : "b64");
        shown++;
    }
    uv_mutex_unlock(&pool->lock);

    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD " [1] Stats   [2] Resolvers   [3] Config   [q] Quit\n" ANSI_RESET);
}

/* ── Panel 2: Config (live editable) ────────────────────────────────────────*/
static void render_config(tui_ctx_t *t) {
    printf(ANSI_BOLD ANSI_CYAN " ▌ LIVE CONFIG (press key number to toggle/edit) ▌\n" ANSI_RESET);
    hr(72, ANSI_CYAN);
    dnstun_config_t *c = t->cfg;
    const char *ciphers[] = { "none","chacha20","aes256gcm","noise_nk" };
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

    hr(72, ANSI_CYAN);
    printf(ANSI_BOLD " [1] Stats   [2] Resolvers   [3] Config   [q] Quit\n" ANSI_RESET);
}

/* ── Public API ─────────────────────────────────────────────────────────────*/
void tui_init(tui_ctx_t *t, tui_stats_t *stats,
              resolver_pool_t *pool, dnstun_config_t *cfg,
              const char *mode)
{
    memset(t, 0, sizeof(*t));
    t->stats   = stats;
    t->pool    = pool;
    t->cfg     = cfg;
    t->running = 1;
    t->panel   = 0;
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

        default: break;
    }
}

void tui_shutdown(tui_ctx_t *t) {
    t->running = 0;
    printf(ANSI_SHOW_CUR ANSI_RESET "\n");
    fflush(stdout);
}
