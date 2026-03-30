#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Helpers ────────────────────────────────────────────────────────────────*/
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) *e-- = '\0';
    return s;
}

static bool parse_bool(const char *v) {
    return (strcmp(v,"true")==0 || strcmp(v,"1")==0 || strcmp(v,"yes")==0);
}

/* ── Defaults ───────────────────────────────────────────────────────────────*/
void config_defaults(dnstun_config_t *cfg, bool is_server) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->is_server = is_server;

    /* core */
    if (!is_server) {
        strncpy(cfg->socks5_bind, "127.0.0.1:1080", sizeof(cfg->socks5_bind)-1);
    } else {
        strncpy(cfg->server_bind, "0.0.0.0:53", sizeof(cfg->server_bind)-1);
    }
    cfg->workers              = 4;
    cfg->threads              = 2;
    cfg->log_level            = 1; /* info */
    strcpy(cfg->user_id, "default");

    /* resolvers */
    cfg->cidr_scan            = false;
    cfg->cidr_prefix          = 24;
    cfg->swarm_sync           = false;
    cfg->swarm_serve          = true;
    cfg->swarm_save_disk      = true;
    cfg->background_recovery_rate = 5;

    /* tuning */
    cfg->poll_interval_ms     = 500;
    cfg->fec_window           = 32;
    cfg->fec_redundancy       = 20;
    cfg->cwnd_init            = 16.0;
    cfg->cwnd_max             = 512.0;
    cfg->idle_timeout_sec     = 120;
    cfg->downstream_mtu      = 220;

    /* mtu_testing - Binary search MTU testing like client.py */
    cfg->max_upload_mtu       = 512;     /* Maximum upload MTU to test */
    cfg->max_download_mtu      = 700;    /* Maximum download MTU to test (400-700 like Python reference) */
    cfg->min_upload_mtu        = 0;       /* Minimum acceptable upload MTU (0 = no minimum) */
    cfg->min_download_mtu      = 400;    /* Minimum download MTU to test */
    cfg->mtu_test_retries     = 2;       /* Number of retries per MTU test */
    cfg->mtu_test_timeout_ms   = 1000;    /* Timeout for MTU test packets (ms) */
    cfg->mtu_test_parallelism  = 10;      /* Parallel MTU tests */

    /* packet_aggregation - Pack multiple symbols into one packet */
    cfg->packet_aggregation   = true;     /* Enable packet aggregation */
    cfg->symbol_size          = 64;       /* Rateless symbol size */
    cfg->max_symbols_per_packet = 16;      /* Max symbols to aggregate */
    cfg->auto_aggregate       = true;      /* Auto-calculate optimal packing */

    /* encoding - Downstream encoding for server → client */
    cfg->downstream_encoding   = DNSTUN_ENC_BASE64;  /* Default: base64 */
    cfg->downstream_buffer_size = 8192;               /* Default: 8KB, max: 64KB */

    /* domains */
    cfg->dns_flux             = false;
    cfg->flux_period_sec      = 21600; /* 6 hours */

    /* resolver_testing - Scanner.py style DNS resolver testing */
    strcpy(cfg->test_domain, "s.domain.com");
    strcpy(cfg->nonexistent_domain, "nonexistent.example.com");
    strcpy(cfg->long_label_domain, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.google.com");
    cfg->test_timeout_ms     = 1000;

    /* transport */
    cfg->transport            = TRANSPORT_UDP;

    /* encryption */
    cfg->encryption           = false;
    cfg->cipher               = CIPHER_CHACHA20;

    /* obfuscation — all off by default */
    cfg->jitter               = false;
    cfg->padding              = false;
    cfg->chaffing             = false;
    cfg->chrome_cover         = false;

    /* OTA */
    cfg->ota_enabled          = false;
    cfg->ota_check_interval_sec = 3600;
}

/* ── Per-key setter (also used by TUI live edit) ────────────────────────────*/
int config_set_key(dnstun_config_t *cfg,
                   const char *section,
                   const char *key,
                   const char *value)
{
    /* [core] */
    if (strcmp(section,"core")==0) {
        if      (strcmp(key,"socks5_bind")==0)  strncpy(cfg->socks5_bind, value, sizeof(cfg->socks5_bind)-1);
        else if (strcmp(key,"server_bind")==0)  strncpy(cfg->server_bind, value, sizeof(cfg->server_bind)-1);
        else if (strcmp(key,"workers")==0)       cfg->workers   = atoi(value);
        else if (strcmp(key,"threads")==0)       cfg->threads   = atoi(value);
        else if (strcmp(key,"log_level")==0) {
            if      (strcmp(value,"silent")==0) cfg->log_level = 0;
            else if (strcmp(value,"info")==0)   cfg->log_level = 1;
            else if (strcmp(value,"debug")==0)  cfg->log_level = 2;
            else cfg->log_level = atoi(value);
        }
        else if (strcmp(key,"user_id")==0) {
            strncpy(cfg->user_id, value, sizeof(cfg->user_id)-1);
            cfg->user_id[sizeof(cfg->user_id)-1] = '\0';
        }
    }
    /* [resolvers] */
    else if (strcmp(section,"resolvers")==0) {
        if (strcmp(key,"seed_list")==0) {
            /* comma-separated IPs */
            char tmp[4096];
            strncpy(tmp, value, sizeof(tmp)-1);
            char *tok = strtok(tmp, ",");
            cfg->seed_count = 0;
            while (tok && cfg->seed_count < DNSTUN_MAX_RESOLVERS) {
                char *t = trim(tok);
                strncpy(cfg->seed_resolvers[cfg->seed_count++], t, 45);
                tok = strtok(NULL, ",");
            }
        }
        else if (strcmp(key,"cidr_scan")==0)     cfg->cidr_scan   = parse_bool(value);
        else if (strcmp(key,"cidr_prefix")==0)   cfg->cidr_prefix = atoi(value);
        else if (strcmp(key,"swarm_sync")==0)    cfg->swarm_sync  = parse_bool(value);
        else if (strcmp(key,"background_recovery_rate")==0)
            cfg->background_recovery_rate = atoi(value);
    }
    /* [tuning] */
    else if (strcmp(section,"tuning")==0) {
        if      (strcmp(key,"poll_interval_ms")==0) cfg->poll_interval_ms = atoi(value);
        else if (strcmp(key,"fec_window")==0)       cfg->fec_window       = atoi(value);
        else if (strcmp(key,"fec_redundancy")==0)   cfg->fec_redundancy   = atoi(value);
        else if (strcmp(key,"cwnd_init")==0)        cfg->cwnd_init        = atof(value);
        else if (strcmp(key,"cwnd_max")==0)         cfg->cwnd_max         = atof(value);
        else if (strcmp(key,"idle_timeout_sec")==0)  cfg->idle_timeout_sec  = atoi(value);
        else if (strcmp(key,"downstream_mtu")==0)    cfg->downstream_mtu   = atoi(value);
    }
    /* [mtu_testing] - Binary search MTU testing like client.py */
    else if (strcmp(section,"mtu_testing")==0) {
        if      (strcmp(key,"max_upload_mtu")==0)       cfg->max_upload_mtu      = atoi(value);
        else if (strcmp(key,"max_download_mtu")==0)      cfg->max_download_mtu    = atoi(value);
        else if (strcmp(key,"min_upload_mtu")==0)        cfg->min_upload_mtu      = atoi(value);
        else if (strcmp(key,"min_download_mtu")==0)       cfg->min_download_mtu    = atoi(value);
        else if (strcmp(key,"mtu_test_retries")==0)      cfg->mtu_test_retries    = atoi(value);
        else if (strcmp(key,"mtu_test_timeout_ms")==0)   cfg->mtu_test_timeout_ms = atoi(value);
        else if (strcmp(key,"mtu_test_parallelism")==0)  cfg->mtu_test_parallelism = atoi(value);
    }
    /* [packet_aggregation] - Pack multiple symbols into one packet */
    else if (strcmp(section,"packet_aggregation")==0) {
        if      (strcmp(key,"enabled")==0)              cfg->packet_aggregation = parse_bool(value);
        else if (strcmp(key,"symbol_size")==0)            cfg->symbol_size = atoi(value);
        else if (strcmp(key,"max_symbols_per_packet")==0) cfg->max_symbols_per_packet = atoi(value);
        else if (strcmp(key,"auto_aggregate")==0)        cfg->auto_aggregate = parse_bool(value);
    }
    /* [domains] */
    else if (strcmp(section,"domains")==0) {
        if (strcmp(key,"list")==0) {
            char tmp[4096];
            strncpy(tmp, value, sizeof(tmp)-1);
            char *tok = strtok(tmp, ",");
            cfg->domain_count = 0;
            while (tok && cfg->domain_count < DNSTUN_MAX_DOMAINS) {
                char *t = trim(tok);
                strncpy(cfg->domains[cfg->domain_count++], t, 255);
                tok = strtok(NULL, ",");
            }
        }
        else if (strcmp(key,"dns_flux")==0)      cfg->dns_flux        = parse_bool(value);
        else if (strcmp(key,"flux_period_sec")==0) cfg->flux_period_sec = atoi(value);
    }
    /* [resolver_testing] - Scanner.py style DNS resolver testing */
    else if (strcmp(section,"resolver_testing")==0) {
        if      (strcmp(key,"test_domain")==0)          strncpy(cfg->test_domain, value, sizeof(cfg->test_domain)-1);
        else if (strcmp(key,"nonexistent_domain")==0)   strncpy(cfg->nonexistent_domain, value, sizeof(cfg->nonexistent_domain)-1);
        else if (strcmp(key,"long_label_domain")==0)    strncpy(cfg->long_label_domain, value, sizeof(cfg->long_label_domain)-1);
        else if (strcmp(key,"test_timeout_ms")==0)      cfg->test_timeout_ms = atoi(value);
    }
    /* [transport] */
    else if (strcmp(section,"transport")==0) {
        if (strcmp(key,"mode")==0) {
            if      (strcmp(value,"doh")==0) cfg->transport = TRANSPORT_DOH;
            else if (strcmp(value,"dot")==0) cfg->transport = TRANSPORT_DOT;
            else                             cfg->transport = TRANSPORT_UDP;
        }
    }
    /* [encryption] */
    else if (strcmp(section,"encryption")==0) {
        if      (strcmp(key,"enabled")==0)      cfg->encryption = parse_bool(value);
        else if (strcmp(key,"cipher")==0) {
            if      (strcmp(value,"aes256gcm")==0) cfg->cipher = CIPHER_AES256GCM;
            else if (strcmp(value,"noise_nk")==0)  cfg->cipher = CIPHER_NOISE_NK;
            else                                   cfg->cipher = CIPHER_CHACHA20;
        }
        else if (strcmp(key,"psk")==0)          strncpy(cfg->psk, value, sizeof(cfg->psk)-1);
        else if (strcmp(key,"pubkey_file")==0)  strncpy(cfg->pubkey_file, value, sizeof(cfg->pubkey_file)-1);
        else if (strcmp(key,"privkey_file")==0) strncpy(cfg->privkey_file, value, sizeof(cfg->privkey_file)-1);
    }
    /* [obfuscation] */
    else if (strcmp(section,"obfuscation")==0) {
        if      (strcmp(key,"jitter")==0)       cfg->jitter       = parse_bool(value);
        else if (strcmp(key,"padding")==0)      cfg->padding      = parse_bool(value);
        else if (strcmp(key,"chaffing")==0)     cfg->chaffing     = parse_bool(value);
        else if (strcmp(key,"chrome_cover")==0) cfg->chrome_cover = parse_bool(value);
    }
    /* [swarm] */
    else if (strcmp(section,"swarm")==0) {
        if      (strcmp(key,"serve")==0)       cfg->swarm_serve    = parse_bool(value);
        else if (strcmp(key,"save_to_disk")==0) cfg->swarm_save_disk = parse_bool(value);
    }
    /* [ota] */
    else if (strcmp(section,"ota")==0) {
        if      (strcmp(key,"enabled")==0)             cfg->ota_enabled = parse_bool(value);
        else if (strcmp(key,"check_interval_sec")==0)  cfg->ota_check_interval_sec = atoi(value);
    }
    else {
        return -1; /* unknown section */
    }
    return 0;
}

/* ── INI File loader ────────────────────────────────────────────────────────*/
int config_load(dnstun_config_t *cfg, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[config] cannot open '%s'\n", path);
        return -1;
    }

    char   line[1024];
    char   section[64] = "";
    int    lineno = 0;
    int    errors = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *l = trim(line);

        /* skip blank lines and comments */
        if (!l[0] || l[0] == '#' || l[0] == ';') continue;

        /* section header */
        if (l[0] == '[') {
            char *end = strchr(l, ']');
            if (!end) {
                fprintf(stderr, "[config] line %d: malformed section\n", lineno);
                errors++;
                continue;
            }
            *end = '\0';
            strncpy(section, l+1, sizeof(section)-1);
            section[sizeof(section)-1] = '\0';
            continue;
        }

        /* key = value */
        char *eq = strchr(l, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key   = trim(l);
        char *value = trim(eq+1);

        /* strip inline comments */
        char *comment = strchr(value, '#');
        if (!comment) comment = strchr(value, ';');
        if (comment) *comment = '\0';
        value = trim(value);

        if (config_set_key(cfg, section, key, value) != 0) {
            errors++;
            if (cfg->log_level >= 2)
                fprintf(stderr, "[config] unknown key [%s] %s at line %d\n",
                        section, key, lineno);
        }
    }

    fclose(f);
    return errors ? -1 : 0;
}

/* ── Dump ───────────────────────────────────────────────────────────────────*/
void config_dump(const dnstun_config_t *cfg) {
    printf("[core]\n");
    if (!cfg->is_server)
        printf("  socks5_bind       = %s\n", cfg->socks5_bind);
    else
        printf("  server_bind       = %s\n", cfg->server_bind);
    printf("  workers           = %d\n", cfg->workers);
    printf("  threads           = %d\n", cfg->threads);
    printf("  log_level         = %d\n", cfg->log_level);

    printf("[resolvers]\n");
    printf("  seed_count        = %d\n", cfg->seed_count);
    printf("  cidr_scan         = %s\n", cfg->cidr_scan ? "true" : "false");
    printf("  cidr_prefix       = /%d\n", cfg->cidr_prefix);
    printf("  swarm_sync        = %s\n", cfg->swarm_sync ? "true" : "false");
    printf("  recovery_rate     = %d IPs/s\n", cfg->background_recovery_rate);

    printf("[tuning]\n");
    printf("  poll_interval_ms  = %d\n", cfg->poll_interval_ms);
    printf("  fec_window        = %d\n", cfg->fec_window);
    printf("  cwnd_init         = %.0f\n", cfg->cwnd_init);
    printf("  cwnd_max          = %.0f\n", cfg->cwnd_max);

    printf("[encryption]\n");
    printf("  enabled           = %s\n", cfg->encryption ? "true" : "false");
    const char *ciphers[] = { "none","chacha20","aes256gcm","noise_nk" };
    printf("  cipher            = %s\n", ciphers[cfg->cipher]);

    printf("[obfuscation]\n");
    printf("  jitter            = %s\n", cfg->jitter       ? "true" : "false");
    printf("  padding           = %s\n", cfg->padding      ? "true" : "false");
    printf("  chaffing          = %s\n", cfg->chaffing     ? "true" : "false");
    printf("  chrome_cover      = %s\n", cfg->chrome_cover ? "true" : "false");
}

/* ── INI file writer ────────────────────────────────────────────────────────
   Reads the entire INI file into memory, replaces (or inserts) a single
   key under the given section, then writes the result back to disk.
   Strategy:
     1. If [section] + key found      → replace that line in-place.
     2. If [section] found, key absent → insert "key = value" after header.
     3. Neither found                  → append "\n[section]\nkey = value\n".
   The file is kept small enough that reading it fully into memory is fine. */
int config_save_key(const char *path, const char *section,
                    const char *key, const char *value)
{
    /* ── Read whole file ── */
    FILE *f = fopen(path, "r");
    char **lines   = NULL;
    int    nlines  = 0;
    int    cap     = 64;

    lines = malloc(cap * sizeof(char*));
    if (!lines) return -1;

    if (f) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), f)) {
            if (nlines >= cap) {
                cap *= 2;
                char **tmp = realloc(lines, cap * sizeof(char*));
                if (!tmp) { fclose(f); goto fail; }
                lines = tmp;
            }
            lines[nlines++] = strdup(buf);
        }
        fclose(f);
    }
    /* If file did not exist yet, we'll create it from scratch below. */

    /* ── Scan for section + key ── */
    char sec_hdr[80];
    snprintf(sec_hdr, sizeof(sec_hdr), "[%s]", section);

    int  in_section   = 0;
    int  key_replaced = 0;
    int  sec_line     = -1;     /* index of the section-header line */

    for (int i = 0; i < nlines; i++) {
        char *l = lines[i];
        /* section header? */
        if (l[0] == '[') {
            if (strncmp(l, sec_hdr, strlen(sec_hdr)) == 0) {
                in_section = 1;
                sec_line   = i;
            } else {
                /* If we were in our section and haven't found the key yet,
                   insert it BEFORE this next section header. */
                if (in_section && !key_replaced && sec_line >= 0) {
                    char newline[1024];
                    snprintf(newline, sizeof(newline), "%s = %s\n", key, value);
                    /* Insert at position i */
                    if (nlines >= cap) {
                        cap *= 2;
                        char **tmp = realloc(lines, cap * sizeof(char*));
                        if (!tmp) goto fail;
                        lines = tmp;
                    }
                    memmove(&lines[i+1], &lines[i], (nlines - i) * sizeof(char*));
                    lines[i] = strdup(newline);
                    nlines++;
                    key_replaced = 1;
                }
                in_section = 0;
            }
            continue;
        }
        if (!in_section) continue;

        /* key = value line? */
        char *eq = strchr(l, '=');
        if (!eq) continue;
        /* extract key name */
        char lkey[128] = {0};
        size_t klen = (size_t)(eq - l);
        if (klen >= sizeof(lkey)) continue;
        strncpy(lkey, l, klen);
        /* trim lkey */
        char *lk = lkey;
        while (*lk == ' ' || *lk == '\t') lk++;
        char *lke = lk + strlen(lk) - 1;
        while (lke > lk && (*lke == ' ' || *lke == '\t')) *lke-- = '\0';

        if (strcmp(lk, key) == 0) {
            /* Replace this line */
            free(lines[i]);
            char newline[1024];
            snprintf(newline, sizeof(newline), "%s = %s\n", key, value);
            lines[i]     = strdup(newline);
            key_replaced = 1;
        }
    }

    /* If we ended while still in our section and never replaced */
    if (in_section && !key_replaced && sec_line >= 0) {
        if (nlines >= cap) {
            cap *= 2;
            char **tmp = realloc(lines, cap * sizeof(char*));
            if (!tmp) goto fail;
            lines = tmp;
        }
        char newline[1024];
        snprintf(newline, sizeof(newline), "%s = %s\n", key, value);
        lines[nlines++] = strdup(newline);
        key_replaced = 1;
    }

    /* Section never found: append it */
    if (!key_replaced) {
        /* Ensure trailing newline separation */
        if (nlines > 0) {
            const char *last = lines[nlines-1];
            size_t ll = strlen(last);
            if (ll == 0 || last[ll-1] != '\n') {
                if (nlines + 3 >= cap) {
                    cap += 8;
                    char **tmp = realloc(lines, cap * sizeof(char*));
                    if (!tmp) goto fail;
                    lines = tmp;
                }
                lines[nlines++] = strdup("\n");
            }
        }
        if (nlines + 3 >= cap) {
            cap += 8;
            char **tmp = realloc(lines, cap * sizeof(char*));
            if (!tmp) goto fail;
            lines = tmp;
        }
        char hdr[80];
        snprintf(hdr, sizeof(hdr), "[%s]\n", section);
        lines[nlines++] = strdup(hdr);
        char newline[1024];
        snprintf(newline, sizeof(newline), "%s = %s\n", key, value);
        lines[nlines++] = strdup(newline);
    }

    /* ── Write back ── */
    f = fopen(path, "w");
    if (!f) goto fail;
    for (int i = 0; i < nlines; i++)
        if (lines[i]) fputs(lines[i], f);
    fclose(f);

    for (int i = 0; i < nlines; i++) free(lines[i]);
    free(lines);
    return 0;

fail:
    for (int i = 0; i < nlines; i++) free(lines[i]);
    free(lines);
    return -1;
}

/* ── Persist domains list ───────────────────────────────────────────────────*/
int config_save_domains(const char *path, const dnstun_config_t *cfg)
{
    /* Build "domain1,domain2,..." string */
    char value[4096] = {0};
    for (int i = 0; i < cfg->domain_count; i++) {
        if (i > 0) strncat(value, ",", sizeof(value) - strlen(value) - 1);
        strncat(value, cfg->domains[i], sizeof(value) - strlen(value) - 1);
    }
    return config_save_key(path, "domains", "list", value);
}
