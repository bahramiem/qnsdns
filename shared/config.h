#pragma once
#ifndef DNSTUN_CONFIG_H
#define DNSTUN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include "types.h"

/* ──────────────────────────────────────────────
   Config structure — covers ALL features
   in both client.ini and server.ini
────────────────────────────────────────────── */
typedef struct dnstun_config {

    /* [core] */
    char     socks5_bind[64];   /* e.g. "127.0.0.1:1080" */
    char     server_bind[64];   /* server: e.g. "0.0.0.0:53"  */
    int      workers;           /* libuv UV_THREADPOOL_SIZE   */
    int      threads;           /* codec/FEC worker threads   */
    int      log_level;         /* 0=silent 1=info 2=debug    */
    bool     is_server;         /* true when running as server */
    char     user_id[16];       /* identifies this node in the swarm */

    /* [resolvers] / [server_sync] */
    char     seed_resolvers[DNSTUN_MAX_RESOLVERS][46]; /* IPv4/v6 strings */
    int      seed_count;
    bool     cidr_scan;
    int      cidr_prefix;       /* 24 or 16 */
    bool     swarm_sync;        /* client fetches server's list */
    bool     swarm_serve;       /* server serves list to clients */
    bool     swarm_save_disk;
    int      background_recovery_rate; /* IPs/sec to probe dead pool */

    /* [tuning] */
    int      poll_interval_ms;  /* downstream POLL interval */
    int      fec_window;        /* chunks between FEC recalc */
    double   cwnd_init;         /* starting cong window */
    double   cwnd_max;          /* max cong window */
    int      idle_timeout_sec;

    /* [domains] */
    char     domains[DNSTUN_MAX_DOMAINS][256];
    int      domain_count;
    bool     dns_flux;          /* time-sliced domain rotation */
    int      flux_period_sec;   /* default 21600 (6h) */

    /* [transport] */
    transport_t transport;      /* UDP | DOH | DOT */

    /* [encryption] */
    bool     encryption;
    cipher_t cipher;
    char     psk[256];          /* pre-shared key */
    char     pubkey_file[256];  /* Noise_NK: server public key file */
    char     privkey_file[256]; /* Noise_NK: server private key file */

    /* [obfuscation] */
    bool     jitter;
    bool     padding;
    bool     chaffing;
    bool     chrome_cover;      /* Chrome DNS fingerprint traffic */

    /* [ota] */
    bool     ota_enabled;
    int      ota_check_interval_sec;

} dnstun_config_t;

/* ──────────────────────────────────────────────
   API
────────────────────────────────────────────── */

/* Load config from INI file. Returns 0 on success. */
int  config_load(dnstun_config_t *cfg, const char *path);

/* Apply defaults to an uninitialised config struct. */
void config_defaults(dnstun_config_t *cfg, bool is_server);

/* Dump current config to stdout (for TUI config panel). */
void config_dump(const dnstun_config_t *cfg);

/* Reload specific key=value pair at runtime (for TUI live edit). */
int  config_set_key(dnstun_config_t *cfg, const char *section,
                    const char *key, const char *value);

/* Write one key back into an existing INI file (creates section if absent).
   Returns 0 on success. */
int  config_save_key(const char *path, const char *section,
                     const char *key, const char *value);

/* Persist the current domains list back to the INI file. */
int  config_save_domains(const char *path, const dnstun_config_t *cfg);

#endif /* DNSTUN_CONFIG_H */
