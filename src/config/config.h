#ifndef WOLFGUARD_CONFIG_CONFIG_H
#define WOLFGUARD_CONFIG_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

constexpr size_t WG_CONFIG_MAX_DNS = 8;
constexpr size_t WG_CONFIG_MAX_STR = 256;

typedef struct {
    char listen_address[WG_CONFIG_MAX_STR];
    uint16_t listen_port;
    uint16_t dtls_port;
    uint32_t max_clients;
    uint32_t worker_count;
} wg_config_server_t;

typedef struct {
    char method[64];
    uint32_t cookie_timeout;
    uint32_t cookie_rekey;
} wg_config_auth_t;

typedef struct {
    char ipv4_pool[WG_CONFIG_MAX_STR];
    char dns[WG_CONFIG_MAX_DNS][WG_CONFIG_MAX_STR];
    uint32_t dns_count;
    char default_domain[WG_CONFIG_MAX_STR];
    uint32_t mtu;
} wg_config_network_t;

typedef struct {
    char cert_file[WG_CONFIG_MAX_STR];
    char key_file[WG_CONFIG_MAX_STR];
    char min_version[16];
    char ciphers[512];
} wg_config_tls_t;

typedef struct {
    bool seccomp;
    bool landlock;
    char wolfsentry_config[WG_CONFIG_MAX_STR];
} wg_config_security_t;

typedef struct {
    wg_config_server_t server;
    wg_config_auth_t auth;
    wg_config_network_t network;
    wg_config_tls_t tls;
    wg_config_security_t security;
} wg_config_t;

void wg_config_set_defaults(wg_config_t *cfg);

[[nodiscard]] int wg_config_load(const char *path, wg_config_t *cfg);

void wg_config_free(wg_config_t *cfg);

#endif /* WOLFGUARD_CONFIG_CONFIG_H */
