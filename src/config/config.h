#ifndef RINGWALL_CONFIG_CONFIG_H
#define RINGWALL_CONFIG_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_CONFIG_MAX_DNS = 8;
constexpr size_t RW_CONFIG_MAX_STR = 256;

typedef struct {
    char listen_address[RW_CONFIG_MAX_STR];
    uint16_t listen_port;
    uint16_t dtls_port;
    uint32_t max_clients;
    uint32_t worker_count;
} rw_config_server_t;

typedef struct {
    char method[64];
    uint32_t cookie_timeout;
    uint32_t cookie_rekey;
} rw_config_auth_t;

typedef struct {
    char ipv4_pool[RW_CONFIG_MAX_STR];
    char dns[RW_CONFIG_MAX_DNS][RW_CONFIG_MAX_STR];
    uint32_t dns_count;
    char default_domain[RW_CONFIG_MAX_STR];
    uint32_t mtu;
} rw_config_network_t;

typedef struct {
    char cert_file[RW_CONFIG_MAX_STR];
    char key_file[RW_CONFIG_MAX_STR];
    char min_version[16];
    char ciphers[512];
} rw_config_tls_t;

typedef struct {
    bool seccomp;
    bool landlock;
    char wolfsentry_config[RW_CONFIG_MAX_STR];
} rw_config_security_t;

typedef struct {
    rw_config_server_t server;
    rw_config_auth_t auth;
    rw_config_network_t network;
    rw_config_tls_t tls;
    rw_config_security_t security;
} rw_config_t;

void rw_config_set_defaults(rw_config_t *cfg);

[[nodiscard]] int rw_config_load(const char *path, rw_config_t *cfg);

void rw_config_free(rw_config_t *cfg);

#endif /* RINGWALL_CONFIG_CONFIG_H */
