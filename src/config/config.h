#ifndef IOGUARD_CONFIG_CONFIG_H
#define IOGUARD_CONFIG_CONFIG_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t IOG_CONFIG_MAX_DNS = 8;
constexpr size_t IOG_CONFIG_MAX_STR = 256;

typedef struct {
    char listen_address[IOG_CONFIG_MAX_STR];
    uint16_t listen_port;
    uint16_t dtls_port;
    uint32_t max_clients;
    uint32_t worker_count;
} iog_config_server_t;

typedef struct {
    char method[64];
    uint32_t cookie_timeout;
    uint32_t cookie_rekey;
    char totp_issuer[128];
    uint32_t totp_digits;
    uint32_t totp_window;
} iog_config_auth_t;

constexpr size_t IOG_CONFIG_MAX_POOLS = 16;

typedef struct {
    char ipv4_pools[IOG_CONFIG_MAX_POOLS][IOG_CONFIG_MAX_STR];
    uint32_t ipv4_pool_count;
    char ipv6_pools[IOG_CONFIG_MAX_POOLS][IOG_CONFIG_MAX_STR];
    uint32_t ipv6_pool_count;
    char dns[IOG_CONFIG_MAX_DNS][IOG_CONFIG_MAX_STR];
    uint32_t dns_count;
    char default_domain[IOG_CONFIG_MAX_STR];
    uint32_t mtu;
} iog_config_network_t;

typedef struct {
    char cert_file[IOG_CONFIG_MAX_STR];
    char key_file[IOG_CONFIG_MAX_STR];
    char min_version[16];
    char ciphers[512];
} iog_config_tls_t;

typedef struct {
    bool seccomp;
    bool landlock;
    char wolfsentry_config[IOG_CONFIG_MAX_STR];
} iog_config_security_t;

typedef struct {
    char mdbx_path[IOG_CONFIG_MAX_STR];
    char sqlite_path[IOG_CONFIG_MAX_STR];
    char vault_key_path[IOG_CONFIG_MAX_STR];
} iog_config_storage_t;

typedef struct {
    iog_config_server_t server;
    iog_config_auth_t auth;
    iog_config_network_t network;
    iog_config_tls_t tls;
    iog_config_security_t security;
    iog_config_storage_t storage;
} iog_config_t;

void iog_config_set_defaults(iog_config_t *cfg);

[[nodiscard]] int iog_config_load(const char *path, iog_config_t *cfg);

void iog_config_free(iog_config_t *cfg);

#endif /* IOGUARD_CONFIG_CONFIG_H */
