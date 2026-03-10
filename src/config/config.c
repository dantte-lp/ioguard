#include "config/config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_TOML
#    include <toml.h>
#endif

static void safe_copy(char *dst, const char *src, size_t dst_size)
{
    if (src == nullptr) {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

void rw_config_set_defaults(rw_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    safe_copy(cfg->server.listen_address, "0.0.0.0", sizeof(cfg->server.listen_address));
    cfg->server.listen_port = 443;
    cfg->server.dtls_port = 443;
    cfg->server.max_clients = 256;
    cfg->server.worker_count = 0;
    safe_copy(cfg->auth.method, "pam", sizeof(cfg->auth.method));
    cfg->auth.cookie_timeout = 300;
    cfg->auth.cookie_rekey = 14400;
    snprintf(cfg->auth.totp_issuer, sizeof(cfg->auth.totp_issuer), "ioguard");
    cfg->auth.totp_digits = 6;
    cfg->auth.totp_window = 1;
    cfg->network.mtu = 1400;
    safe_copy(cfg->tls.min_version, "1.2", sizeof(cfg->tls.min_version));
    cfg->security.seccomp = true;
    cfg->security.landlock = true;
}

#ifdef USE_TOML

static void parse_server(toml_table_t *tbl, rw_config_server_t *srv)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "listen-address");
    if (d.ok) {
        safe_copy(srv->listen_address, d.u.s, sizeof(srv->listen_address));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "listen-port");
    if (d.ok) {
        srv->listen_port = (uint16_t)d.u.i;
    }
    d = toml_int_in(tbl, "dtls-port");
    if (d.ok) {
        srv->dtls_port = (uint16_t)d.u.i;
    }
    d = toml_int_in(tbl, "max-clients");
    if (d.ok) {
        srv->max_clients = (uint32_t)d.u.i;
    }
    d = toml_int_in(tbl, "worker-count");
    if (d.ok) {
        srv->worker_count = (uint32_t)d.u.i;
    }
}

static void parse_auth(toml_table_t *tbl, rw_config_auth_t *auth)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "method");
    if (d.ok) {
        safe_copy(auth->method, d.u.s, sizeof(auth->method));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "cookie-timeout");
    if (d.ok) {
        auth->cookie_timeout = (uint32_t)d.u.i;
    }
    d = toml_int_in(tbl, "cookie-rekey");
    if (d.ok) {
        auth->cookie_rekey = (uint32_t)d.u.i;
    }
    d = toml_string_in(tbl, "totp-issuer");
    if (d.ok) {
        safe_copy(auth->totp_issuer, d.u.s, sizeof(auth->totp_issuer));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "totp-digits");
    if (d.ok) {
        auth->totp_digits = (uint32_t)d.u.i;
    }
    d = toml_int_in(tbl, "totp-window");
    if (d.ok) {
        auth->totp_window = (uint32_t)d.u.i;
    }
}

static void parse_network(toml_table_t *tbl, rw_config_network_t *net)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "ipv4-pool");
    if (d.ok && net->ipv4_pool_count < RW_CONFIG_MAX_POOLS) {
        safe_copy(net->ipv4_pools[net->ipv4_pool_count], d.u.s, sizeof(net->ipv4_pools[0]));
        net->ipv4_pool_count++;
        free(d.u.s);
    }
    d = toml_string_in(tbl, "default-domain");
    if (d.ok) {
        safe_copy(net->default_domain, d.u.s, sizeof(net->default_domain));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "mtu");
    if (d.ok) {
        net->mtu = (uint32_t)d.u.i;
    }

    toml_array_t *dns_arr = toml_array_in(tbl, "dns");
    if (dns_arr != nullptr) {
        int nelem = toml_array_nelem(dns_arr);
        size_t n = nelem > 0 ? (size_t)nelem : 0;
        if (n > RW_CONFIG_MAX_DNS) {
            n = RW_CONFIG_MAX_DNS;
        }
        for (size_t i = 0; i < n; i++) {
            d = toml_string_at(dns_arr, i);
            if (d.ok) {
                safe_copy(net->dns[i], d.u.s, sizeof(net->dns[i]));
                free(d.u.s);
                net->dns_count++;
            }
        }
    }
}

static void parse_tls(toml_table_t *tbl, rw_config_tls_t *tls)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "cert-file");
    if (d.ok) {
        safe_copy(tls->cert_file, d.u.s, sizeof(tls->cert_file));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "key-file");
    if (d.ok) {
        safe_copy(tls->key_file, d.u.s, sizeof(tls->key_file));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "min-version");
    if (d.ok) {
        safe_copy(tls->min_version, d.u.s, sizeof(tls->min_version));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "ciphers");
    if (d.ok) {
        safe_copy(tls->ciphers, d.u.s, sizeof(tls->ciphers));
        free(d.u.s);
    }
}

static void parse_storage(toml_table_t *tbl, rw_config_storage_t *storage)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "mdbx-path");
    if (d.ok) {
        safe_copy(storage->mdbx_path, d.u.s, sizeof(storage->mdbx_path));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "sqlite-path");
    if (d.ok) {
        safe_copy(storage->sqlite_path, d.u.s, sizeof(storage->sqlite_path));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "vault-key-path");
    if (d.ok) {
        safe_copy(storage->vault_key_path, d.u.s, sizeof(storage->vault_key_path));
        free(d.u.s);
    }
}

static void parse_security(toml_table_t *tbl, rw_config_security_t *sec)
{
    toml_datum_t d;
    d = toml_bool_in(tbl, "seccomp");
    if (d.ok) {
        sec->seccomp = d.u.b;
    }
    d = toml_bool_in(tbl, "landlock");
    if (d.ok) {
        sec->landlock = d.u.b;
    }
    d = toml_string_in(tbl, "wolfsentry-config");
    if (d.ok) {
        safe_copy(sec->wolfsentry_config, d.u.s, sizeof(sec->wolfsentry_config));
        free(d.u.s);
    }
}

int rw_config_load(const char *path, rw_config_t *cfg)
{
    rw_config_set_defaults(cfg);

    FILE *fp = fopen(path, "r");
    if (fp == nullptr) {
        return -errno;
    }

    char errbuf[256];
    toml_table_t *root = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    if (root == nullptr) {
        return -EINVAL;
    }

    toml_table_t *tbl;
    tbl = toml_table_in(root, "server");
    if (tbl) {
        parse_server(tbl, &cfg->server);
    }
    tbl = toml_table_in(root, "auth");
    if (tbl) {
        parse_auth(tbl, &cfg->auth);
    }
    tbl = toml_table_in(root, "network");
    if (tbl) {
        parse_network(tbl, &cfg->network);
    }
    tbl = toml_table_in(root, "tls");
    if (tbl) {
        parse_tls(tbl, &cfg->tls);
    }
    tbl = toml_table_in(root, "security");
    if (tbl) {
        parse_security(tbl, &cfg->security);
    }
    tbl = toml_table_in(root, "storage");
    if (tbl) {
        parse_storage(tbl, &cfg->storage);
    }

    toml_free(root);
    return 0;
}

#else

int rw_config_load(const char *path, rw_config_t *cfg)
{
    (void)path;
    rw_config_set_defaults(cfg);
    return -ENOTSUP;
}

#endif

void rw_config_free(rw_config_t *cfg)
{
    (void)cfg;
}
