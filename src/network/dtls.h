/**
 * @file dtls.h
 * @brief DTLS 1.2 context management for Cisco client compatibility.
 *
 * wolfSSL DTLS 1.2 context lifecycle: config, create, destroy.
 * No handshake logic — just context setup with cipher suites and MTU.
 */

#ifndef IOGUARD_NETWORK_DTLS_H
#define IOGUARD_NETWORK_DTLS_H

#include <stdint.h>

constexpr uint32_t IOG_DTLS_DEFAULT_MTU = 1400;
constexpr uint32_t IOG_DTLS_DEFAULT_TIMEOUT_S = 5;
constexpr uint32_t IOG_DTLS_DEFAULT_REKEY_S = 3600;

typedef struct {
    uint32_t mtu;
    uint32_t timeout_init_s;
    uint32_t rekey_interval_s;
    const char *cert_file;
    const char *key_file;
    const char *ca_file;
    const char *cipher_list;
    bool enable_cookies;
} iog_dtls_config_t;

typedef struct iog_dtls_ctx iog_dtls_ctx_t;

/** Initialize DTLS config with defaults. */
void iog_dtls_config_init(iog_dtls_config_t *cfg);

/** Validate DTLS config. Returns 0 or negative errno. */
[[nodiscard]] int iog_dtls_config_validate(const iog_dtls_config_t *cfg);

/** Create DTLS context. Returns nullptr on failure. */
[[nodiscard]] iog_dtls_ctx_t *iog_dtls_create(const iog_dtls_config_t *cfg);

/** Destroy DTLS context. */
void iog_dtls_destroy(iog_dtls_ctx_t *ctx);

/** Get MTU for DTLS context. */
[[nodiscard]] uint32_t iog_dtls_get_mtu(const iog_dtls_ctx_t *ctx);

/** Cisco-compatible DTLS 1.2 cipher list string. */
[[nodiscard]] const char *iog_dtls_cisco_ciphers(void);

#endif /* IOGUARD_NETWORK_DTLS_H */
