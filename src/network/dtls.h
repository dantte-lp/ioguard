/**
 * @file dtls.h
 * @brief DTLS 1.2 context management for Cisco client compatibility.
 *
 * wolfSSL DTLS 1.2 context lifecycle: config, create, destroy.
 * No handshake logic — just context setup with cipher suites and MTU.
 */

#ifndef WOLFGUARD_NETWORK_DTLS_H
#define WOLFGUARD_NETWORK_DTLS_H

#include <stdbool.h>
#include <stdint.h>

constexpr uint32_t WG_DTLS_DEFAULT_MTU = 1400;
constexpr uint32_t WG_DTLS_DEFAULT_TIMEOUT_S = 5;
constexpr uint32_t WG_DTLS_DEFAULT_REKEY_S = 3600;

typedef struct {
	uint32_t mtu;
	uint32_t timeout_init_s;
	uint32_t rekey_interval_s;
	const char *cert_file;
	const char *key_file;
	const char *ca_file;
	const char *cipher_list;
	bool enable_cookies;
} wg_dtls_config_t;

typedef struct wg_dtls_ctx wg_dtls_ctx_t;

/** Initialize DTLS config with defaults. */
void wg_dtls_config_init(wg_dtls_config_t *cfg);

/** Validate DTLS config. Returns 0 or negative errno. */
[[nodiscard]] int wg_dtls_config_validate(const wg_dtls_config_t *cfg);

/** Create DTLS context. Returns nullptr on failure. */
[[nodiscard]] wg_dtls_ctx_t *wg_dtls_create(const wg_dtls_config_t *cfg);

/** Destroy DTLS context. */
void wg_dtls_destroy(wg_dtls_ctx_t *ctx);

/** Get MTU for DTLS context. */
[[nodiscard]] uint32_t wg_dtls_get_mtu(const wg_dtls_ctx_t *ctx);

/** Cisco-compatible DTLS 1.2 cipher list string. */
[[nodiscard]] const char *wg_dtls_cisco_ciphers(void);

#endif /* WOLFGUARD_NETWORK_DTLS_H */
