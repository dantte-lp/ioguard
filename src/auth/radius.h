#ifndef RINGWALL_AUTH_RADIUS_H
#define RINGWALL_AUTH_RADIUS_H

#include <stddef.h>
#include <stdint.h>

struct rw_auth_backend;

/** Maximum length for RADIUS server address (host:port). */
constexpr size_t RW_RADIUS_SERVER_MAX = 256;

/** Maximum length for RADIUS shared secret. */
constexpr size_t RW_RADIUS_SECRET_MAX = 128;

/** Maximum length for RADIUS dictionary path. */
constexpr size_t RW_RADIUS_DICT_PATH_MAX = 256;

/** Maximum length for NAS-Identifier attribute. */
constexpr size_t RW_RADIUS_NAS_ID_MAX = 64;

/** Default RADIUS request timeout in milliseconds. */
constexpr uint32_t RW_RADIUS_DEFAULT_TIMEOUT_MS = 5000;

/** Default number of RADIUS retries. */
constexpr uint32_t RW_RADIUS_DEFAULT_RETRIES = 3;

/**
 * RADIUS backend configuration.
 */
typedef struct {
    char server[RW_RADIUS_SERVER_MAX];
    char secret[RW_RADIUS_SECRET_MAX];
    char dictionary_path[RW_RADIUS_DICT_PATH_MAX];
    uint32_t timeout_ms;
    uint32_t retries;
    char nas_identifier[RW_RADIUS_NAS_ID_MAX];
} rw_radius_config_t;

/**
 * Initialize the RADIUS authentication backend.
 *
 * @param config  Pointer to a rw_radius_config_t. Must not be null.
 *                Fields server and secret are required. timeout_ms and retries
 *                default to 5000 and 3 respectively when set to 0.
 * @return 0 on success, -EINVAL for invalid config, -EIO on radcli failure.
 */
[[nodiscard]] int rw_radius_init(const void *config);

/**
 * Shut down the RADIUS backend and zero secrets.
 *
 * Safe to call when not initialized (no-op).
 */
void rw_radius_destroy(void);

/**
 * Return the RADIUS authentication backend descriptor.
 *
 * @return Pointer to a static backend struct with name "radius".
 */
const struct rw_auth_backend *rw_radius_backend(void);

/**
 * Apply defaults to a RADIUS configuration.
 *
 * Sets timeout_ms to RW_RADIUS_DEFAULT_TIMEOUT_MS and retries to
 * RW_RADIUS_DEFAULT_RETRIES when the respective fields are zero.
 *
 * @param cfg  Configuration to fill defaults for. Must not be null.
 * @return 0 on success, -EINVAL if cfg is null.
 */
[[nodiscard]] int rw_radius_config_defaults(rw_radius_config_t *cfg);

/**
 * Validate a RADIUS configuration.
 *
 * Checks that server and secret are non-empty.
 *
 * @param cfg  Configuration to validate.
 * @return 0 on success, -EINVAL if validation fails.
 */
[[nodiscard]] int rw_radius_config_validate(const rw_radius_config_t *cfg);

#endif /* RINGWALL_AUTH_RADIUS_H */
