#ifndef IOGUARD_AUTH_RADIUS_H
#define IOGUARD_AUTH_RADIUS_H

#include <stddef.h>
#include <stdint.h>

struct iog_auth_backend;

/** Maximum length for RADIUS server address (host:port). */
constexpr size_t IOG_RADIUS_SERVER_MAX = 256;

/** Maximum length for RADIUS shared secret. */
constexpr size_t IOG_RADIUS_SECRET_MAX = 128;

/** Maximum length for RADIUS dictionary path. */
constexpr size_t IOG_RADIUS_DICT_PATH_MAX = 256;

/** Maximum length for NAS-Identifier attribute. */
constexpr size_t IOG_RADIUS_NAS_ID_MAX = 64;

/** Default RADIUS request timeout in milliseconds. */
constexpr uint32_t IOG_RADIUS_DEFAULT_TIMEOUT_MS = 5000;

/** Default number of RADIUS retries. */
constexpr uint32_t IOG_RADIUS_DEFAULT_RETRIES = 3;

/**
 * RADIUS backend configuration.
 */
typedef struct {
    char server[IOG_RADIUS_SERVER_MAX];
    char secret[IOG_RADIUS_SECRET_MAX];
    char dictionary_path[IOG_RADIUS_DICT_PATH_MAX];
    uint32_t timeout_ms;
    uint32_t retries;
    char nas_identifier[IOG_RADIUS_NAS_ID_MAX];
} iog_radius_config_t;

/**
 * Initialize the RADIUS authentication backend.
 *
 * @param config  Pointer to a iog_radius_config_t. Must not be null.
 *                Fields server and secret are required. timeout_ms and retries
 *                default to 5000 and 3 respectively when set to 0.
 * @return 0 on success, -EINVAL for invalid config, -EIO on radcli failure.
 */
[[nodiscard]] int iog_radius_init(const void *config);

/**
 * Shut down the RADIUS backend and zero secrets.
 *
 * Safe to call when not initialized (no-op).
 */
void iog_radius_destroy(void);

/**
 * Return the RADIUS authentication backend descriptor.
 *
 * @return Pointer to a static backend struct with name "radius".
 */
const struct iog_auth_backend *iog_radius_backend(void);

/**
 * Apply defaults to a RADIUS configuration.
 *
 * Sets timeout_ms to IOG_RADIUS_DEFAULT_TIMEOUT_MS and retries to
 * IOG_RADIUS_DEFAULT_RETRIES when the respective fields are zero.
 *
 * @param cfg  Configuration to fill defaults for. Must not be null.
 * @return 0 on success, -EINVAL if cfg is null.
 */
[[nodiscard]] int iog_radius_config_defaults(iog_radius_config_t *cfg);

/**
 * Validate a RADIUS configuration.
 *
 * Checks that server and secret are non-empty.
 *
 * @param cfg  Configuration to validate.
 * @return 0 on success, -EINVAL if validation fails.
 */
[[nodiscard]] int iog_radius_config_validate(const iog_radius_config_t *cfg);

#endif /* IOGUARD_AUTH_RADIUS_H */
