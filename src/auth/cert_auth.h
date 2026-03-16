#ifndef IOGUARD_AUTH_CERT_H
#define IOGUARD_AUTH_CERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "auth/auth_backend.h"

/** Maximum path length for CA certificate and CRL files. */
constexpr size_t IOG_CERT_PATH_MAX = 256;

/** Maximum OID string length for MS AD certificate template. */
constexpr size_t IOG_CERT_TEMPLATE_OID_MAX = 128;

/** Maximum template name length. */
constexpr size_t IOG_CERT_TEMPLATE_NAME_MAX = 64;

/** Maximum username field specifier length. */
constexpr size_t IOG_CERT_USERNAME_FIELD_MAX = 32;

/** Maximum extracted username length. */
constexpr size_t IOG_CERT_USERNAME_MAX = 256;

/** Certificate authentication configuration. */
typedef struct {
    char ca_cert_path[IOG_CERT_PATH_MAX];             /**< Trusted CA for client certs */
    char crl_path[IOG_CERT_PATH_MAX];                 /**< CRL file path (optional) */
    bool require_eku;                                 /**< Require EKU: Client Authentication */
    char template_oid[IOG_CERT_TEMPLATE_OID_MAX];     /**< MS AD template OID (optional) */
    char template_name[IOG_CERT_TEMPLATE_NAME_MAX];   /**< Required template name (optional) */
    char username_field[IOG_CERT_USERNAME_FIELD_MAX]; /**< "CN", "SAN:email", "SAN:UPN" */
} iog_cert_auth_config_t;

/**
 * Initialize the certificate authentication backend.
 *
 * @param config  Pointer to certificate auth configuration.
 * @return 0 on success, -EINVAL if config is null or invalid,
 *         -EALREADY if already initialized.
 */
[[nodiscard]] int iog_cert_auth_init(const iog_cert_auth_config_t *config);

/**
 * Destroy the certificate authentication backend.
 *
 * Safe to call with uninitialized state or multiple times.
 */
void iog_cert_auth_destroy(void);

/**
 * Get the certificate authentication backend descriptor.
 *
 * @return Pointer to the static backend descriptor.
 */
[[nodiscard]] const iog_auth_backend_t *iog_cert_auth_backend(void);

/**
 * Extract a username from a DER-encoded X.509 certificate.
 *
 * The field extracted depends on the configured username_field:
 * - "CN":        Common Name from the subject
 * - "SAN:email": Email from Subject Alternative Name
 * - "SAN:UPN":   User Principal Name from SAN
 *
 * @param der       DER-encoded certificate bytes.
 * @param der_len   Length of the DER data.
 * @param field     Username field specifier (e.g., "CN").
 * @param out       Output buffer for the extracted username.
 * @param out_size  Size of the output buffer.
 * @return 0 on success, -EINVAL for null/invalid arguments,
 *         -ENOENT if the certificate contains no data,
 *         -ENOSPC if the output buffer is too small,
 *         -ENOTSUP if wolfSSL is not compiled in.
 */
[[nodiscard]] int iog_cert_extract_username(const uint8_t *der, size_t der_len, const char *field,
                                            char *out, size_t out_size);

#endif /* IOGUARD_AUTH_CERT_H */
