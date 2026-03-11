#ifndef IOGUARD_AUTH_LDAP_H
#define IOGUARD_AUTH_LDAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "auth/auth_backend.h"

/** Maximum URI length for LDAP server. */
constexpr size_t IOG_LDAP_URI_MAX = 512;

/** Maximum bind DN template length. */
constexpr size_t IOG_LDAP_BIND_DN_MAX = 512;

/** Maximum search base length. */
constexpr size_t IOG_LDAP_SEARCH_BASE_MAX = 256;

/** Maximum group attribute name length. */
constexpr size_t IOG_LDAP_GROUP_ATTR_MAX = 64;

/** Maximum group filter length. */
constexpr size_t IOG_LDAP_GROUP_FILTER_MAX = 256;

/** Maximum CA certificate path length. */
constexpr size_t IOG_LDAP_CA_CERT_MAX = 256;

/** Default LDAP operation timeout in milliseconds. */
constexpr uint32_t IOG_LDAP_DEFAULT_TIMEOUT_MS = 5000;

/** Maximum length of a constructed bind DN. */
constexpr size_t IOG_LDAP_DN_BUF_MAX = 1024;

/** Maximum length of a constructed search filter. */
constexpr size_t IOG_LDAP_FILTER_BUF_MAX = 512;

/** LDAP backend configuration. */
typedef struct {
    char uri[IOG_LDAP_URI_MAX];
    char bind_dn_template[IOG_LDAP_BIND_DN_MAX];
    char search_base[IOG_LDAP_SEARCH_BASE_MAX];
    char group_attr[IOG_LDAP_GROUP_ATTR_MAX];
    char group_filter[IOG_LDAP_GROUP_FILTER_MAX];
    bool use_starttls;
    uint32_t timeout_ms;
    char ca_cert_path[IOG_LDAP_CA_CERT_MAX];
} iog_ldap_config_t;

/**
 * Initialize the LDAP authentication backend.
 *
 * @param config  Pointer to LDAP configuration (copied internally).
 * @return 0 on success, -EINVAL if config is null or invalid.
 */
[[nodiscard]] int iog_ldap_init(const iog_ldap_config_t *config);

/**
 * Destroy the LDAP authentication backend and zero sensitive config.
 *
 * Safe to call with uninitialized state (no-op).
 */
void iog_ldap_destroy(void);

/**
 * Return the LDAP backend descriptor for registration.
 *
 * @return Pointer to the static LDAP backend descriptor.
 */
const iog_auth_backend_t *iog_ldap_backend(void);

/**
 * Build a bind DN from the template and username.
 *
 * Replaces the first %%s in the template with the given username.
 *
 * @param tmpl    Bind DN template containing %%s placeholder.
 * @param user    Username to substitute.
 * @param out     Output buffer for the constructed DN.
 * @param out_sz  Size of the output buffer.
 * @return Number of bytes written (excluding NUL) on success,
 *         -EINVAL if any argument is null, -ENOSPC if buffer too small.
 */
[[nodiscard]] ssize_t iog_ldap_build_bind_dn(const char *tmpl, const char *user,
                                             char *out, size_t out_sz);

/**
 * Build an LDAP group membership search filter.
 *
 * Constructs a filter like "(memberOf=uid=USER,ou=people,dc=example,dc=com)".
 *
 * @param attr    Group attribute name (e.g., "memberOf").
 * @param user_dn Full user DN to match against.
 * @param out     Output buffer for the constructed filter.
 * @param out_sz  Size of the output buffer.
 * @return Number of bytes written (excluding NUL) on success,
 *         -EINVAL if any argument is null, -ENOSPC if buffer too small.
 */
[[nodiscard]] ssize_t iog_ldap_build_group_filter(const char *attr,
                                                  const char *user_dn,
                                                  char *out, size_t out_sz);

#endif /* IOGUARD_AUTH_LDAP_H */
