#define _GNU_SOURCE
#include "auth/ldap_auth.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#ifdef USE_LDAP
#include <ldap.h>
#include <lber.h>
#endif

/** Module-level configuration (copied from caller during init). */
static rw_ldap_config_t g_ldap_cfg;
static bool g_ldap_initialized;

/**
 * Validate that a URI starts with ldap:// or ldaps://.
 */
static bool validate_uri_scheme(const char *uri)
{
    if (uri == nullptr) {
        return false;
    }

    return (strncmp(uri, "ldap://", 7) == 0 ||
            strncmp(uri, "ldaps://", 8) == 0);
}

ssize_t rw_ldap_build_bind_dn(const char *tmpl, const char *user,
                               char *out, size_t out_sz)
{
    if (tmpl == nullptr || user == nullptr || out == nullptr || out_sz == 0) {
        return -EINVAL;
    }

    int ret = snprintf(out, out_sz, tmpl, user);
    if (ret < 0) {
        return -EINVAL;
    }
    if ((size_t)ret >= out_sz) {
        return -ENOSPC;
    }

    return ret;
}

ssize_t rw_ldap_build_group_filter(const char *attr, const char *user_dn,
                                    char *out, size_t out_sz)
{
    if (attr == nullptr || user_dn == nullptr || out == nullptr || out_sz == 0) {
        return -EINVAL;
    }

    int ret = snprintf(out, out_sz, "(%s=%s)", attr, user_dn);
    if (ret < 0) {
        return -EINVAL;
    }
    if ((size_t)ret >= out_sz) {
        return -ENOSPC;
    }

    return ret;
}

int rw_ldap_init(const rw_ldap_config_t *config)
{
    if (config == nullptr) {
        return -EINVAL;
    }

    if (config->uri[0] == '\0') {
        return -EINVAL;
    }

    if (!validate_uri_scheme(config->uri)) {
        return -EINVAL;
    }

    memcpy(&g_ldap_cfg, config, sizeof(g_ldap_cfg));

    /* Apply defaults for optional fields */
    if (g_ldap_cfg.group_attr[0] == '\0') {
        snprintf(g_ldap_cfg.group_attr, sizeof(g_ldap_cfg.group_attr),
                 "memberOf");
    }

    if (g_ldap_cfg.timeout_ms == 0) {
        g_ldap_cfg.timeout_ms = RW_LDAP_DEFAULT_TIMEOUT_MS;
    }

    g_ldap_initialized = true;
    return 0;
}

void rw_ldap_destroy(void)
{
    if (g_ldap_initialized) {
        explicit_bzero(&g_ldap_cfg, sizeof(g_ldap_cfg));
        g_ldap_initialized = false;
    }
}

#ifdef USE_LDAP

/**
 * Authenticate a user via LDAP simple bind and optional group search.
 *
 * Flow: ldap_initialize → set LDAPv3 → optional StartTLS → bind → search
 *       groups → unbind.
 */
static rw_auth_status_t ldap_authenticate(const rw_auth_request_t *req,
                                           rw_auth_response_t *resp)
{
    if (req == nullptr || resp == nullptr) {
        return RW_AUTH_STATUS_ERROR;
    }

    if (req->username == nullptr || req->password == nullptr) {
        return RW_AUTH_STATUS_ERROR;
    }

    if (!g_ldap_initialized) {
        return RW_AUTH_STATUS_ERROR;
    }

    memset(resp, 0, sizeof(*resp));

    /* Build the bind DN from template + username */
    char bind_dn[RW_LDAP_DN_BUF_MAX];
    ssize_t dn_len = rw_ldap_build_bind_dn(g_ldap_cfg.bind_dn_template,
                                             req->username,
                                             bind_dn, sizeof(bind_dn));
    if (dn_len < 0) {
        return RW_AUTH_STATUS_ERROR;
    }

    LDAP *ld = nullptr;
    int rc = ldap_initialize(&ld, g_ldap_cfg.uri);
    if (rc != LDAP_SUCCESS) {
        return RW_AUTH_STATUS_ERROR;
    }

    /* Force LDAPv3 */
    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    /* Set network timeout */
    struct timeval tv = {
        .tv_sec = g_ldap_cfg.timeout_ms / 1000,
        .tv_usec = (g_ldap_cfg.timeout_ms % 1000) * 1000,
    };
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);

    /* Set CA certificate for TLS verification */
    if (g_ldap_cfg.ca_cert_path[0] != '\0') {
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE,
                        g_ldap_cfg.ca_cert_path);
    }

    /* StartTLS if requested (for ldap:// URIs; ldaps:// uses implicit TLS) */
    if (g_ldap_cfg.use_starttls) {
        rc = ldap_start_tls_s(ld, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) {
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            return RW_AUTH_STATUS_ERROR;
        }
    }

    /* Simple bind with user credentials */
    struct berval cred = {
        .bv_val = (char *)req->password,
        .bv_len = strlen(req->password),
    };

    rc = ldap_sasl_bind_s(ld, bind_dn, LDAP_SASL_SIMPLE, &cred,
                          nullptr, nullptr, nullptr);

    /* Zero the credential struct (password pointer still owned by caller) */
    explicit_bzero(&cred, sizeof(cred));

    if (rc == LDAP_INVALID_CREDENTIALS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        resp->status = RW_AUTH_STATUS_FAILURE;
        return RW_AUTH_STATUS_FAILURE;
    }

    if (rc != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        resp->status = RW_AUTH_STATUS_ERROR;
        return RW_AUTH_STATUS_ERROR;
    }

    /* Optionally search for group memberships */
    if (g_ldap_cfg.search_base[0] != '\0') {
        char filter[RW_LDAP_FILTER_BUF_MAX];
        ssize_t flen = rw_ldap_build_group_filter(g_ldap_cfg.group_attr,
                                                   bind_dn,
                                                   filter, sizeof(filter));
        if (flen > 0) {
            char *attrs[] = {"cn", nullptr};
            LDAPMessage *result = nullptr;

            rc = ldap_search_ext_s(ld, g_ldap_cfg.search_base,
                                   LDAP_SCOPE_SUBTREE, filter,
                                   attrs, 0, nullptr, nullptr,
                                   &tv, 100, &result);

            if (rc == LDAP_SUCCESS && result != nullptr) {
                /* Collect group CNs into comma-separated list */
                size_t offset = 0;
                LDAPMessage *entry = ldap_first_entry(ld, result);

                while (entry != nullptr) {
                    struct berval **vals =
                        ldap_get_values_len(ld, entry, "cn");

                    if (vals != nullptr && vals[0] != nullptr) {
                        if (offset > 0 &&
                            offset < sizeof(resp->groups) - 1) {
                            resp->groups[offset++] = ',';
                        }
                        size_t remain = sizeof(resp->groups) - offset;
                        size_t copy_len = vals[0]->bv_len;
                        if (copy_len >= remain) {
                            copy_len = remain - 1;
                        }
                        memcpy(resp->groups + offset,
                               vals[0]->bv_val, copy_len);
                        offset += copy_len;
                    }

                    if (vals != nullptr) {
                        ldap_value_free_len(vals);
                    }
                    entry = ldap_next_entry(ld, entry);
                }

                resp->groups[offset] = '\0';
                ldap_msgfree(result);
            } else if (result != nullptr) {
                ldap_msgfree(result);
            }
        }
    }

    ldap_unbind_ext_s(ld, nullptr, nullptr);

    resp->status = RW_AUTH_STATUS_SUCCESS;
    return RW_AUTH_STATUS_SUCCESS;
}

#else /* !USE_LDAP */

/**
 * Stub when LDAP support is not compiled in.
 */
static rw_auth_status_t ldap_authenticate(const rw_auth_request_t *req,
                                           rw_auth_response_t *resp)
{
    (void)req;
    if (resp != nullptr) {
        resp->status = RW_AUTH_STATUS_ERROR;
    }
    return RW_AUTH_STATUS_ERROR;
}

#endif /* USE_LDAP */

/**
 * Backend init callback — delegates to rw_ldap_init().
 */
static int ldap_backend_init(const void *config)
{
    return rw_ldap_init((const rw_ldap_config_t *)config);
}

static const rw_auth_backend_t ldap_backend_desc = {
    .name = "ldap",
    .init = ldap_backend_init,
    .authenticate = ldap_authenticate,
    .destroy = rw_ldap_destroy,
};

const rw_auth_backend_t *rw_ldap_backend(void)
{
    return &ldap_backend_desc;
}
