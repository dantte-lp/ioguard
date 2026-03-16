#define _GNU_SOURCE
#include "auth/cert_auth.h"

#include <errno.h>
#include <string.h>

#ifdef USE_WOLFSSL
/* clang-format off */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
/* clang-format on */
#endif

/** Default username field when none is configured. */
static constexpr char DEFAULT_USERNAME_FIELD[] = "CN";

/** Module state: configuration copy and initialization flag. */
static iog_cert_auth_config_t g_cert_cfg;
static bool g_cert_initialized = false;

/**
 * Validate that the config has required fields set.
 */
static int validate_config(const iog_cert_auth_config_t *config)
{
    if (config == nullptr) {
        return -EINVAL;
    }

    /* CA cert path is required */
    if (strnlen(config->ca_cert_path, IOG_CERT_PATH_MAX) == 0) {
        return -EINVAL;
    }

    return 0;
}

/**
 * Apply default values to any unset optional fields.
 */
static void apply_defaults(iog_cert_auth_config_t *cfg)
{
    if (strnlen(cfg->username_field, IOG_CERT_USERNAME_FIELD_MAX) == 0) {
        memcpy(cfg->username_field, DEFAULT_USERNAME_FIELD, sizeof(DEFAULT_USERNAME_FIELD));
    }
}

/**
 * Authenticate using the client certificate from the request.
 */
static iog_auth_status_t cert_authenticate(const iog_auth_request_t *req, iog_auth_response_t *resp)
{
    if (req == nullptr || resp == nullptr) {
        return IOG_AUTH_STATUS_ERROR;
    }

    if (!g_cert_initialized) {
        return IOG_AUTH_STATUS_ERROR;
    }

    /* Client cert is required for this backend */
    if (req->client_cert == nullptr || req->client_cert_len == 0) {
        resp->status = IOG_AUTH_STATUS_FAILURE;
        return IOG_AUTH_STATUS_FAILURE;
    }

    /* Extract username from the certificate */
    char username[IOG_CERT_USERNAME_MAX];
    int ret = iog_cert_extract_username(req->client_cert, req->client_cert_len,
                                        g_cert_cfg.username_field, username, sizeof(username));
    if (ret != 0) {
        resp->status = IOG_AUTH_STATUS_FAILURE;
        return IOG_AUTH_STATUS_FAILURE;
    }

    /* Authentication succeeded — username was extracted and cert was parsed */
    resp->status = IOG_AUTH_STATUS_SUCCESS;
    resp->groups[0] = '\0';
    resp->framed_ip = 0;
    resp->has_framed_ipv6 = false;

    return IOG_AUTH_STATUS_SUCCESS;
}

/**
 * Init callback for the auth_backend_t interface.
 */
static int cert_backend_init(const void *config)
{
    return iog_cert_auth_init((const iog_cert_auth_config_t *)config);
}

/**
 * Static backend descriptor for registration with the auth framework.
 */
static const iog_auth_backend_t cert_backend = {
    .name = "cert",
    .init = cert_backend_init,
    .authenticate = cert_authenticate,
    .destroy = iog_cert_auth_destroy,
};

int iog_cert_auth_init(const iog_cert_auth_config_t *config)
{
    int ret = validate_config(config);
    if (ret != 0) {
        return ret;
    }

    if (g_cert_initialized) {
        return -EALREADY;
    }

    memcpy(&g_cert_cfg, config, sizeof(g_cert_cfg));
    apply_defaults(&g_cert_cfg);
    g_cert_initialized = true;

    return 0;
}

void iog_cert_auth_destroy(void)
{
    if (g_cert_initialized) {
        explicit_bzero(&g_cert_cfg, sizeof(g_cert_cfg));
        g_cert_initialized = false;
    }
}

const iog_auth_backend_t *iog_cert_auth_backend(void)
{
    return &cert_backend;
}

int iog_cert_extract_username(const uint8_t *der, size_t der_len, const char *field, char *out,
                              size_t out_size)
{
    if (der == nullptr || field == nullptr || out == nullptr || out_size == 0) {
        return -EINVAL;
    }

    if (der_len == 0) {
        return -ENOENT;
    }

#ifdef USE_WOLFSSL
    const unsigned char *p = der;
    WOLFSSL_X509 *x509 = wolfSSL_d2i_X509(nullptr, &p, (int)der_len);
    if (x509 == nullptr) {
        return -EINVAL;
    }

    int ret = -ENOENT;

    if (strcmp(field, "CN") == 0) {
        WOLFSSL_X509_NAME *subj = wolfSSL_X509_get_subject_name(x509);
        if (subj != nullptr) {
            int len = wolfSSL_X509_NAME_get_text_by_NID(subj, NID_commonName, out, (int)out_size);
            if (len > 0) {
                ret = 0;
            } else if (len == 0) {
                ret = -ENOENT;
            } else {
                ret = -ENOSPC;
            }
        }
    } else if (strcmp(field, "SAN:email") == 0 || strcmp(field, "SAN:UPN") == 0) {
        /* SAN extraction — retrieve email from the certificate */
        char *email = wolfSSL_X509_get_next_altname(x509);
        if (email != nullptr) {
            size_t elen = strnlen(email, out_size);
            if (elen >= out_size) {
                ret = -ENOSPC;
            } else {
                memcpy(out, email, elen + 1);
                ret = 0;
            }
        }
    } else {
        ret = -EINVAL;
    }

    wolfSSL_X509_free(x509);
    return ret;
#else
    (void)der_len;
    return -ENOTSUP;
#endif
}
