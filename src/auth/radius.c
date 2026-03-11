#define _GNU_SOURCE
#include "auth/radius.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "auth/auth_backend.h"

#ifdef USE_RADCLI
#    include <radcli/radcli.h>
#endif

/* ---------------------------------------------------------------------------
 * Module state
 * --------------------------------------------------------------------------- */

static rw_radius_config_t g_cfg;

#ifdef USE_RADCLI
static rc_handle *g_rh;
#endif

static bool g_initialized;

/* ---------------------------------------------------------------------------
 * Configuration helpers
 * --------------------------------------------------------------------------- */

int rw_radius_config_defaults(rw_radius_config_t *cfg)
{
    if (cfg == nullptr) {
        return -EINVAL;
    }

    if (cfg->timeout_ms == 0) {
        cfg->timeout_ms = RW_RADIUS_DEFAULT_TIMEOUT_MS;
    }
    if (cfg->retries == 0) {
        cfg->retries = RW_RADIUS_DEFAULT_RETRIES;
    }

    return 0;
}

int rw_radius_config_validate(const rw_radius_config_t *cfg)
{
    if (cfg == nullptr) {
        return -EINVAL;
    }

    if (strnlen(cfg->server, RW_RADIUS_SERVER_MAX) == 0) {
        return -EINVAL;
    }

    if (strnlen(cfg->secret, RW_RADIUS_SECRET_MAX) == 0) {
        return -EINVAL;
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * radcli AVP helpers (internal, used by radius_authenticate)
 * --------------------------------------------------------------------------- */

#ifdef USE_RADCLI

/**
 * Build AVP list for Access-Request: PW_USER_NAME, PW_USER_PASSWORD,
 * and optionally PW_NAS_IDENTIFIER.
 */
static int build_avpairs(rc_handle *rh, const char *username, const char *password,
                         const char *nas_id, VALUE_PAIR **send)
{
    if (rh == nullptr || username == nullptr || password == nullptr || send == nullptr) {
        return -EINVAL;
    }

    *send = nullptr;

    if (rc_avpair_add(rh, send, PW_USER_NAME, username, -1, 0) == nullptr) {
        return -ENOMEM;
    }

    if (rc_avpair_add(rh, send, PW_USER_PASSWORD, password, -1, 0) == nullptr) {
        goto cleanup;
    }

    /* NAS-Identifier is optional */
    if (nas_id != nullptr && nas_id[0] != '\0') {
        if (rc_avpair_add(rh, send, PW_NAS_IDENTIFIER, nas_id, -1, 0) == nullptr) {
            goto cleanup;
        }
    }

    return 0;

cleanup:
    rc_avpair_free(*send);
    *send = nullptr;
    return -ENOMEM;
}

/**
 * Parse Access-Accept response to extract Framed-IP-Address.
 */
static int parse_accept(VALUE_PAIR *received, iog_auth_response_t *resp)
{
    if (resp == nullptr) {
        return -EINVAL;
    }

    if (received == nullptr) {
        return 0;
    }

    VALUE_PAIR *vp = rc_avpair_get(received, PW_FRAMED_IP_ADDRESS, 0);
    if (vp != nullptr) {
        memcpy(&resp->framed_ip, vp->strvalue, sizeof(resp->framed_ip));
    }

    return 0;
}

#endif /* USE_RADCLI */

/* ---------------------------------------------------------------------------
 * Backend interface
 * --------------------------------------------------------------------------- */

int rw_radius_init(const void *config)
{
    if (config == nullptr) {
        return -EINVAL;
    }

    const rw_radius_config_t *cfg = config;

    /* Copy and apply defaults */
    memcpy(&g_cfg, cfg, sizeof(g_cfg));

    int ret = rw_radius_config_defaults(&g_cfg);
    if (ret != 0) {
        return ret;
    }

    ret = rw_radius_config_validate(&g_cfg);
    if (ret != 0) {
        explicit_bzero(&g_cfg, sizeof(g_cfg));
        return ret;
    }

#ifdef USE_RADCLI
    g_rh = rc_new();
    if (g_rh == nullptr) {
        explicit_bzero(&g_cfg, sizeof(g_cfg));
        return -EIO;
    }

    if (rc_config_init(g_rh) == nullptr) {
        goto radcli_err;
    }

    /* Configure server: "host:port:secret" */
    char authserver[512];
    ret = snprintf(authserver, sizeof(authserver), "%s:%s", g_cfg.server, g_cfg.secret);
    if (ret < 0 || (size_t)ret >= sizeof(authserver)) {
        goto radcli_err;
    }

    if (rc_add_config(g_rh, "authserver", authserver, "ioguard", 0) != 0) {
        goto radcli_err;
    }

    /* Timeout in seconds (radcli uses seconds) */
    char timeout_str[16];
    snprintf(timeout_str, sizeof(timeout_str), "%u", g_cfg.timeout_ms / 1000);
    if (rc_add_config(g_rh, "radius_timeout", timeout_str, "ioguard", 0) != 0) {
        goto radcli_err;
    }

    char retries_str[16];
    snprintf(retries_str, sizeof(retries_str), "%u", g_cfg.retries);
    if (rc_add_config(g_rh, "radius_retries", retries_str, "ioguard", 0) != 0) {
        goto radcli_err;
    }

    /* Read dictionary if path provided */
    if (g_cfg.dictionary_path[0] != '\0') {
        if (rc_read_dictionary(g_rh, g_cfg.dictionary_path) != 0) {
            goto radcli_err;
        }
    }

    /* Zero the authserver buffer that contained the shared secret */
    explicit_bzero(authserver, sizeof(authserver));
#endif /* USE_RADCLI */

    g_initialized = true;
    return 0;

#ifdef USE_RADCLI
radcli_err:
    explicit_bzero(authserver, sizeof(authserver));
    rc_destroy(g_rh);
    g_rh = nullptr;
    explicit_bzero(&g_cfg, sizeof(g_cfg));
    return -EIO;
#endif
}

static iog_auth_status_t radius_authenticate(const iog_auth_request_t *req,
                                             iog_auth_response_t *resp)
{
    if (req == nullptr || resp == nullptr) {
        return IOG_AUTH_STATUS_ERROR;
    }

    if (req->username == nullptr || req->password == nullptr) {
        return IOG_AUTH_STATUS_ERROR;
    }

    if (!g_initialized) {
        return IOG_AUTH_STATUS_ERROR;
    }

    memset(resp, 0, sizeof(*resp));

#ifdef USE_RADCLI
    VALUE_PAIR *send = nullptr;
    VALUE_PAIR *received = nullptr;
    char msg[4096];

    int ret = build_avpairs(g_rh, req->username, req->password, g_cfg.nas_identifier, &send);
    if (ret != 0) {
        return IOG_AUTH_STATUS_ERROR;
    }

    int rc_ret = rc_auth(g_rh, 0, send, &received, msg);
    rc_avpair_free(send);

    iog_auth_status_t status;
    switch (rc_ret) {
    case OK_RC:
        status = IOG_AUTH_STATUS_SUCCESS;
        resp->status = IOG_AUTH_STATUS_SUCCESS;
        (void)parse_accept(received, resp);
        break;
    case REJECT_RC:
        status = IOG_AUTH_STATUS_FAILURE;
        resp->status = IOG_AUTH_STATUS_FAILURE;
        break;
    case TIMEOUT_RC:
    case ERROR_RC:
    default:
        status = IOG_AUTH_STATUS_ERROR;
        resp->status = IOG_AUTH_STATUS_ERROR;
        break;
    }

    if (received != nullptr) {
        rc_avpair_free(received);
    }

    return status;
#else
    resp->status = IOG_AUTH_STATUS_ERROR;
    return IOG_AUTH_STATUS_ERROR;
#endif /* USE_RADCLI */
}

void rw_radius_destroy(void)
{
    if (!g_initialized) {
        return;
    }

#ifdef USE_RADCLI
    if (g_rh != nullptr) {
        rc_destroy(g_rh);
        g_rh = nullptr;
    }
#endif

    explicit_bzero(&g_cfg, sizeof(g_cfg));
    g_initialized = false;
}

static const iog_auth_backend_t g_radius_backend = {
    .name = "radius",
    .init = rw_radius_init,
    .authenticate = radius_authenticate,
    .destroy = rw_radius_destroy,
};

const struct iog_auth_backend *iog_radius_backend(void)
{
    return &g_radius_backend;
}
