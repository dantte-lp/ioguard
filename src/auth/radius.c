#define _GNU_SOURCE
#include "auth/radius.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "auth/auth_backend.h"

#ifdef USE_RADCLI
#    include <radcli/radcli.h>
#endif

/* ---------------------------------------------------------------------------
 * Module state
 * --------------------------------------------------------------------------- */

static iog_radius_config_t g_cfg;

#ifdef USE_RADCLI
static rc_handle *g_rh;
#endif

static bool g_initialized;

/* ---------------------------------------------------------------------------
 * Configuration helpers
 * --------------------------------------------------------------------------- */

int iog_radius_config_defaults(iog_radius_config_t *cfg)
{
    if (cfg == nullptr) {
        return -EINVAL;
    }

    if (cfg->timeout_ms == 0) {
        cfg->timeout_ms = IOG_RADIUS_DEFAULT_TIMEOUT_MS;
    }
    if (cfg->retries == 0) {
        cfg->retries = IOG_RADIUS_DEFAULT_RETRIES;
    }

    return 0;
}

int iog_radius_config_validate(const iog_radius_config_t *cfg)
{
    if (cfg == nullptr) {
        return -EINVAL;
    }

    if (strnlen(cfg->server, IOG_RADIUS_SERVER_MAX) == 0) {
        return -EINVAL;
    }

    if (strnlen(cfg->secret, IOG_RADIUS_SECRET_MAX) == 0) {
        return -EINVAL;
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * Cisco VSA group extraction (public helper)
 * --------------------------------------------------------------------------- */

/**
 * Cisco VSA wire format (RFC 2865 section 5.26):
 *   [4 bytes vendor-id] [1 byte type] [1 byte length] [value...]
 *   Minimum: 4 (vendor) + 1 (type) + 1 (length) + 1 (value) = 7 bytes
 */
constexpr size_t CISCO_VSA_HEADER_LEN = 6;

ssize_t iog_radius_extract_cisco_group(const uint8_t *vsa_data, size_t vsa_len, char *out,
                                       size_t out_sz)
{
    if (vsa_data == nullptr || out == nullptr || out_sz == 0) {
        return -EINVAL;
    }

    /* Need at least vendor-id(4) + type(1) + length(1) + 1 byte value */
    if (vsa_len < CISCO_VSA_HEADER_LEN + 1) {
        return -EINVAL;
    }

    /* Extract vendor ID (network byte order, big-endian) */
    uint32_t vendor_id = ((uint32_t)vsa_data[0] << 24) | ((uint32_t)vsa_data[1] << 16) |
                         ((uint32_t)vsa_data[2] << 8) | (uint32_t)vsa_data[3];

    if (vendor_id != IOG_RADIUS_VENDOR_CISCO) {
        return -EINVAL;
    }

    uint8_t attr_type = vsa_data[4];
    if (attr_type != IOG_RADIUS_CISCO_AVPAIR_TYPE) {
        return -EINVAL;
    }

    uint8_t attr_len = vsa_data[5];
    /* attr_len includes type(1) + length(1) + value bytes */
    if (attr_len < 3 || (size_t)attr_len > vsa_len - 4) {
        return -EINVAL;
    }

    size_t value_len = (size_t)attr_len - 2;
    const char *value = (const char *)&vsa_data[CISCO_VSA_HEADER_LEN];

    /* Check for "group=" prefix (case-sensitive, Cisco convention) */
    const char prefix[] = "group=";
    constexpr size_t prefix_len = sizeof(prefix) - 1;

    const char *group_str = value;
    size_t group_len = value_len;

    if (value_len > prefix_len && memcmp(value, prefix, prefix_len) == 0) {
        group_str = value + prefix_len;
        group_len = value_len - prefix_len;
    }

    /* Strip trailing NUL if present in the RADIUS value */
    if (group_len > 0 && group_str[group_len - 1] == '\0') {
        group_len--;
    }

    if (group_len == 0) {
        return -EINVAL;
    }

    /* Need room for group name + NUL terminator */
    if (group_len + 1 > out_sz) {
        return -ENOSPC;
    }

    memcpy(out, group_str, group_len);
    out[group_len] = '\0';

    return (ssize_t)group_len;
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
 * Parse Access-Accept response to extract Framed-IP-Address and Cisco VSA
 * group attributes.
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

    /* Extract Cisco VSA group attributes (vendor 9, cisco-avpair) */
    resp->groups[0] = '\0';
    size_t groups_off = 0;

    VALUE_PAIR *vsa = rc_avpair_get(received, PW_VENDOR_SPECIFIC, 0);
    while (vsa != nullptr) {
        char group_buf[128];
        ssize_t glen = iog_radius_extract_cisco_group((const uint8_t *)vsa->strvalue, vsa->lvalue,
                                                      group_buf, sizeof(group_buf));

        if (glen > 0) {
            size_t needed = (groups_off > 0) ? (size_t)glen + 1 : (size_t)glen;
            if (groups_off + needed < sizeof(resp->groups)) {
                if (groups_off > 0) {
                    resp->groups[groups_off++] = ',';
                }
                memcpy(&resp->groups[groups_off], group_buf, (size_t)glen);
                groups_off += (size_t)glen;
                resp->groups[groups_off] = '\0';
            }
        }

        vsa = rc_avpair_get(vsa->next, PW_VENDOR_SPECIFIC, 0);
    }

    return 0;
}

#endif /* USE_RADCLI */

/* ---------------------------------------------------------------------------
 * Backend interface
 * --------------------------------------------------------------------------- */

int iog_radius_init(const void *config)
{
    if (config == nullptr) {
        return -EINVAL;
    }

    const iog_radius_config_t *cfg = config;

    /* Copy and apply defaults */
    memcpy(&g_cfg, cfg, sizeof(g_cfg));

    int ret = iog_radius_config_defaults(&g_cfg);
    if (ret != 0) {
        return ret;
    }

    ret = iog_radius_config_validate(&g_cfg);
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

void iog_radius_destroy(void)
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
    .init = iog_radius_init,
    .authenticate = radius_authenticate,
    .destroy = iog_radius_destroy,
};

const struct iog_auth_backend *iog_radius_backend(void)
{
    return &g_radius_backend;
}
