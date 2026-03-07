#include "core/secmod.h"
#include "ipc/messages.h"
#include "ipc/transport.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/**
 * Build and send an auth response over IPC.
 */
static int secmod_send_auth_response(int fd,
                                      const wg_ipc_auth_response_t *resp)
{
    uint8_t buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_auth_response(resp, buf, sizeof(buf));

    if (packed < 0) {
        return (int)packed;
    }
    return wg_ipc_send(fd, buf, (size_t)packed);
}

/**
 * Handle an authentication request (username + password).
 */
static int secmod_handle_auth(wg_secmod_ctx_t *ctx,
                               wg_ipc_auth_request_t *req)
{
    wg_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));

    wg_auth_result_t result = wg_pam_authenticate(&ctx->pam_cfg,
                                                    req->username,
                                                    req->password);
    if (result == WG_AUTH_SUCCESS) {
        wg_session_t *session = nullptr;
        int ret = wg_session_create(ctx->sessions, req->username,
                                     req->group,
                                     ctx->config->auth.cookie_timeout,
                                     &session);
        if (ret == 0 && session != nullptr) {
            resp.success = true;
            resp.session_cookie = session->cookie;
            resp.session_cookie_len = WG_SESSION_COOKIE_SIZE;
            resp.session_ttl = session->ttl_seconds;
            resp.assigned_ip = session->assigned_ip;
            resp.dns_server = (ctx->config->network.dns_count > 0)
                                  ? ctx->config->network.dns[0]
                                  : nullptr;
            resp.default_domain = ctx->config->network.default_domain;
        } else {
            resp.success = false;
            resp.error_msg = "session creation failed";
        }
    } else {
        resp.success = false;
        resp.error_msg = "authentication failed";
    }

    return secmod_send_auth_response(ctx->ipc_fd, &resp);
}

/**
 * Handle a session validation request (cookie lookup).
 */
static int secmod_handle_session_validate(wg_secmod_ctx_t *ctx,
                                           wg_ipc_session_validate_t *req)
{
    wg_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));

    wg_session_t *session = nullptr;
    int ret = wg_session_validate(ctx->sessions, req->cookie,
                                   req->cookie_len, &session);

    if (ret == 0 && session != nullptr) {
        resp.success = true;
        resp.session_cookie = session->cookie;
        resp.session_cookie_len = WG_SESSION_COOKIE_SIZE;
        resp.session_ttl = session->ttl_seconds;
        resp.assigned_ip = session->assigned_ip;
        resp.dns_server = (ctx->config->network.dns_count > 0)
                              ? ctx->config->network.dns[0]
                              : nullptr;
        resp.default_domain = ctx->config->network.default_domain;
    } else {
        resp.success = false;
        resp.error_msg = "session not found or expired";
    }

    return secmod_send_auth_response(ctx->ipc_fd, &resp);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int wg_secmod_init(wg_secmod_ctx_t *ctx, int ipc_fd,
                    const wg_config_t *config)
{
    if (ctx == nullptr || config == nullptr) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->ipc_fd = ipc_fd;
    ctx->config = config;
    ctx->running = false;

    /* Initialise PAM with the configured auth method (service name) */
    const char *service = (config->auth.method[0] != '\0')
                              ? config->auth.method
                              : nullptr;
    int ret = wg_pam_init(&ctx->pam_cfg, service);

    if (ret != 0) {
        return ret;
    }

    /* Create session store sized for max_clients */
    uint32_t max = config->server.max_clients;

    if (max == 0) {
        max = WG_SESSION_MAX_SESSIONS;
    }
    ctx->sessions = wg_session_store_create(max);
    if (ctx->sessions == nullptr) {
        return -ENOMEM;
    }

    return 0;
}

int wg_secmod_handle_message(wg_secmod_ctx_t *ctx,
                              const uint8_t *data, size_t len)
{
    if (ctx == nullptr || data == nullptr || len == 0) {
        return -EINVAL;
    }

    /*
     * Try unpacking as auth_request first.  If it has a password field
     * (non-null), treat it as a login attempt.  Otherwise fall through
     * and try session_validate.
     */
    wg_ipc_auth_request_t auth_req;
    memset(&auth_req, 0, sizeof(auth_req));

    int ret = wg_ipc_unpack_auth_request(data, len, &auth_req);

    if (ret == 0 && auth_req.password != nullptr
        && auth_req.username != nullptr) {
        ret = secmod_handle_auth(ctx, &auth_req);
        wg_ipc_free_auth_request(&auth_req);
        return ret;
    }

    /* Not a password-based auth request — clean up and try session_validate */
    if (ret == 0) {
        wg_ipc_free_auth_request(&auth_req);
    }

    wg_ipc_session_validate_t sv_req;
    memset(&sv_req, 0, sizeof(sv_req));

    ret = wg_ipc_unpack_session_validate(data, len, &sv_req);
    if (ret == 0 && sv_req.cookie != nullptr && sv_req.cookie_len > 0) {
        ret = secmod_handle_session_validate(ctx, &sv_req);
        wg_ipc_free_session_validate(&sv_req);
        return ret;
    }

    if (ret == 0) {
        wg_ipc_free_session_validate(&sv_req);
    }

    return -EPROTO;
}

int wg_secmod_run(wg_secmod_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return -EINVAL;
    }

    ctx->running = true;

    while (ctx->running) {
        struct pollfd pfd = {.fd = ctx->ipc_fd, .events = POLLIN};
        int ret = poll(&pfd, 1, 1000);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }

        if (ret > 0 && (pfd.revents & POLLIN)) {
            uint8_t buf[WG_IPC_MAX_MSG_SIZE];
            ssize_t n = wg_ipc_recv(ctx->ipc_fd, buf, sizeof(buf));

            if (n > 0) {
                (void)wg_secmod_handle_message(ctx, buf, (size_t)n);
            }
        }

        /* Periodic cleanup of expired sessions */
        wg_session_cleanup_expired(ctx->sessions);
    }

    return 0;
}

void wg_secmod_stop(wg_secmod_ctx_t *ctx)
{
    if (ctx != nullptr) {
        ctx->running = false;
    }
}

void wg_secmod_destroy(wg_secmod_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->sessions != nullptr) {
        wg_session_store_destroy(ctx->sessions);
    }

    explicit_bzero(ctx, sizeof(*ctx));
}
