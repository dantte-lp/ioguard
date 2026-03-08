#include "core/secmod.h"
#include "ipc/messages.h"
#include "ipc/transport.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/**
 * Build and send an auth response over IPC.
 */
static int secmod_send_auth_response(int fd, const rw_ipc_auth_response_t *resp)
{
    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = rw_ipc_pack_auth_response(resp, buf, sizeof(buf));

    if (packed < 0) {
        return (int)packed;
    }
    return rw_ipc_send(fd, buf, (size_t)packed);
}

/**
 * Handle an authentication request (username + password).
 */
static int secmod_handle_auth(rw_secmod_ctx_t *ctx, rw_ipc_auth_request_t *req)
{
    rw_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));

    rw_auth_result_t result = rw_pam_authenticate(&ctx->pam_cfg, req->username, req->password);
    if (result == RW_AUTH_SUCCESS) {
        rw_session_t *session = nullptr;
        int ret = rw_session_create(ctx->sessions, req->username, req->group,
                                    ctx->config->auth.cookie_timeout, &session);
        if (ret == 0 && session != nullptr) {
            resp.success = true;
            resp.session_cookie = session->cookie;
            resp.session_cookie_len = RW_SESSION_COOKIE_SIZE;
            resp.session_ttl = session->ttl_seconds;
            resp.assigned_ip = session->assigned_ip;
            resp.dns_server = (ctx->config->network.dns_count > 0) ? ctx->config->network.dns[0]
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
static int secmod_handle_session_validate(rw_secmod_ctx_t *ctx, rw_ipc_session_validate_t *req)
{
    rw_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));

    rw_session_t *session = nullptr;
    int ret = rw_session_validate(ctx->sessions, req->cookie, req->cookie_len, &session);

    if (ret == 0 && session != nullptr) {
        resp.success = true;
        resp.session_cookie = session->cookie;
        resp.session_cookie_len = RW_SESSION_COOKIE_SIZE;
        resp.session_ttl = session->ttl_seconds;
        resp.assigned_ip = session->assigned_ip;
        resp.dns_server = (ctx->config->network.dns_count > 0) ? ctx->config->network.dns[0]
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

int rw_secmod_init(rw_secmod_ctx_t *ctx, int ipc_fd, const rw_config_t *config)
{
    if (ctx == nullptr || config == nullptr) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->ipc_fd = ipc_fd;
    ctx->config = config;
    ctx->running = false;

    /* Initialise PAM with the configured auth method (service name) */
    const char *service = (config->auth.method[0] != '\0') ? config->auth.method : nullptr;
    int ret = rw_pam_init(&ctx->pam_cfg, service);

    if (ret != 0) {
        return ret;
    }

    /* Create session store sized for max_clients */
    uint32_t max = config->server.max_clients;

    if (max == 0) {
        max = RW_SESSION_MAX_SESSIONS;
    }
    ctx->sessions = rw_session_store_create(max);
    if (ctx->sessions == nullptr) {
        return -ENOMEM;
    }

    return 0;
}

int rw_secmod_handle_message(rw_secmod_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx == nullptr || data == nullptr || len == 0) {
        return -EINVAL;
    }

    /*
     * Try unpacking as auth_request first.  If it has a password field
     * (non-null), treat it as a login attempt.  Otherwise fall through
     * and try session_validate.
     */
    rw_ipc_auth_request_t auth_req;
    memset(&auth_req, 0, sizeof(auth_req));

    int ret = rw_ipc_unpack_auth_request(data, len, &auth_req);

    if (ret == 0 && auth_req.password != nullptr && auth_req.username != nullptr) {
        ret = secmod_handle_auth(ctx, &auth_req);
        rw_ipc_free_auth_request(&auth_req);
        return ret;
    }

    /* Not a password-based auth request — clean up and try session_validate */
    if (ret == 0) {
        rw_ipc_free_auth_request(&auth_req);
    }

    rw_ipc_session_validate_t sv_req;
    memset(&sv_req, 0, sizeof(sv_req));

    ret = rw_ipc_unpack_session_validate(data, len, &sv_req);
    if (ret == 0 && sv_req.cookie != nullptr && sv_req.cookie_len > 0) {
        ret = secmod_handle_session_validate(ctx, &sv_req);
        rw_ipc_free_session_validate(&sv_req);
        return ret;
    }

    if (ret == 0) {
        rw_ipc_free_session_validate(&sv_req);
    }

    return -EPROTO;
}

int rw_secmod_run(rw_secmod_ctx_t *ctx)
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
            uint8_t buf[RW_IPC_MAX_MSG_SIZE];
            ssize_t n = rw_ipc_recv(ctx->ipc_fd, buf, sizeof(buf));

            if (n > 0) {
                (void)rw_secmod_handle_message(ctx, buf, (size_t)n);
            }
        }

        /* Periodic cleanup of expired sessions */
        rw_session_cleanup_expired(ctx->sessions);
    }

    return 0;
}

void rw_secmod_stop(rw_secmod_ctx_t *ctx)
{
    if (ctx != nullptr) {
        ctx->running = false;
    }
}

void rw_secmod_destroy(rw_secmod_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->sessions != nullptr) {
        rw_session_store_destroy(ctx->sessions);
    }

    explicit_bzero(ctx, sizeof(*ctx));
}
