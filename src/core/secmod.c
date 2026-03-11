#include "core/secmod.h"
#include "auth/totp.h"
#include "ipc/messages.h"
#include "ipc/transport.h"
#include "storage/vault.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

/* Write an audit entry to SQLite (best-effort, non-fatal) */
static void secmod_audit_log(rw_secmod_ctx_t *ctx, const char *event_type, const char *username,
                             const char *source_ip, const char *result)
{
    if (ctx->sqlite == nullptr) {
        return;
    }

    rw_audit_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    snprintf(entry.event_type, sizeof(entry.event_type), "%s", event_type);
    if (username != nullptr) {
        snprintf(entry.username, sizeof(entry.username), "%s", username);
    }
    if (source_ip != nullptr) {
        snprintf(entry.source_ip, sizeof(entry.source_ip), "%s", source_ip);
    }
    snprintf(entry.result, sizeof(entry.result), "%s", result);

    (void)iog_sqlite_audit_insert(ctx->sqlite, &entry);
}

/* Persist session to mdbx (if available) */
static int secmod_persist_session(rw_secmod_ctx_t *ctx, const iog_session_t *session)
{
    if (ctx->mdbx == nullptr) {
        return 0;
    }

    iog_session_record_t record;
    memset(&record, 0, sizeof(record));
    memcpy(record.session_id, session->cookie, IOG_SESSION_ID_LEN);
    snprintf(record.username, sizeof(record.username), "%s", session->username);
    snprintf(record.groupname, sizeof(record.groupname), "%s", session->group);
    record.created_at = session->created;
    record.expires_at = session->created + (time_t)session->ttl_seconds;

    return iog_mdbx_session_create(ctx->mdbx, &record);
}

/* Delete session from mdbx (if available) — used during disconnect handling */
[[maybe_unused]] static int secmod_delete_session(rw_secmod_ctx_t *ctx, const uint8_t *cookie)
{
    if (ctx->mdbx == nullptr) {
        return 0;
    }
    return iog_mdbx_session_delete(ctx->mdbx, cookie);
}

/* Build and send an auth response over IPC. */
static int secmod_send_auth_response(int fd, const iog_ipc_auth_response_t *resp)
{
    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_response(resp, buf, sizeof(buf));

    if (packed < 0) {
        return (int)packed;
    }
    return iog_ipc_send(fd, buf, (size_t)packed);
}

/* Create a session and populate the response fields. */
static int secmod_create_session_response(rw_secmod_ctx_t *ctx, iog_ipc_auth_request_t *req,
                                          iog_ipc_auth_response_t *resp)
{
    iog_session_t *session = nullptr;
    int ret = iog_session_create(ctx->sessions, req->username, req->group,
                                ctx->config->auth.cookie_timeout, &session);
    if (ret == 0 && session != nullptr) {
        resp->success = true;
        resp->session_cookie = session->cookie;
        resp->session_cookie_len = IOG_SESSION_COOKIE_SIZE;
        resp->session_ttl = session->ttl_seconds;
        resp->assigned_ip = session->assigned_ip;
        resp->dns_server = (ctx->config->network.dns_count > 0) ? ctx->config->network.dns[0]
                                                                : nullptr;
        resp->default_domain = ctx->config->network.default_domain;

        /* Persist to mdbx */
        (void)secmod_persist_session(ctx, session);

        /* Audit success */
        secmod_audit_log(ctx, "AUTH", req->username, req->source_ip, "OK");
        return 0;
    }

    resp->success = false;
    resp->error_msg = "session creation failed";
    return -1;
}

/* Handle TOTP second-factor validation. Returns 0 on success, <0 on failure. */
static int secmod_handle_totp(rw_secmod_ctx_t *ctx, iog_ipc_auth_request_t *req,
                              iog_ipc_auth_response_t *resp)
{
    iog_user_record_t user;
    memset(&user, 0, sizeof(user));

    if (req->otp == nullptr || req->otp[0] == '\0') {
        resp->success = false;
        resp->error_msg = "missing OTP";
        return -EINVAL;
    }

    int ret = iog_sqlite_user_lookup(ctx->sqlite, req->username, &user);
    if (ret < 0) {
        resp->success = false;
        resp->error_msg = "user lookup failed";
        explicit_bzero(&user, sizeof(user));
        return ret;
    }

    if (!user.totp_enabled || user.totp_secret_len == 0) {
        resp->success = false;
        resp->error_msg = "TOTP not configured for user";
        explicit_bzero(&user, sizeof(user));
        return -EINVAL;
    }

    /* Decrypt the TOTP secret via vault */
    uint8_t decrypted[RW_TOTP_SECRET_SIZE + 16];
    size_t dec_len = 0;

    ret = rw_vault_decrypt(ctx->vault, user.totp_secret, user.totp_secret_len, decrypted,
                           sizeof(decrypted), &dec_len);
    explicit_bzero(&user, sizeof(user));

    if (ret < 0) {
        explicit_bzero(decrypted, sizeof(decrypted));
        resp->success = false;
        resp->error_msg = "TOTP secret decryption failed";
        return ret;
    }

    /* Parse OTP string to uint32_t (6-8 digits max) */
    char *end = nullptr;
    errno = 0;
    unsigned long otp_val = strtoul(req->otp, &end, 10);
    if (end == req->otp || *end != '\0' || otp_val > UINT32_MAX || errno == ERANGE) {
        explicit_bzero(decrypted, sizeof(decrypted));
        resp->success = false;
        resp->error_msg = "invalid OTP format";
        secmod_audit_log(ctx, "TOTP", req->username, req->source_ip, "TOTP_FAIL");
        return -EINVAL;
    }

    uint32_t otp_code = (uint32_t)otp_val;
    ret = rw_totp_validate(decrypted, dec_len, otp_code, (uint64_t)time(nullptr), 1);
    explicit_bzero(decrypted, sizeof(decrypted));

    if (ret < 0) {
        resp->success = false;
        resp->error_msg = "TOTP validation failed";
        secmod_audit_log(ctx, "TOTP", req->username, req->source_ip, "TOTP_FAIL");
        return ret;
    }

    /* TOTP valid — create session */
    secmod_audit_log(ctx, "TOTP", req->username, req->source_ip, "OK");
    return secmod_create_session_response(ctx, req, resp);
}

/* Handle an authentication request (username + password, or OTP second factor). */
static int secmod_handle_auth(rw_secmod_ctx_t *ctx, iog_ipc_auth_request_t *req)
{
    iog_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));

    /* Check ban list before attempting auth */
    if (ctx->sqlite != nullptr && req->source_ip != nullptr) {
        bool banned = false;
        int bret = iog_sqlite_ban_check(ctx->sqlite, req->source_ip, &banned);
        if (bret == 0 && banned) {
            resp.success = false;
            resp.error_msg = "IP address is banned";
            secmod_audit_log(ctx, "AUTH", req->username, req->source_ip, "BANNED");
            return secmod_send_auth_response(ctx->ipc_fd, &resp);
        }
    }

    /* TOTP second-factor: OTP provided without password (second round-trip) */
    if (req->otp != nullptr && req->otp[0] != '\0' && req->username != nullptr &&
        req->username[0] != '\0' && (req->password == nullptr || req->password[0] == '\0') &&
        ctx->sqlite != nullptr && ctx->vault != nullptr) {
        (void)secmod_handle_totp(ctx, req, &resp);
        return secmod_send_auth_response(ctx->ipc_fd, &resp);
    }

    /* Primary authentication via PAM */
    rw_auth_result_t result = rw_pam_authenticate(&ctx->pam_cfg, req->username, req->password);
    if (result == RW_AUTH_SUCCESS) {
        /* Check if user has TOTP enabled */
        if (ctx->sqlite != nullptr && ctx->vault != nullptr) {
            iog_user_record_t user;
            memset(&user, 0, sizeof(user));
            int lret = iog_sqlite_user_lookup(ctx->sqlite, req->username, &user);
            if (lret == 0 && user.totp_enabled && user.totp_secret_len > 0) {
                /* TOTP required — signal challenge, do not create session yet */
                explicit_bzero(&user, sizeof(user));
                resp.success = false;
                resp.requires_totp = true;
                resp.error_msg = "TOTP required";
                secmod_audit_log(ctx, "AUTH", req->username, req->source_ip, "TOTP_REQUIRED");
                return secmod_send_auth_response(ctx->ipc_fd, &resp);
            }
            explicit_bzero(&user, sizeof(user));
        }

        /* No TOTP — create session directly */
        (void)secmod_create_session_response(ctx, req, &resp);
    } else {
        resp.success = false;
        resp.error_msg = "authentication failed";

        /* Audit failure */
        secmod_audit_log(ctx, "AUTH", req->username, req->source_ip, "FAIL");
    }

    return secmod_send_auth_response(ctx->ipc_fd, &resp);
}

/* Handle a session validation request (cookie lookup). */
static int secmod_handle_session_validate(rw_secmod_ctx_t *ctx, iog_ipc_session_validate_t *req)
{
    iog_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));

    iog_session_t *session = nullptr;
    int ret = iog_session_validate(ctx->sessions, req->cookie, req->cookie_len, &session);

    if (ret == 0 && session != nullptr) {
        resp.success = true;
        resp.session_cookie = session->cookie;
        resp.session_cookie_len = IOG_SESSION_COOKIE_SIZE;
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

/* Two-pass expired session cleanup: collect IDs during read txn, delete after */
constexpr size_t SECMOD_CLEANUP_BATCH = 64;

typedef struct {
    uint8_t ids[SECMOD_CLEANUP_BATCH][IOG_SESSION_ID_LEN];
    size_t count;
} secmod_expired_batch_t;

static int expired_session_collect(const iog_session_record_t *session, void *userdata)
{
    secmod_expired_batch_t *batch = userdata;
    time_t now = time(nullptr);

    if (session->expires_at > 0 && session->expires_at < now) {
        if (batch->count < SECMOD_CLEANUP_BATCH) {
            memcpy(batch->ids[batch->count], session->session_id, IOG_SESSION_ID_LEN);
            batch->count++;
        }
    }
    return 0;
}

static void secmod_cleanup_expired_mdbx(rw_secmod_ctx_t *ctx)
{
    if (ctx->mdbx == nullptr) {
        return;
    }

    secmod_expired_batch_t batch;
    memset(&batch, 0, sizeof(batch));

    /* Pass 1: collect expired IDs (read-only txn inside iterate) */
    (void)iog_mdbx_session_iterate(ctx->mdbx, expired_session_collect, &batch);

    /* Pass 2: delete collected sessions (separate write txns) */
    for (size_t i = 0; i < batch.count; i++) {
        (void)iog_mdbx_session_delete(ctx->mdbx, batch.ids[i]);
    }
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int rw_secmod_init(rw_secmod_ctx_t *ctx, int ipc_fd, const iog_config_t *config)
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

    /* Create in-memory session store */
    uint32_t max = config->server.max_clients;
    if (max == 0) {
        max = IOG_SESSION_MAX_SESSIONS;
    }
    ctx->sessions = iog_session_store_create(max);
    if (ctx->sessions == nullptr) {
        return -ENOMEM;
    }

    /* Initialize persistent session store (mdbx) if configured */
    if (config->storage.mdbx_path[0] != '\0') {
        ctx->mdbx = calloc(1, sizeof(*ctx->mdbx));
        if (ctx->mdbx == nullptr) {
            iog_session_store_destroy(ctx->sessions);
            return -ENOMEM;
        }
        ret = rw_mdbx_init(ctx->mdbx, config->storage.mdbx_path);
        if (ret < 0) {
            free(ctx->mdbx);
            ctx->mdbx = nullptr;
            iog_session_store_destroy(ctx->sessions);
            return ret;
        }
    }

    /* Initialize SQLite control plane if configured */
    if (config->storage.sqlite_path[0] != '\0') {
        ctx->sqlite = calloc(1, sizeof(*ctx->sqlite));
        if (ctx->sqlite == nullptr) {
            if (ctx->mdbx != nullptr) {
                rw_mdbx_close(ctx->mdbx);
                free(ctx->mdbx);
            }
            iog_session_store_destroy(ctx->sessions);
            return -ENOMEM;
        }
        ret = iog_sqlite_init(ctx->sqlite, config->storage.sqlite_path);
        if (ret < 0) {
            free(ctx->sqlite);
            ctx->sqlite = nullptr;
            if (ctx->mdbx != nullptr) {
                rw_mdbx_close(ctx->mdbx);
                free(ctx->mdbx);
            }
            iog_session_store_destroy(ctx->sessions);
            return ret;
        }
    }

    /* Initialize vault for field-level encryption (TOTP secrets) */
    if (config->storage.vault_key_path[0] != '\0') {
        ret = rw_vault_init(config->storage.vault_key_path, &ctx->vault);
        if (ret < 0) {
            if (ctx->sqlite != nullptr) {
                iog_sqlite_close(ctx->sqlite);
                free(ctx->sqlite);
            }
            if (ctx->mdbx != nullptr) {
                rw_mdbx_close(ctx->mdbx);
                free(ctx->mdbx);
            }
            iog_session_store_destroy(ctx->sessions);
            return ret;
        }
    }

    return 0;
}

int rw_secmod_handle_message(rw_secmod_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (ctx == nullptr || data == nullptr || len == 0) {
        return -EINVAL;
    }

    iog_ipc_auth_request_t auth_req;
    memset(&auth_req, 0, sizeof(auth_req));

    int ret = iog_ipc_unpack_auth_request(data, len, &auth_req);

    if (ret == 0 && auth_req.username != nullptr) {
        ret = secmod_handle_auth(ctx, &auth_req);
        iog_ipc_free_auth_request(&auth_req);
        return ret;
    }

    if (ret == 0) {
        iog_ipc_free_auth_request(&auth_req);
    }

    iog_ipc_session_validate_t sv_req;
    memset(&sv_req, 0, sizeof(sv_req));

    ret = iog_ipc_unpack_session_validate(data, len, &sv_req);
    if (ret == 0 && sv_req.cookie != nullptr && sv_req.cookie_len > 0) {
        ret = secmod_handle_session_validate(ctx, &sv_req);
        iog_ipc_free_session_validate(&sv_req);
        return ret;
    }

    if (ret == 0) {
        iog_ipc_free_session_validate(&sv_req);
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
            ssize_t n = iog_ipc_recv(ctx->ipc_fd, buf, sizeof(buf));

            if (n > 0) {
                (void)rw_secmod_handle_message(ctx, buf, (size_t)n);
            }
        }

        /* Periodic cleanup of expired sessions */
        iog_session_cleanup_expired(ctx->sessions);
        secmod_cleanup_expired_mdbx(ctx);
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
        iog_session_store_destroy(ctx->sessions);
    }

    if (ctx->mdbx != nullptr) {
        rw_mdbx_close(ctx->mdbx);
        free(ctx->mdbx);
    }

    if (ctx->sqlite != nullptr) {
        iog_sqlite_close(ctx->sqlite);
        free(ctx->sqlite);
    }

    if (ctx->vault != nullptr) {
        rw_vault_destroy(ctx->vault);
    }

    explicit_bzero(ctx, sizeof(*ctx));
}
