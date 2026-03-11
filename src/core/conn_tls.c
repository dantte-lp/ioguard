#include "core/conn_tls.h"

#include <errno.h>
#include <string.h>

/* Map tls_abstract error codes to negative errno for the rest of ioguard */
static int tls_err_to_errno(int tls_err)
{
    switch (tls_err) {
    case TLS_E_SUCCESS:
        return 0;
    case TLS_E_AGAIN:
    case TLS_E_INTERRUPTED:
        return -EAGAIN;
    case TLS_E_MEMORY_ERROR:
        return -ENOMEM;
    case TLS_E_INVALID_REQUEST:
    case TLS_E_INVALID_PARAMETER:
        return -EINVAL;
    case TLS_E_CERTIFICATE_ERROR:
    case TLS_E_CERTIFICATE_REQUIRED:
        return -EACCES;
    case TLS_E_PREMATURE_TERMINATION:
        return -ECONNRESET;
    case TLS_E_HANDSHAKE_FAILED:
    case TLS_E_FATAL_ALERT_RECEIVED:
    case TLS_E_DECRYPTION_FAILED:
        return -EPROTO;
    default:
        return -EIO;
    }
}

/* Track whether tls_global_init has been called */
static bool g_tls_initialized = false;

int iog_tls_server_init(iog_tls_server_t *srv, const iog_tls_server_config_t *cfg)
{
    if (srv == nullptr || cfg == nullptr) {
        return -EINVAL;
    }
    if (cfg->cert_file == nullptr || cfg->key_file == nullptr) {
        return -EINVAL;
    }

    memset(srv, 0, sizeof(*srv));

    /* Initialize wolfSSL globally (idempotent guard) */
    if (!g_tls_initialized) {
        int ret = tls_global_init(TLS_BACKEND_WOLFSSL);
        if (ret != TLS_E_SUCCESS) {
            return tls_err_to_errno(ret);
        }
        g_tls_initialized = true;
    }

    /* Create TLS 1.3 server context */
    srv->ctx = tls_context_new(true, false);
    if (srv->ctx == nullptr) {
        return -ENOMEM;
    }

    /* Load certificate */
    int ret = tls_context_set_cert_file(srv->ctx, cfg->cert_file);
    if (ret != TLS_E_SUCCESS) {
        goto cleanup;
    }

    /* Load private key */
    ret = tls_context_set_key_file(srv->ctx, cfg->key_file);
    if (ret != TLS_E_SUCCESS) {
        goto cleanup;
    }

    /* Optional: CA file for client cert verification */
    if (cfg->ca_file != nullptr) {
        ret = tls_context_set_ca_file(srv->ctx, cfg->ca_file);
        if (ret != TLS_E_SUCCESS) {
            goto cleanup;
        }
    }

    /* Optional: cipher priority string */
    if (cfg->ciphers != nullptr) {
        ret = tls_context_set_priority(srv->ctx, cfg->ciphers);
        if (ret != TLS_E_SUCCESS) {
            goto cleanup;
        }
    }

    return 0;

cleanup:
    tls_context_free(srv->ctx);
    srv->ctx = nullptr;
    return tls_err_to_errno(ret);
}

void iog_tls_server_destroy(iog_tls_server_t *srv)
{
    if (srv == nullptr) {
        return;
    }
    if (srv->ctx != nullptr) {
        tls_context_free(srv->ctx);
        srv->ctx = nullptr;
    }
}

int iog_tls_conn_init(iog_tls_conn_t *conn, iog_tls_server_t *srv, int fd)
{
    if (conn == nullptr || srv == nullptr || srv->ctx == nullptr || fd < 0) {
        return -EINVAL;
    }

    memset(conn, 0, sizeof(*conn));
    conn->fd = fd;
    conn->handshake_done = false;

    conn->session = tls_session_new(srv->ctx);
    if (conn->session == nullptr) {
        return -ENOMEM;
    }

    int ret = tls_session_set_fd(conn->session, fd);
    if (ret != TLS_E_SUCCESS) {
        tls_session_free(conn->session);
        conn->session = nullptr;
        return tls_err_to_errno(ret);
    }

    return 0;
}

void iog_tls_conn_destroy(iog_tls_conn_t *conn)
{
    if (conn == nullptr) {
        return;
    }
    if (conn->session != nullptr) {
        if (conn->handshake_done) {
            (void)tls_bye(conn->session);
        }
        tls_session_free(conn->session);
        conn->session = nullptr;
    }
    conn->handshake_done = false;
}

int iog_tls_conn_handshake(iog_tls_conn_t *conn)
{
    if (conn == nullptr || conn->session == nullptr) {
        return -EINVAL;
    }
    if (conn->handshake_done) {
        return 0;
    }

    int ret = tls_handshake(conn->session);
    if (ret == TLS_E_SUCCESS) {
        conn->handshake_done = true;
        return 0;
    }

    return tls_err_to_errno(ret);
}

ssize_t iog_tls_conn_read(iog_tls_conn_t *conn, void *buf, size_t len)
{
    if (conn == nullptr || conn->session == nullptr || buf == nullptr) {
        return -EINVAL;
    }
    if (!conn->handshake_done) {
        return -EPROTO;
    }

    ssize_t ret = tls_recv(conn->session, buf, len);
    if (ret > 0) {
        return ret;
    }

    return tls_err_to_errno((int)ret);
}

ssize_t iog_tls_conn_write(iog_tls_conn_t *conn, const void *buf, size_t len)
{
    if (conn == nullptr || conn->session == nullptr || buf == nullptr) {
        return -EINVAL;
    }
    if (!conn->handshake_done) {
        return -EPROTO;
    }

    ssize_t ret = tls_send(conn->session, buf, len);
    if (ret > 0) {
        return ret;
    }

    return tls_err_to_errno((int)ret);
}
