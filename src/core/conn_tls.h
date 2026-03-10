#ifndef RINGWALL_CORE_CONN_TLS_H
#define RINGWALL_CORE_CONN_TLS_H

#include "crypto/tls_abstract.h"

#include <stdint.h>

/**
 * @brief Per-worker TLS server context (shared across all connections).
 *
 * Wraps tls_context_t with server-specific configuration.
 * One instance per worker process, created at worker startup.
 */
typedef struct {
    tls_context_t *ctx;
} rw_tls_server_t;

/**
 * @brief Per-connection TLS state.
 *
 * Wraps tls_session_t for a single client connection.
 * Owned by the worker event loop, one per active VPN client.
 */
typedef struct {
    tls_session_t *session;
    int fd;
    bool handshake_done;
} rw_tls_conn_t;

/**
 * @brief Configuration for TLS server context.
 */
typedef struct {
    const char *cert_file;
    const char *key_file;
    const char *ca_file; /* may be nullptr (no client cert verification) */
    const char *ciphers; /* GnuTLS priority string, nullptr for defaults */
} rw_tls_server_config_t;

/**
 * @brief Initialize per-worker TLS server context.
 *
 * Calls tls_global_init() if not yet done, creates TLS 1.3 server context,
 * loads certificate and key.
 *
 * @param srv  Server context to initialize (caller-owned).
 * @param cfg  TLS configuration (cert_file and key_file required).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_tls_server_init(rw_tls_server_t *srv, const rw_tls_server_config_t *cfg);

/**
 * @brief Destroy per-worker TLS server context.
 * @param srv  Server context (may be nullptr).
 */
void rw_tls_server_destroy(rw_tls_server_t *srv);

/**
 * @brief Initialize per-connection TLS state.
 *
 * Creates a new TLS session from the server context and associates the fd.
 *
 * @param conn  Connection to initialize (caller-owned).
 * @param srv   Server context (must outlive conn).
 * @param fd    Client socket fd.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_tls_conn_init(rw_tls_conn_t *conn, rw_tls_server_t *srv, int fd);

/**
 * @brief Destroy per-connection TLS state.
 *
 * Sends close_notify and frees the TLS session. Does NOT close fd.
 *
 * @param conn  Connection to destroy (may be nullptr).
 */
void rw_tls_conn_destroy(rw_tls_conn_t *conn);

/**
 * @brief Attempt TLS handshake (non-blocking).
 *
 * @param conn  Connection with fd set.
 * @return 0 if handshake complete, -EAGAIN if WANT_READ/WANT_WRITE,
 *         negative errno on fatal error.
 */
[[nodiscard]] int rw_tls_conn_handshake(rw_tls_conn_t *conn);

/**
 * @brief Read decrypted data from TLS connection.
 *
 * @param conn  Connection (handshake must be done).
 * @param buf   Output buffer.
 * @param len   Buffer size.
 * @return Bytes read (>0), -EAGAIN if would block, negative errno on error.
 */
[[nodiscard]] ssize_t rw_tls_conn_read(rw_tls_conn_t *conn, void *buf, size_t len);

/**
 * @brief Write data to TLS connection (encrypted on wire).
 *
 * @param conn  Connection (handshake must be done).
 * @param buf   Data to send.
 * @param len   Data length.
 * @return Bytes written (>0), -EAGAIN if would block, negative errno on error.
 */
[[nodiscard]] ssize_t rw_tls_conn_write(rw_tls_conn_t *conn, const void *buf, size_t len);

#endif /* RINGWALL_CORE_CONN_TLS_H */
