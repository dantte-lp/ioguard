#ifndef RINGWALL_CORE_SECMOD_H
#define RINGWALL_CORE_SECMOD_H

#include "auth/pam.h"
#include "config/config.h"
#include "core/session.h"
#include "storage/mdbx.h"
#include "storage/sqlite.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief sec-mod context — manages authentication and session state.
 *
 * sec-mod is a dedicated child process that handles all authentication.
 * It receives auth requests via SOCK_SEQPACKET IPC from worker processes,
 * dispatches to PAM, manages session cookies, and returns responses.
 *
 * Storage:
 * - rw_session_store_t: in-memory session cache (always available)
 * - rw_mdbx_ctx_t: persistent session store (if mdbx_path configured)
 * - rw_sqlite_ctx_t: audit log + user management (if sqlite_path configured)
 */
typedef struct {
    int ipc_fd;
    rw_pam_config_t pam_cfg;
    rw_session_store_t *sessions;
    rw_mdbx_ctx_t *mdbx;           /* persistent sessions (nullable) */
    rw_sqlite_ctx_t *sqlite;       /* audit + users (nullable) */
    const rw_config_t *config;
    bool running;
} rw_secmod_ctx_t;

/**
 * @brief Initialise a sec-mod context.
 *
 * @param ctx     Context to initialise (caller-owned).
 * @param ipc_fd  IPC socket fd (SOCK_SEQPACKET).
 * @param config  Server configuration (must outlive ctx).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_secmod_init(rw_secmod_ctx_t *ctx, int ipc_fd, const rw_config_t *config);

/**
 * @brief Run the sec-mod event loop (blocking).
 *
 * Polls for IPC messages and processes auth/session-validate requests.
 * Returns when rw_secmod_stop() is called or on fatal error.
 *
 * @param ctx  Initialised context.
 * @return 0 on clean shutdown, negative errno on error.
 */
[[nodiscard]] int rw_secmod_run(rw_secmod_ctx_t *ctx);

/**
 * @brief Signal the sec-mod event loop to stop.
 *
 * @param ctx  Running context.
 */
void rw_secmod_stop(rw_secmod_ctx_t *ctx);

/**
 * @brief Release all resources owned by a sec-mod context.
 *
 * @param ctx  Context to destroy (may be nullptr).
 */
void rw_secmod_destroy(rw_secmod_ctx_t *ctx);

/**
 * @brief Process a single raw IPC message (for unit testing).
 *
 * @param ctx   Initialised context.
 * @param data  Raw IPC message bytes.
 * @param len   Length of data.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_secmod_handle_message(rw_secmod_ctx_t *ctx, const uint8_t *data, size_t len);

#endif /* RINGWALL_CORE_SECMOD_H */
