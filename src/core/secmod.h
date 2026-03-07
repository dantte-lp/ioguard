#ifndef WOLFGUARD_CORE_SECMOD_H
#define WOLFGUARD_CORE_SECMOD_H

#include "auth/pam.h"
#include "core/session.h"
#include "config/config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief sec-mod context — manages authentication and session state.
 *
 * sec-mod is a dedicated child process that handles all authentication.
 * It receives auth requests via SOCK_SEQPACKET IPC from worker processes,
 * dispatches to PAM, manages session cookies, and returns responses.
 */
typedef struct {
    int ipc_fd;
    wg_pam_config_t pam_cfg;
    wg_session_store_t *sessions;
    const wg_config_t *config;
    bool running;
} wg_secmod_ctx_t;

/**
 * @brief Initialise a sec-mod context.
 *
 * @param ctx     Context to initialise (caller-owned).
 * @param ipc_fd  IPC socket fd (SOCK_SEQPACKET).
 * @param config  Server configuration (must outlive ctx).
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int wg_secmod_init(wg_secmod_ctx_t *ctx, int ipc_fd,
                                  const wg_config_t *config);

/**
 * @brief Run the sec-mod event loop (blocking).
 *
 * Polls for IPC messages and processes auth/session-validate requests.
 * Returns when wg_secmod_stop() is called or on fatal error.
 *
 * @param ctx  Initialised context.
 * @return 0 on clean shutdown, negative errno on error.
 */
[[nodiscard]] int wg_secmod_run(wg_secmod_ctx_t *ctx);

/**
 * @brief Signal the sec-mod event loop to stop.
 *
 * @param ctx  Running context.
 */
void wg_secmod_stop(wg_secmod_ctx_t *ctx);

/**
 * @brief Release all resources owned by a sec-mod context.
 *
 * @param ctx  Context to destroy (may be nullptr).
 */
void wg_secmod_destroy(wg_secmod_ctx_t *ctx);

/**
 * @brief Process a single raw IPC message (for unit testing).
 *
 * @param ctx   Initialised context.
 * @param data  Raw IPC message bytes.
 * @param len   Length of data.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int wg_secmod_handle_message(wg_secmod_ctx_t *ctx,
                                            const uint8_t *data, size_t len);

#endif /* WOLFGUARD_CORE_SECMOD_H */
