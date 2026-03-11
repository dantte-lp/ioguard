#ifndef RINGWALL_CORE_SHUTDOWN_H
#define RINGWALL_CORE_SHUTDOWN_H

#include "core/conn_data.h"
#include "core/worker.h"
#include "network/cstp.h"

#include <stdint.h>

/** Default drain timeout in seconds before force-closing connections. */
constexpr uint32_t RW_SHUTDOWN_DRAIN_TIMEOUT_S = 30;

/**
 * @brief Shutdown context for coordinating graceful drain.
 */
typedef struct {
    iog_worker_t *worker;
    uint32_t drain_timeout_s;
    uint32_t connections_drained;
    bool drain_started;
} iog_shutdown_ctx_t;

/**
 * @brief Initialize shutdown context.
 *
 * @param ctx     Shutdown context (caller-owned).
 * @param worker  Worker owning the connections to drain.
 * @param timeout_s  Drain timeout in seconds (0 = use default).
 * @return 0 on success, -EINVAL on bad params.
 */
[[nodiscard]] int iog_shutdown_init(iog_shutdown_ctx_t *ctx, iog_worker_t *worker, uint32_t timeout_s);

/**
 * @brief Encode a CSTP DISCONNECT frame into a buffer.
 *
 * Helper for sending disconnect to each connection's TLS write path.
 *
 * @param buf      Output buffer (must be >= IOG_CSTP_HEADER_SIZE).
 * @param buf_len  Buffer size.
 * @return Encoded length on success, negative errno on error.
 */
[[nodiscard]] int iog_shutdown_encode_disconnect(uint8_t *buf, size_t buf_len);

/**
 * @brief Drain all active connections in the worker.
 *
 * For each active connection: encodes a CSTP DISCONNECT frame.
 * Caller is responsible for actually sending the frame via TLS.
 * After drain, removes all connections from the worker pool.
 *
 * @param ctx  Shutdown context.
 * @return Number of connections drained, or negative errno on error.
 */
[[nodiscard]] int iog_shutdown_drain(iog_shutdown_ctx_t *ctx);

/**
 * @brief Check if drain timeout has been exceeded.
 *
 * @param ctx       Shutdown context.
 * @param elapsed_s  Seconds since drain started.
 * @return true if timeout exceeded.
 */
[[nodiscard]] bool iog_shutdown_timed_out(const iog_shutdown_ctx_t *ctx, uint32_t elapsed_s);

#endif /* RINGWALL_CORE_SHUTDOWN_H */
