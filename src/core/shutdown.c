#include "core/shutdown.h"

#include <errno.h>
#include <string.h>

int rw_shutdown_init(rw_shutdown_ctx_t *ctx, rw_worker_t *worker, uint32_t timeout_s)
{
    if (ctx == nullptr || worker == nullptr) {
        return -EINVAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->worker = worker;
    ctx->drain_timeout_s = (timeout_s > 0) ? timeout_s : RW_SHUTDOWN_DRAIN_TIMEOUT_S;
    ctx->drain_started = false;
    ctx->connections_drained = 0;

    return 0;
}

int rw_shutdown_encode_disconnect(uint8_t *buf, size_t buf_len)
{
    if (buf == nullptr || buf_len < RW_CSTP_HEADER_SIZE) {
        return -EINVAL;
    }

    return rw_cstp_encode(buf, buf_len, RW_CSTP_DISCONNECT, nullptr, 0);
}

int rw_shutdown_drain(rw_shutdown_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->worker == nullptr) {
        return -EINVAL;
    }

    ctx->drain_started = true;

    /* Iterate over all connection slots — safe regardless of conn_id range */
    uint32_t drained = 0;
    uint32_t max_slots = rw_worker_max_connections(ctx->worker);

    for (uint32_t i = 0; i < max_slots; i++) {
        rw_connection_t *conn = rw_worker_connection_at(ctx->worker, i);
        if (conn == nullptr) {
            continue;
        }
        (void)rw_worker_remove_connection(ctx->worker, conn->conn_id);
        drained++;
    }

    ctx->connections_drained = drained;
    return (int)drained;
}

bool rw_shutdown_timed_out(const rw_shutdown_ctx_t *ctx, uint32_t elapsed_s)
{
    if (ctx == nullptr) {
        return true;
    }
    return elapsed_s >= ctx->drain_timeout_s;
}
