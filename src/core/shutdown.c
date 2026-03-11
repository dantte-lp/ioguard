#include "core/shutdown.h"

#include <errno.h>
#include <string.h>

int iog_shutdown_init(iog_shutdown_ctx_t *ctx, iog_worker_t *worker, uint32_t timeout_s)
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

int iog_shutdown_encode_disconnect(uint8_t *buf, size_t buf_len)
{
    if (buf == nullptr || buf_len < IOG_CSTP_HEADER_SIZE) {
        return -EINVAL;
    }

    return rw_cstp_encode(buf, buf_len, IOG_CSTP_DISCONNECT, nullptr, 0);
}

int iog_shutdown_drain(iog_shutdown_ctx_t *ctx)
{
    if (ctx == nullptr || ctx->worker == nullptr) {
        return -EINVAL;
    }

    ctx->drain_started = true;

    /* Iterate over all connection slots — safe regardless of conn_id range */
    uint32_t drained = 0;
    uint32_t max_slots = iog_worker_max_connections(ctx->worker);

    for (uint32_t i = 0; i < max_slots; i++) {
        iog_connection_t *conn = iog_worker_connection_at(ctx->worker, i);
        if (conn == nullptr) {
            continue;
        }
        (void)iog_worker_remove_connection(ctx->worker, conn->conn_id);
        drained++;
    }

    ctx->connections_drained = drained;
    return (int)drained;
}

bool iog_shutdown_timed_out(const iog_shutdown_ctx_t *ctx, uint32_t elapsed_s)
{
    if (ctx == nullptr) {
        return true;
    }
    return elapsed_s >= ctx->drain_timeout_s;
}
