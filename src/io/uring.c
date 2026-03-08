#include "io/uring.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Internal callback: sets int pointer to 1 */
static void nop_complete_cb(int res, void *user_data)
{
    (void)res;
    int *flag = user_data;
    *flag = 1;
}

/* Internal callback: timeout fired */
static void timeout_cb(int res, void *user_data)
{
    (void)res;
    int *flag = user_data;
    *flag = 1;
}

rw_io_ctx_t *rw_io_init(uint32_t queue_depth, uint32_t flags)
{
    if (queue_depth == 0) {
        return nullptr;
    }

    rw_io_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return nullptr;
    }

    int ret = io_uring_queue_init(queue_depth, &ctx->ring, flags);
    if (ret < 0) {
        free(ctx);
        return nullptr;
    }

    ctx->queue_depth = queue_depth;
    ctx->running = false;
    return ctx;
}

void rw_io_destroy(rw_io_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    io_uring_queue_exit(&ctx->ring);
    free(ctx);
}

int rw_io_run_once(rw_io_ctx_t *ctx, uint32_t timeout_ms)
{
    struct io_uring_cqe *cqe;
    int ret;
    int processed = 0;

    if (timeout_ms > 0) {
        struct __kernel_timespec ts = {
            .tv_sec = timeout_ms / 1000,
            .tv_nsec = (timeout_ms % 1000) * 1000000L,
        };
        ret = io_uring_submit_and_wait_timeout(&ctx->ring, &cqe, 1, &ts, nullptr);
    } else {
        ret = io_uring_submit(&ctx->ring);
        if (ret < 0) {
            return ret;
        }
        ret = io_uring_peek_cqe(&ctx->ring, &cqe);
    }

    if (ret < 0 && ret != -ETIME) {
        return (ret == -EAGAIN) ? 0 : ret;
    }

    /* Process all available CQEs */
    unsigned head;
    io_uring_for_each_cqe(&ctx->ring, head, cqe)
    {
        rw_io_completion_t *comp = io_uring_cqe_get_data(cqe);
        if (comp != nullptr) {
            comp->cb(cqe->res, comp->user_data);
            free(comp);
        }
        processed++;
    }
    io_uring_cq_advance(&ctx->ring, processed);

    return processed;
}

int rw_io_run(rw_io_ctx_t *ctx)
{
    ctx->running = true;
    while (ctx->running) {
        int ret = rw_io_run_once(ctx, 1000);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

void rw_io_stop(rw_io_ctx_t *ctx)
{
    ctx->running = false;
}

int rw_io_submit_nop(rw_io_ctx_t *ctx, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    rw_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = nop_complete_cb;
    comp->user_data = completed;
    *completed = 0;

    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int rw_io_prep_recv(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    rw_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = nop_complete_cb;
    comp->user_data = completed;
    *completed = 0;

    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int rw_io_prep_send(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    rw_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = nop_complete_cb;
    comp->user_data = completed;
    *completed = 0;

    io_uring_prep_send(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int rw_io_prep_read(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    rw_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = nop_complete_cb;
    comp->user_data = completed;
    *completed = 0;

    io_uring_prep_read(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int rw_io_prep_write(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    rw_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = nop_complete_cb;
    comp->user_data = completed;
    *completed = 0;

    io_uring_prep_write(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int rw_io_add_timeout(rw_io_ctx_t *ctx, uint64_t timeout_ms, int *fired)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    /* Allocate completion + timespec together */
    typedef struct {
        rw_io_completion_t comp;
        struct __kernel_timespec ts;
    } timeout_data_t;

    timeout_data_t *td = calloc(1, sizeof(*td));
    if (td == nullptr) {
        return -ENOMEM;
    }
    td->comp.cb = timeout_cb;
    td->comp.user_data = fired;
    td->ts.tv_sec = timeout_ms / 1000;
    td->ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
    *fired = 0;

    io_uring_prep_timeout(sqe, &td->ts, 0, 0);
    io_uring_sqe_set_data(sqe, &td->comp);
    return 0;
}
