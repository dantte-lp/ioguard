#include "io/uring.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Initial capacity for the active completions tracking array */
constexpr uint32_t IOG_IO_ACTIVE_INIT_CAP = 16;

/* Track a completion in the active array (for cancel-by-user_data) */
static int io_active_add(iog_io_ctx_t *ctx, iog_io_completion_t *comp)
{
    if (ctx->active_count == ctx->active_cap) {
        uint32_t new_cap = (ctx->active_cap == 0) ? IOG_IO_ACTIVE_INIT_CAP : ctx->active_cap * 2;
        iog_io_completion_t **new_arr = realloc(ctx->active, new_cap * sizeof(*new_arr));
        if (new_arr == nullptr) {
            return -ENOMEM;
        }
        ctx->active = new_arr;
        ctx->active_cap = new_cap;
    }
    ctx->active[ctx->active_count++] = comp;
    return 0;
}

/* Remove a completion from the active array */
static void io_active_remove(iog_io_ctx_t *ctx, iog_io_completion_t *comp)
{
    for (uint32_t i = 0; i < ctx->active_count; i++) {
        if (ctx->active[i] == comp) {
            /* Swap with last element for O(1) removal */
            ctx->active[i] = ctx->active[ctx->active_count - 1];
            ctx->active_count--;
            return;
        }
    }
}

/* Find a completion by user_data */
static iog_io_completion_t *io_active_find(iog_io_ctx_t *ctx, void *user_data)
{
    for (uint32_t i = 0; i < ctx->active_count; i++) {
        if (ctx->active[i]->user_data == user_data) {
            return ctx->active[i];
        }
    }
    return nullptr;
}

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

iog_io_ctx_t *iog_io_init(uint32_t queue_depth, uint32_t flags)
{
    if (queue_depth == 0) {
        return nullptr;
    }

    iog_io_ctx_t *ctx = calloc(1, sizeof(*ctx));
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

void iog_io_destroy(iog_io_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    io_uring_queue_exit(&ctx->ring);
    free(ctx->active);
    free(ctx);
}

int iog_io_run_once(iog_io_ctx_t *ctx, uint32_t timeout_ms)
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
        iog_io_completion_t *comp = io_uring_cqe_get_data(cqe);
        if (comp != nullptr) {
            io_active_remove(ctx, comp);
            comp->cb(cqe->res, comp->user_data);
            free(comp);
        }
        processed++;
    }
    io_uring_cq_advance(&ctx->ring, processed);

    return processed;
}

int iog_io_run(iog_io_ctx_t *ctx)
{
    ctx->running = true;
    while (ctx->running) {
        int ret = iog_io_run_once(ctx, 1000);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

void iog_io_stop(iog_io_ctx_t *ctx)
{
    ctx->running = false;
}

int iog_io_submit_nop(iog_io_ctx_t *ctx, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
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

int iog_io_prep_recv(iog_io_ctx_t *ctx, int fd, void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
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

int iog_io_prep_send(iog_io_ctx_t *ctx, int fd, const void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
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

int iog_io_prep_read(iog_io_ctx_t *ctx, int fd, void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
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

int iog_io_prep_write(iog_io_ctx_t *ctx, int fd, const void *buf, size_t len, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
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

int iog_io_add_timeout(iog_io_ctx_t *ctx, uint64_t timeout_ms, int *fired)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    /* Allocate completion + timespec together */
    typedef struct {
        iog_io_completion_t comp;
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

/* --- Callback-based operations --- */

int iog_io_prep_recv_cb(iog_io_ctx_t *ctx, int fd, void *buf, size_t len, iog_io_cb cb,
                        void *user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        free(comp);
        return ret;
    }

    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_prep_send_cb(iog_io_ctx_t *ctx, int fd, const void *buf, size_t len, iog_io_cb cb,
                        void *user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        free(comp);
        return ret;
    }

    io_uring_prep_send(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_prep_read_cb(iog_io_ctx_t *ctx, int fd, void *buf, size_t len, iog_io_cb cb,
                        void *user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        free(comp);
        return ret;
    }

    io_uring_prep_read(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_prep_write_cb(iog_io_ctx_t *ctx, int fd, const void *buf, size_t len, iog_io_cb cb,
                         void *user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        free(comp);
        return ret;
    }

    io_uring_prep_write(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_prep_accept_cb(iog_io_ctx_t *ctx, int fd, struct sockaddr *addr, socklen_t *addrlen,
                          iog_io_cb cb, void *user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        free(comp);
        return ret;
    }

    io_uring_prep_accept(sqe, fd, addr, addrlen, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_add_timeout_cb(iog_io_ctx_t *ctx, uint64_t timeout_ms, iog_io_cb cb, void *user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    /* Allocate completion + timespec together */
    typedef struct {
        iog_io_completion_t comp;
        struct __kernel_timespec ts;
    } timeout_data_t;

    timeout_data_t *td = calloc(1, sizeof(*td));
    if (td == nullptr) {
        return -ENOMEM;
    }
    td->comp.cb = cb;
    td->comp.user_data = user_data;
    td->ts.tv_sec = timeout_ms / 1000;
    td->ts.tv_nsec = (timeout_ms % 1000) * 1000000L;

    int ret = io_active_add(ctx, &td->comp);
    if (ret < 0) {
        free(td);
        return ret;
    }

    io_uring_prep_timeout(sqe, &td->ts, 0, 0);
    io_uring_sqe_set_data(sqe, &td->comp);
    return 0;
}

int iog_io_cancel(iog_io_ctx_t *ctx, void *user_data)
{
    /* Find the completion tracking entry by user_data */
    iog_io_completion_t *comp = io_active_find(ctx, user_data);
    if (comp == nullptr) {
        return -ENOENT;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    io_uring_prep_cancel(sqe, comp, 0);
    io_uring_sqe_set_data(sqe, nullptr);
    return 0;
}
