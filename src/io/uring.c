#include "io/uring.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Initial capacity for the active completions tracking array */
constexpr uint32_t IOG_IO_ACTIVE_INIT_CAP = 16;

/* Drain timeout for iog_io_destroy: max iterations waiting for CQEs */
constexpr uint32_t IOG_IO_DRAIN_MAX_ITERS = 64;
constexpr uint32_t IOG_IO_DRAIN_TIMEOUT_MS = 50;

/* --- Send serialization helpers --- */

static inline bool io_send_set_test(const iog_io_send_set_t *set, int fd)
{
    if (fd < 0 || (uint32_t)fd >= IOG_IO_SEND_TRACK_MAX) {
        return false;
    }
    return (set->bits[fd / 64] & (1ULL << (fd % 64))) != 0;
}

static inline void io_send_set_mark(iog_io_send_set_t *set, int fd)
{
    if (fd >= 0 && (uint32_t)fd < IOG_IO_SEND_TRACK_MAX) {
        set->bits[fd / 64] |= (1ULL << (fd % 64));
    }
}

static inline void io_send_set_clear(iog_io_send_set_t *set, int fd)
{
    if (fd >= 0 && (uint32_t)fd < IOG_IO_SEND_TRACK_MAX) {
        set->bits[fd / 64] &= ~(1ULL << (fd % 64));
    }
}

/* --- Slab allocator for iog_io_completion_t objects --- */

/* Allocate a completion from the pre-allocated slab pool.
 * Returns nullptr when pool is exhausted (caller must handle fallback). */
static iog_io_completion_t *slab_alloc(iog_io_ctx_t *ctx)
{
    if (ctx->slab_free_top == 0) {
        return nullptr;
    }
    uint32_t idx = ctx->slab_free_stack[--ctx->slab_free_top];
    iog_io_completion_t *comp = &ctx->slab[idx];
    memset(comp, 0, sizeof(*comp));
    return comp;
}

/* Return a completion to the slab pool.
 * If comp does not belong to the slab (e.g. oversized send/timeout structs),
 * falls back to free(). */
static void slab_free(iog_io_ctx_t *ctx, iog_io_completion_t *comp)
{
    if (comp >= ctx->slab && comp < ctx->slab + ctx->slab_size) {
        uint32_t idx = (uint32_t)(comp - ctx->slab);
        ctx->slab_free_stack[ctx->slab_free_top++] = idx;
    } else {
        free(comp);
    }
}

/* Wrapper completion for send ops: tracks fd for serialization */
typedef struct {
    iog_io_completion_t base;
    iog_io_ctx_t *ctx;
    int fd;
    bool is_send;
} iog_io_send_completion_t;

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

/* Internal callback: clears send-inflight bit then invokes real callback */
static void send_complete_wrapper(int res, void *user_data)
{
    iog_io_send_completion_t *sc = user_data;
    io_send_set_clear(&sc->ctx->send_inflight, sc->fd);
    sc->base.cb(res, sc->base.user_data);
    free(sc);
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

    /* Pre-allocate slab pool for completion objects */
    ctx->slab = calloc(queue_depth, sizeof(*ctx->slab));
    if (ctx->slab == nullptr) {
        io_uring_queue_exit(&ctx->ring);
        free(ctx);
        return nullptr;
    }
    ctx->slab_free_stack = malloc(queue_depth * sizeof(*ctx->slab_free_stack));
    if (ctx->slab_free_stack == nullptr) {
        io_uring_queue_exit(&ctx->ring);
        free(ctx->slab);
        free(ctx);
        return nullptr;
    }
    ctx->slab_size = queue_depth;
    ctx->slab_free_top = queue_depth;
    for (uint32_t i = 0; i < queue_depth; i++) {
        ctx->slab_free_stack[i] = i;
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

    /* Step 1: Cancel all active operations */
    for (uint32_t i = 0; i < ctx->active_count; i++) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
        if (sqe == nullptr) {
            break;
        }
        io_uring_prep_cancel(sqe, ctx->active[i], 0);
        io_uring_sqe_set_data(sqe, nullptr);
    }

    /* Step 2: Submit cancellations */
    io_uring_submit(&ctx->ring);

    /* Step 3: Drain all remaining CQEs until no active ops or timeout */
    for (uint32_t iter = 0; iter < IOG_IO_DRAIN_MAX_ITERS && ctx->active_count > 0; iter++) {
        struct io_uring_cqe *cqe;
        struct __kernel_timespec ts = {
            .tv_sec = 0,
            .tv_nsec = IOG_IO_DRAIN_TIMEOUT_MS * 1000000L,
        };
        int ret = io_uring_submit_and_wait_timeout(&ctx->ring, &cqe, 1, &ts, nullptr);
        if (ret < 0 && ret != -ETIME && ret != -EAGAIN) {
            break;
        }

        unsigned head;
        unsigned count = 0;
        io_uring_for_each_cqe(&ctx->ring, head, cqe)
        {
            iog_io_completion_t *comp = io_uring_cqe_get_data(cqe);
            if (comp != nullptr) {
                io_active_remove(ctx, comp);
                /* During destroy drain, do NOT invoke callbacks — the
                 * owning subsystem (worker, etc.) may already be torn down.
                 * Just return the completion to the slab (or free if oversized). */
                slab_free(ctx, comp);
            }
            count++;
        }
        io_uring_cq_advance(&ctx->ring, count);

        if (count == 0) {
            break;
        }
    }

    /* Step 4: Free any remaining active completions that never got CQEs */
    for (uint32_t i = 0; i < ctx->active_count; i++) {
        slab_free(ctx, ctx->active[i]);
    }

    io_uring_queue_exit(&ctx->ring);
    free(ctx->active);
    free(ctx->slab);
    free(ctx->slab_free_stack);
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
            slab_free(ctx, comp);
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

    iog_io_completion_t *comp = slab_alloc(ctx);
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

    iog_io_completion_t *comp = slab_alloc(ctx);
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
    /* Send serialization: reject if fd already has in-flight send */
    if (io_send_set_test(&ctx->send_inflight, fd)) {
        return -EBUSY;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_send_completion_t *sc = calloc(1, sizeof(*sc));
    if (sc == nullptr) {
        return -ENOMEM;
    }
    sc->base.cb = nop_complete_cb;
    sc->base.user_data = completed;
    sc->ctx = ctx;
    sc->fd = fd;
    sc->is_send = true;
    *completed = 0;

    io_send_set_mark(&ctx->send_inflight, fd);

    /* The CQE handler sees this as iog_io_completion_t* and calls send_complete_wrapper */
    iog_io_completion_t *comp = slab_alloc(ctx);
    if (comp == nullptr) {
        io_send_set_clear(&ctx->send_inflight, fd);
        free(sc);
        return -ENOMEM;
    }
    comp->cb = send_complete_wrapper;
    comp->user_data = sc;

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

    iog_io_completion_t *comp = slab_alloc(ctx);
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

    iog_io_completion_t *comp = slab_alloc(ctx);
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
    // cppcheck-suppress memleak  ; td freed in CQE handler (iog_io_run_once)
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

    iog_io_completion_t *comp = slab_alloc(ctx);
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        slab_free(ctx, comp);
        return ret;
    }

    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_prep_send_cb(iog_io_ctx_t *ctx, int fd, const void *buf, size_t len, iog_io_cb cb,
                        void *user_data)
{
    /* Send serialization: reject if fd already has in-flight send */
    if (io_send_set_test(&ctx->send_inflight, fd)) {
        return -EBUSY;
    }

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_send_completion_t *sc = calloc(1, sizeof(*sc));
    if (sc == nullptr) {
        return -ENOMEM;
    }
    sc->base.cb = cb;
    sc->base.user_data = user_data;
    sc->ctx = ctx;
    sc->fd = fd;
    sc->is_send = true;

    /* Wrap in a completion that clears the send bit on CQE */
    iog_io_completion_t *comp = slab_alloc(ctx);
    if (comp == nullptr) {
        free(sc);
        return -ENOMEM;
    }
    comp->cb = send_complete_wrapper;
    comp->user_data = sc;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        free(sc);
        slab_free(ctx, comp);
        return ret;
    }

    io_send_set_mark(&ctx->send_inflight, fd);

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

    iog_io_completion_t *comp = slab_alloc(ctx);
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        slab_free(ctx, comp);
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

    iog_io_completion_t *comp = slab_alloc(ctx);
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        slab_free(ctx, comp);
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

    iog_io_completion_t *comp = slab_alloc(ctx);
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = cb;
    comp->user_data = user_data;

    int ret = io_active_add(ctx, comp);
    if (ret < 0) {
        slab_free(ctx, comp);
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
    // cppcheck-suppress memleak  ; td freed in CQE handler via io_active tracking
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

/* --- io_uring ring restrictions --- */

/* Common worker opcodes allowed for data-plane operations */
static const uint8_t worker_ops[] = {
    IORING_OP_RECV,    IORING_OP_SEND,           IORING_OP_READ, IORING_OP_WRITE,
    IORING_OP_TIMEOUT, IORING_OP_TIMEOUT_REMOVE, IORING_OP_NOP,  IORING_OP_ASYNC_CANCEL,
};

/* Additional opcodes for auth-mod (storage file access) */
static const uint8_t authmod_extra_ops[] = {
    IORING_OP_OPENAT,
    IORING_OP_CLOSE,
    IORING_OP_FSYNC,
};

/* Build restriction array and apply to ring.
 * Ring MUST have been created with IORING_SETUP_R_DISABLED. */
static int io_apply_restrictions(struct io_uring *ring, const uint8_t *ops, size_t nops,
                                 const uint8_t *extra_ops, size_t nextra)
{
    /* +1 for IORING_RESTRICTION_REGISTER_OP (ENABLE_RINGS) */
    size_t total = nops + nextra + 1;
    struct io_uring_restriction *res = calloc(total, sizeof(*res));
    if (res == nullptr) {
        return -ENOMEM;
    }

    size_t idx = 0;

    /* Allow each SQE opcode */
    for (size_t i = 0; i < nops; i++) {
        res[idx].opcode = IORING_RESTRICTION_SQE_OP;
        res[idx].sqe_op = ops[i];
        idx++;
    }
    for (size_t i = 0; i < nextra; i++) {
        res[idx].opcode = IORING_RESTRICTION_SQE_OP;
        res[idx].sqe_op = extra_ops[i];
        idx++;
    }

    /* Allow IORING_REGISTER_ENABLE_RINGS so we can enable the ring after */
    res[idx].opcode = IORING_RESTRICTION_REGISTER_OP;
    res[idx].register_op = IORING_REGISTER_ENABLE_RINGS;
    idx++;

    int ret = io_uring_register_restrictions(ring, res, (unsigned int)idx);
    free(res);

    if (ret < 0) {
        return ret;
    }

    /* Enable the ring now that restrictions are in place */
    ret = io_uring_enable_rings(ring);
    return ret;
}

int iog_io_restrict_worker(iog_io_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return -EINVAL;
    }
    return io_apply_restrictions(&ctx->ring, worker_ops, sizeof(worker_ops) / sizeof(worker_ops[0]),
                                 nullptr, 0);
}

int iog_io_restrict_authmod(iog_io_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return -EINVAL;
    }
    return io_apply_restrictions(&ctx->ring, worker_ops, sizeof(worker_ops) / sizeof(worker_ops[0]),
                                 authmod_extra_ops,
                                 sizeof(authmod_extra_ops) / sizeof(authmod_extra_ops[0]));
}

bool iog_io_restrictions_supported(void)
{
    /* Probe by creating a disabled ring and attempting to register restrictions */
    struct io_uring probe_ring;
    int ret = io_uring_queue_init(1, &probe_ring, IORING_SETUP_R_DISABLED);
    if (ret < 0) {
        return false;
    }

    /* Try registering a single NOP restriction */
    struct io_uring_restriction res = {
        .opcode = IORING_RESTRICTION_SQE_OP,
        .sqe_op = IORING_OP_NOP,
    };

    ret = io_uring_register_restrictions(&probe_ring, &res, 1);
    io_uring_queue_exit(&probe_ring);

    return (ret == 0);
}
