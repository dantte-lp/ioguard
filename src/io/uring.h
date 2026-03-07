#ifndef WOLFGUARD_IO_URING_H
#define WOLFGUARD_IO_URING_H

/* liburing.h requires POSIX/GNU types (sigset_t, AT_FDCWD, idtype_t, etc.)
 * _GNU_SOURCE is set via target_compile_definitions in CMakeLists.txt */
#include <liburing.h>
#include <stdbool.h>
#include <stdint.h>

/* Opaque io_uring event loop context */
typedef struct wg_io_ctx wg_io_ctx_t;

/* Completion callback type.
 * res: CQE result (bytes transferred or negative errno)
 * user_data: pointer passed when operation was submitted */
typedef void (*wg_io_cb)(int res, void *user_data);

/* Internal: completion entry tracking */
typedef struct {
    wg_io_cb cb;
    void    *user_data;
} wg_io_completion_t;

struct wg_io_ctx {
    struct io_uring ring;
    bool            running;
    uint32_t        queue_depth;
};

/* Create io_uring context. Returns nullptr on failure.
 * queue_depth: number of SQE slots (must be > 0, rounded up to power of 2)
 * flags: io_uring setup flags (e.g., IORING_SETUP_COOP_TASKRUN) */
[[nodiscard]] wg_io_ctx_t *wg_io_init(uint32_t queue_depth, uint32_t flags);

/* Destroy io_uring context and free resources */
void wg_io_destroy(wg_io_ctx_t *ctx);

/* Run event loop once: submit pending SQEs, wait for at least 1 CQE.
 * timeout_ms: max wait time in milliseconds (0 = no wait, poll only)
 * Returns: number of CQEs processed, or negative errno on error */
[[nodiscard]] int wg_io_run_once(wg_io_ctx_t *ctx, uint32_t timeout_ms);

/* Run event loop until wg_io_stop() is called.
 * Returns 0 on clean stop, negative errno on error. */
[[nodiscard]] int wg_io_run(wg_io_ctx_t *ctx);

/* Signal the event loop to stop after current iteration */
void wg_io_stop(wg_io_ctx_t *ctx);

/* Submit a NOP operation (for testing).
 * completed: pointer to int, set to 1 when CQE arrives */
[[nodiscard]] int wg_io_submit_nop(wg_io_ctx_t *ctx, int *completed);

/* Submit a timeout.
 * timeout_ms: duration in milliseconds
 * fired: pointer to int, set to 1 when timeout fires */
[[nodiscard]] int wg_io_add_timeout(wg_io_ctx_t *ctx, uint64_t timeout_ms, int *fired);

/* Submit a recv operation on a socket */
[[nodiscard]] int wg_io_prep_recv(wg_io_ctx_t *ctx, int fd, void *buf,
                                  size_t len, int *completed);

/* Submit a send operation on a socket */
[[nodiscard]] int wg_io_prep_send(wg_io_ctx_t *ctx, int fd, const void *buf,
                                  size_t len, int *completed);

/* Submit a read operation on a file descriptor (TUN, signalfd, etc.) */
[[nodiscard]] int wg_io_prep_read(wg_io_ctx_t *ctx, int fd, void *buf,
                                  size_t len, int *completed);

/* Submit a write operation on a file descriptor */
[[nodiscard]] int wg_io_prep_write(wg_io_ctx_t *ctx, int fd, const void *buf,
                                   size_t len, int *completed);

#endif /* WOLFGUARD_IO_URING_H */
