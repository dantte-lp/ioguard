#ifndef RINGWALL_IO_URING_H
#define RINGWALL_IO_URING_H

/* liburing.h requires POSIX/GNU types (sigset_t, AT_FDCWD, idtype_t, etc.)
 * _GNU_SOURCE is set via target_compile_definitions in CMakeLists.txt */
#include <liburing.h>
#include <stdint.h>
#include <sys/socket.h>

/* Opaque io_uring event loop context */
typedef struct rw_io_ctx rw_io_ctx_t;

/* Completion callback type.
 * res: CQE result (bytes transferred or negative errno)
 * user_data: pointer passed when operation was submitted */
typedef void (*rw_io_cb)(int res, void *user_data);

/* Internal: completion entry tracking */
typedef struct {
    rw_io_cb cb;
    void *user_data;
} rw_io_completion_t;

struct rw_io_ctx {
    struct io_uring ring;
    bool running;
    uint32_t queue_depth;
    /* Active completions for cancel-by-user_data lookup */
    rw_io_completion_t **active;
    uint32_t active_count;
    uint32_t active_cap;
};

/* Create io_uring context. Returns nullptr on failure.
 * queue_depth: number of SQE slots (must be > 0, rounded up to power of 2)
 * flags: io_uring setup flags (e.g., IORING_SETUP_COOP_TASKRUN) */
[[nodiscard]] rw_io_ctx_t *rw_io_init(uint32_t queue_depth, uint32_t flags);

/* Destroy io_uring context and free resources */
void rw_io_destroy(rw_io_ctx_t *ctx);

/* Run event loop once: submit pending SQEs, wait for at least 1 CQE.
 * timeout_ms: max wait time in milliseconds (0 = no wait, poll only)
 * Returns: number of CQEs processed, or negative errno on error */
[[nodiscard]] int rw_io_run_once(rw_io_ctx_t *ctx, uint32_t timeout_ms);

/* Run event loop until rw_io_stop() is called.
 * Returns 0 on clean stop, negative errno on error. */
[[nodiscard]] int rw_io_run(rw_io_ctx_t *ctx);

/* Signal the event loop to stop after current iteration */
void rw_io_stop(rw_io_ctx_t *ctx);

/* Submit a NOP operation (for testing).
 * completed: pointer to int, set to 1 when CQE arrives */
[[nodiscard]] int rw_io_submit_nop(rw_io_ctx_t *ctx, int *completed);

/* Submit a timeout.
 * timeout_ms: duration in milliseconds
 * fired: pointer to int, set to 1 when timeout fires */
[[nodiscard]] int rw_io_add_timeout(rw_io_ctx_t *ctx, uint64_t timeout_ms, int *fired);

/* Submit a recv operation on a socket */
[[nodiscard]] int rw_io_prep_recv(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, int *completed);

/* Submit a send operation on a socket */
[[nodiscard]] int rw_io_prep_send(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len,
                                  int *completed);

/* Submit a read operation on a file descriptor (TUN, signalfd, etc.) */
[[nodiscard]] int rw_io_prep_read(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, int *completed);

/* Submit a write operation on a file descriptor */
[[nodiscard]] int rw_io_prep_write(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len,
                                   int *completed);

/* Callback-based operations — for production event loops.
 * cb is invoked with CQE result (bytes or negative errno) and user_data. */

[[nodiscard]] int rw_io_prep_recv_cb(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, rw_io_cb cb,
                                     void *user_data);

[[nodiscard]] int rw_io_prep_send_cb(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len,
                                     rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_prep_read_cb(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, rw_io_cb cb,
                                     void *user_data);

[[nodiscard]] int rw_io_prep_write_cb(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len,
                                      rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_prep_accept_cb(rw_io_ctx_t *ctx, int fd, struct sockaddr *addr,
                                       socklen_t *addrlen, rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_add_timeout_cb(rw_io_ctx_t *ctx, uint64_t timeout_ms, rw_io_cb cb,
                                       void *user_data);

[[nodiscard]] int rw_io_cancel(rw_io_ctx_t *ctx, void *user_data);

#endif /* RINGWALL_IO_URING_H */
