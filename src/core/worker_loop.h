#ifndef RINGWALL_CORE_WORKER_LOOP_H
#define RINGWALL_CORE_WORKER_LOOP_H

#include "core/worker.h"
#include "io/uring.h"

#include <stdint.h>

/**
 * @brief Worker event loop context.
 *
 * Wraps rw_worker_t (connection pool) with an io_uring event loop.
 * Receives new client fds from main via accept_fd (SCM_RIGHTS).
 * Drives TLS handshake, CSTP framing, and TUN I/O per connection.
 */
typedef struct {
    rw_worker_t *worker;
    rw_io_ctx_t *io;
    int accept_fd; /* unix socket: main passes client fds here */
    int ipc_fd;    /* IPC to auth-mod */
    bool running;
} rw_worker_loop_t;

typedef struct {
    int accept_fd;
    int ipc_fd;
    const rw_worker_config_t *worker_cfg;
} rw_worker_loop_config_t;

/**
 * @brief Initialize worker event loop.
 * @param loop  Worker loop context to initialize.
 * @param cfg   Configuration specifying accept_fd, ipc_fd, worker config.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_worker_loop_init(rw_worker_loop_t *loop, const rw_worker_loop_config_t *cfg);

/**
 * @brief Run worker event loop (blocking). Returns on rw_worker_loop_stop().
 * @param loop  Worker loop context.
 * @return 0 on clean stop, negative errno on error.
 */
[[nodiscard]] int rw_worker_loop_run(rw_worker_loop_t *loop);

/**
 * @brief Process one iteration of the event loop.
 *
 * Checks for new connections from main, processes io_uring events.
 * Useful for testing — avoids blocking run loop.
 *
 * @param loop  Worker loop context.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_worker_loop_process_events(rw_worker_loop_t *loop);

/**
 * @brief Signal worker event loop to stop.
 * @param loop  Worker loop context.
 */
void rw_worker_loop_stop(rw_worker_loop_t *loop);

/**
 * @brief Destroy worker event loop and free resources.
 * @param loop  Worker loop context.
 */
void rw_worker_loop_destroy(rw_worker_loop_t *loop);

#endif /* RINGWALL_CORE_WORKER_LOOP_H */
