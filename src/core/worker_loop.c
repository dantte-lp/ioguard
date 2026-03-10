#include "core/worker_loop.h"
#include "ipc/fdpass.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Per-connection callback context for io_uring operations */
typedef struct {
    rw_worker_loop_t *loop;
    uint64_t conn_id;
} rw_conn_ctx_t;

static void on_tls_recv(int res, void *user_data);

/* Arm a recv operation on the connection's TLS fd */
static int arm_connection_recv(rw_worker_loop_t *loop, uint64_t conn_id)
{
    rw_connection_t *conn = rw_worker_find_connection(loop->worker, conn_id);
    if (conn == nullptr) {
        return -ENOENT;
    }

    rw_conn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return -ENOMEM;
    }
    ctx->loop = loop;
    ctx->conn_id = conn_id;

    int ret = rw_io_prep_recv_cb(loop->io, conn->tls_fd,
                                  conn->recv_buf, sizeof(conn->recv_buf),
                                  on_tls_recv, ctx);
    if (ret < 0) {
        free(ctx);
        return ret;
    }
    return 0;
}

/* Callback: data received on a connection's TLS fd */
static void on_tls_recv(int res, void *user_data)
{
    rw_conn_ctx_t *ctx = user_data;
    rw_connection_t *conn = rw_worker_find_connection(ctx->loop->worker,
                                                       ctx->conn_id);
    if (conn == nullptr) {
        free(ctx);
        return;
    }

    if (res <= 0) {
        /* Connection closed (EOF) or error — remove connection */
        close(conn->tls_fd);
        if (conn->tun_fd >= 0) {
            close(conn->tun_fd);
        }
        (void)rw_worker_remove_connection(ctx->loop->worker, ctx->conn_id);
        free(ctx);
        return;
    }

    /* Store received data length */
    conn->recv_len = (size_t)res;

    /* TODO Task 6: pass through wolfSSL_read for TLS decryption */
    /* TODO Task 7: forward plaintext to TUN via CSTP framing */

    /* Re-arm recv for next data */
    int ret = rw_io_prep_recv_cb(ctx->loop->io, conn->tls_fd,
                                  conn->recv_buf, sizeof(conn->recv_buf),
                                  on_tls_recv, ctx);
    if (ret < 0) {
        free(ctx);
    }
}

/* Try to receive a new connection from main process via fd passing.
 * Non-blocking: returns 0 if got connection, -EAGAIN if nothing available. */
static int try_accept_connection(rw_worker_loop_t *loop)
{
    int fds[2] = {-1, -1};
    size_t nfds = 0;
    size_t dlen = 0;

    int ret = rw_fdpass_recv(loop->accept_fd, fds, 2, &nfds, nullptr, &dlen);
    if (ret < 0) {
        return ret;
    }

    if (nfds < 1) {
        return -EAGAIN;
    }

    int tls_fd = fds[0];
    int tun_fd = (nfds >= 2) ? fds[1] : -1;

    int64_t conn_id = rw_worker_add_connection(loop->worker, tls_fd, tun_fd);
    if (conn_id < 0) {
        /* At capacity or error — close the received fds */
        close(tls_fd);
        if (tun_fd >= 0) {
            close(tun_fd);
        }
        return (int)conn_id;
    }

    /* Arm recv on the new connection's TLS fd */
    ret = arm_connection_recv(loop, (uint64_t)conn_id);
    if (ret < 0) {
        (void)rw_worker_remove_connection(loop->worker, (uint64_t)conn_id);
        close(tls_fd);
        if (tun_fd >= 0) {
            close(tun_fd);
        }
        return ret;
    }

    return 0;
}

int rw_worker_loop_init(rw_worker_loop_t *loop,
                         const rw_worker_loop_config_t *cfg)
{
    memset(loop, 0, sizeof(*loop));

    loop->io = rw_io_init(cfg->worker_cfg->queue_depth, 0);
    if (loop->io == nullptr) {
        return -ENOMEM;
    }

    loop->worker = rw_worker_create(cfg->worker_cfg);
    if (loop->worker == nullptr) {
        rw_io_destroy(loop->io);
        loop->io = nullptr;
        return -ENOMEM;
    }

    loop->accept_fd = cfg->accept_fd;
    loop->ipc_fd = cfg->ipc_fd;
    loop->running = false;

    /* Make accept_fd non-blocking for polling in the event loop */
    int flags = fcntl(loop->accept_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(loop->accept_fd, F_SETFL, flags | O_NONBLOCK);
    }

    return 0;
}

int rw_worker_loop_process_events(rw_worker_loop_t *loop)
{
    /* Check for new connections from main process */
    int ret = try_accept_connection(loop);
    if (ret < 0 && ret != -EAGAIN && ret != -ENOSPC) {
        return ret;
    }

    /* Process io_uring events (100ms timeout) */
    ret = rw_io_run_once(loop->io, 100);
    if (ret < 0 && ret != -ETIME) {
        return ret;
    }

    return 0;
}

int rw_worker_loop_run(rw_worker_loop_t *loop)
{
    loop->running = true;

    while (loop->running) {
        int ret = rw_worker_loop_process_events(loop);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

void rw_worker_loop_stop(rw_worker_loop_t *loop)
{
    loop->running = false;
    if (loop->io != nullptr) {
        rw_io_stop(loop->io);
    }
}

void rw_worker_loop_destroy(rw_worker_loop_t *loop)
{
    if (loop->worker != nullptr) {
        rw_worker_destroy(loop->worker);
        loop->worker = nullptr;
    }
    if (loop->io != nullptr) {
        rw_io_destroy(loop->io);
        loop->io = nullptr;
    }
}
