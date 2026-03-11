#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>
#include "core/worker.h"
#include "core/worker_loop.h"
#include "ipc/fdpass.h"

/* Shared state: accept socketpair for each test */
static int accept_sv[2];

void setUp(void)
{
    int ret = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, accept_sv);
    if (ret < 0) {
        TEST_FAIL_MESSAGE("socketpair failed for accept pair");
    }
}

void tearDown(void)
{
    close(accept_sv[0]);
    close(accept_sv[1]);
}

static void init_loop(iog_worker_loop_t *loop, uint32_t max_conns)
{
    iog_worker_config_t wcfg;
    iog_worker_config_init(&wcfg);
    wcfg.max_connections = max_conns;

    iog_worker_loop_config_t cfg = {
        .accept_fd = accept_sv[1],
        .ipc_fd = -1,
        .worker_cfg = &wcfg,
    };
    int ret = iog_worker_loop_init(loop, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(loop->worker);
    TEST_ASSERT_NOT_NULL(loop->io);
}

/* Helper: create a socketpair and send one end via fdpass */
static int send_mock_connection(int *local_end)
{
    int tls_sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, tls_sv);
    if (ret < 0) {
        return -errno;
    }

    /* Send tls_sv[1] (worker end) to the loop via fdpass */
    int fds[] = {tls_sv[1]};
    ret = iog_fdpass_send(accept_sv[0], fds, 1, nullptr, 0);
    if (ret < 0) {
        close(tls_sv[0]);
        close(tls_sv[1]);
        return ret;
    }

    close(tls_sv[1]); /* sent via SCM_RIGHTS, worker gets its own fd */
    *local_end = tls_sv[0];
    return 0;
}

void test_worker_loop_init_destroy(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 4);

    TEST_ASSERT_FALSE(loop.running);
    TEST_ASSERT_EQUAL_INT(accept_sv[1], loop.accept_fd);

    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_stop_immediate(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 4);

    /* Stop before run — running should be false */
    iog_worker_loop_stop(&loop);
    TEST_ASSERT_FALSE(loop.running);

    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_accept_fd(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 4);

    /* Send a mock connection fd */
    int local_end;
    int ret = send_mock_connection(&local_end);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Process events — should accept the fd and add connection */
    ret = iog_worker_loop_process_events(&loop);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, iog_worker_connection_count(loop.worker));

    close(local_end);
    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_reject_at_capacity(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 2);

    int locals[3];

    /* Fill to capacity */
    for (int i = 0; i < 2; i++) {
        int ret = send_mock_connection(&locals[i]);
        TEST_ASSERT_EQUAL_INT(0, ret);
        ret = iog_worker_loop_process_events(&loop);
        TEST_ASSERT_EQUAL_INT(0, ret);
    }
    TEST_ASSERT_EQUAL_UINT(2, iog_worker_connection_count(loop.worker));

    /* Third connection should be rejected (closed) */
    int ret = send_mock_connection(&locals[2]);
    TEST_ASSERT_EQUAL_INT(0, ret);
    ret = iog_worker_loop_process_events(&loop);
    /* process_events returns 0 even when ENOSPC — connection is closed */
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(2, iog_worker_connection_count(loop.worker));

    for (int i = 0; i < 3; i++) {
        close(locals[i]);
    }
    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_connection_cleanup(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 4);

    /* Add a connection */
    int local_end;
    int ret = send_mock_connection(&local_end);
    TEST_ASSERT_EQUAL_INT(0, ret);
    ret = iog_worker_loop_process_events(&loop);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, iog_worker_connection_count(loop.worker));

    /* Close the peer end — next recv should get EOF */
    close(local_end);

    /* Process events — recv callback should detect EOF and remove connection */
    for (int i = 0; i < 3; i++) {
        ret = iog_worker_loop_process_events(&loop);
        if (ret < 0 && ret != -ETIME) {
            break;
        }
        if (iog_worker_connection_count(loop.worker) == 0) {
            break;
        }
    }
    TEST_ASSERT_EQUAL_UINT(0, iog_worker_connection_count(loop.worker));

    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_multiple_connections(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 8);

    int locals[3];
    for (int i = 0; i < 3; i++) {
        int ret = send_mock_connection(&locals[i]);
        TEST_ASSERT_EQUAL_INT(0, ret);
        ret = iog_worker_loop_process_events(&loop);
        TEST_ASSERT_EQUAL_INT(0, ret);
    }
    TEST_ASSERT_EQUAL_UINT(3, iog_worker_connection_count(loop.worker));

    for (int i = 0; i < 3; i++) {
        close(locals[i]);
    }
    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_recv_data(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 4);

    /* Add connection */
    int local_end;
    int ret = send_mock_connection(&local_end);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Process events to accept the fd and arm recv */
    ret = iog_worker_loop_process_events(&loop);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, iog_worker_connection_count(loop.worker));

    /* Send data from the "client" end */
    const char *msg = "hello-vpn";
    ssize_t n = write(local_end, msg, 9);
    TEST_ASSERT_EQUAL_INT(9, n);

    /* Process events — recv callback should fire */
    ret = iog_worker_loop_process_events(&loop);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Find the connection and verify data */
    iog_connection_t *conn = iog_worker_find_connection(loop.worker, 1);
    TEST_ASSERT_NOT_NULL(conn);
    TEST_ASSERT_EQUAL_UINT(9, conn->recv_len);
    TEST_ASSERT_EQUAL_MEMORY(msg, conn->recv_buf, 9);

    close(local_end);
    iog_worker_loop_destroy(&loop);
}

void test_worker_loop_tun_write(void)
{
    iog_worker_loop_t loop;
    init_loop(&loop, 4);

    /* Create mock TLS and TUN fd pairs */
    int tls_sv[2], tun_sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, tls_sv));
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, tun_sv));

    /* Send both fds (TLS + TUN) via fdpass */
    int fds[] = {tls_sv[1], tun_sv[1]};
    int ret = iog_fdpass_send(accept_sv[0], fds, 2, nullptr, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);
    close(tls_sv[1]);
    close(tun_sv[1]);

    /* Accept the connection */
    ret = iog_worker_loop_process_events(&loop);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, iog_worker_connection_count(loop.worker));

    /* Verify the connection has a valid TUN fd */
    iog_connection_t *conn = iog_worker_find_connection(loop.worker, 1);
    TEST_ASSERT_NOT_NULL(conn);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, conn->tun_fd);

    /* Write to TUN fd via io_uring and verify on the other end */
    const char *msg = "tun-pkt";
    int completed = 0;
    ret = iog_io_prep_write(loop.io, conn->tun_fd, msg, 7, &completed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(loop.io, 500);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);

    char buf[16] = {0};
    ssize_t n = read(tun_sv[0], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(7, n);
    TEST_ASSERT_EQUAL_STRING("tun-pkt", buf);

    close(tls_sv[0]);
    close(tun_sv[0]);
    iog_worker_loop_destroy(&loop);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_worker_loop_init_destroy);
    RUN_TEST(test_worker_loop_stop_immediate);
    RUN_TEST(test_worker_loop_accept_fd);
    RUN_TEST(test_worker_loop_reject_at_capacity);
    RUN_TEST(test_worker_loop_connection_cleanup);
    RUN_TEST(test_worker_loop_multiple_connections);
    RUN_TEST(test_worker_loop_recv_data);
    RUN_TEST(test_worker_loop_tun_write);
    return UNITY_END();
}
