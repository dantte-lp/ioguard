#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>
#include "ipc/fdpass.h"

static int sv[2]; /* socketpair for each test */

void setUp(void)
{
    int ret = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    if (ret < 0) {
        TEST_FAIL_MESSAGE("socketpair failed");
    }
}

void tearDown(void)
{
    close(sv[0]);
    close(sv[1]);
}

void test_fdpass_send_recv_single_fd(void)
{
    int pfd[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd));

    /* Send read end of pipe */
    int ret = rw_fdpass_send(sv[0], &pfd[0], 1, nullptr, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Receive fd */
    int recv_fd = -1;
    size_t nfds = 0;
    size_t dlen = 0;
    ret = rw_fdpass_recv(sv[1], &recv_fd, 1, &nfds, nullptr, &dlen);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, nfds);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, recv_fd);

    close(recv_fd);
    close(pfd[0]);
    close(pfd[1]);
}

void test_fdpass_send_recv_with_data(void)
{
    int pfd[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd));

    const char *payload = "meta";
    int ret = rw_fdpass_send(sv[0], &pfd[0], 1, payload, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int recv_fd = -1;
    size_t nfds = 0;
    char buf[16] = {0};
    size_t dlen = sizeof(buf);
    ret = rw_fdpass_recv(sv[1], &recv_fd, 1, &nfds, buf, &dlen);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, nfds);
    TEST_ASSERT_EQUAL_UINT(4, dlen);
    TEST_ASSERT_EQUAL_STRING("meta", buf);

    close(recv_fd);
    close(pfd[0]);
    close(pfd[1]);
}

void test_fdpass_recv_no_fd(void)
{
    /* Send a plain data message (no SCM_RIGHTS) via regular send */
    const char *msg = "hello";
    ssize_t n = send(sv[0], msg, 5, 0);
    TEST_ASSERT_EQUAL_INT(5, n);

    int recv_fd = -1;
    size_t nfds = 99;
    char buf[16] = {0};
    size_t dlen = sizeof(buf);
    int ret = rw_fdpass_recv(sv[1], &recv_fd, 1, &nfds, buf, &dlen);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(0, nfds);
    TEST_ASSERT_EQUAL_INT(-1, recv_fd);
    TEST_ASSERT_EQUAL_UINT(5, dlen);
    TEST_ASSERT_EQUAL_STRING("hello", buf);
}

void test_fdpass_invalid_fd(void)
{
    int bad_fd = -1;
    int ret = rw_fdpass_send(sv[0], &bad_fd, 1, nullptr, 0);
    TEST_ASSERT_EQUAL_INT(-EBADF, ret);
}

void test_fdpass_send_multiple_fds(void)
{
    int pfd1[2], pfd2[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd1));
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd2));

    int fds[2] = {pfd1[0], pfd2[0]};
    int ret = rw_fdpass_send(sv[0], fds, 2, nullptr, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int recv_fds[4] = {-1, -1, -1, -1};
    size_t nfds = 0;
    size_t dlen = 0;
    ret = rw_fdpass_recv(sv[1], recv_fds, 4, &nfds, nullptr, &dlen);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(2, nfds);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, recv_fds[0]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, recv_fds[1]);

    close(recv_fds[0]);
    close(recv_fds[1]);
    close(pfd1[0]);
    close(pfd1[1]);
    close(pfd2[0]);
    close(pfd2[1]);
}

void test_fdpass_received_fd_is_usable(void)
{
    int pfd[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd));

    /* Send write end */
    int ret = rw_fdpass_send(sv[0], &pfd[1], 1, nullptr, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int recv_fd = -1;
    size_t nfds = 0;
    size_t dlen = 0;
    ret = rw_fdpass_recv(sv[1], &recv_fd, 1, &nfds, nullptr, &dlen);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT(1, nfds);

    /* Write through received fd, read from pipe read end */
    const char *msg = "passed";
    ssize_t n = write(recv_fd, msg, 6);
    TEST_ASSERT_EQUAL_INT(6, n);

    char buf[16] = {0};
    n = read(pfd[0], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(6, n);
    TEST_ASSERT_EQUAL_STRING("passed", buf);

    close(recv_fd);
    close(pfd[0]);
    close(pfd[1]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_fdpass_send_recv_single_fd);
    RUN_TEST(test_fdpass_send_recv_with_data);
    RUN_TEST(test_fdpass_recv_no_fd);
    RUN_TEST(test_fdpass_invalid_fd);
    RUN_TEST(test_fdpass_send_multiple_fds);
    RUN_TEST(test_fdpass_received_fd_is_usable);
    return UNITY_END();
}
