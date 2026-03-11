#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unity/unity.h>
#include "core/main.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_main_parse_args_default_config(void)
{
    char *argv[] = {"ioguard"};
    const char *path = nullptr;
    int ret = iog_main_parse_args(1, argv, &path);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(path);
    TEST_ASSERT_EQUAL_STRING("/etc/ioguard/ioguard.toml", path);
}

void test_main_parse_args_custom_config(void)
{
    char *argv[] = {"ioguard", "--config", "/tmp/test.toml"};
    const char *path = nullptr;
    int ret = iog_main_parse_args(3, argv, &path);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("/tmp/test.toml", path);
}

void test_main_parse_args_help_flag(void)
{
    char *argv[] = {"ioguard", "--help"};
    const char *path = nullptr;
    int ret = iog_main_parse_args(2, argv, &path);
    TEST_ASSERT_EQUAL_INT(1, ret);
}

void test_main_create_ipc_socketpair(void)
{
    int sv[2] = {-1, -1};
    int ret = iog_main_create_ipc_pair(sv);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, sv[0]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, sv[1]);

    /* Verify it's SEQPACKET by sending a message */
    const char *msg = "test";
    ssize_t n = send(sv[0], msg, 4, 0);
    TEST_ASSERT_EQUAL_INT(4, n);

    char buf[16] = {0};
    n = recv(sv[1], buf, sizeof(buf), 0);
    TEST_ASSERT_EQUAL_INT(4, n);
    TEST_ASSERT_EQUAL_STRING("test", buf);

    close(sv[0]);
    close(sv[1]);
}

void test_main_create_accept_socketpair(void)
{
    int sv[2] = {-1, -1};
    int ret = iog_main_create_accept_pair(sv);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, sv[0]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, sv[1]);

    /* Verify it's STREAM */
    const char *msg = "stream";
    ssize_t n = write(sv[0], msg, 6);
    TEST_ASSERT_EQUAL_INT(6, n);

    char buf[16] = {0};
    n = read(sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(6, n);
    TEST_ASSERT_EQUAL_STRING("stream", buf);

    close(sv[0]);
    close(sv[1]);
}

void test_main_signalfd_creation(void)
{
    /* Save and restore signal mask */
    sigset_t old_mask;
    sigprocmask(SIG_BLOCK, nullptr, &old_mask);

    int fd = iog_main_create_signalfd();
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, fd);

    /* Send SIGTERM to self and read from signalfd */
    kill(getpid(), SIGTERM);

    struct signalfd_siginfo ssi;
    ssize_t n = read(fd, &ssi, sizeof(ssi));
    TEST_ASSERT_EQUAL_INT((int)sizeof(ssi), (int)n);
    TEST_ASSERT_EQUAL_UINT32(SIGTERM, ssi.ssi_signo);

    close(fd);

    /* Restore signal mask */
    sigprocmask(SIG_SETMASK, &old_mask, nullptr);
}

void test_main_fork_child_receives_fd(void)
{
    int sv[2];
    int ret = iog_main_create_ipc_pair(sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    pid_t pid = fork();
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, pid);

    if (pid == 0) {
        /* Child: read from sv[1] */
        close(sv[0]);
        char buf[8] = {0};
        ssize_t n = recv(sv[1], buf, sizeof(buf), 0);
        close(sv[1]);
        _exit(n == 4 && memcmp(buf, "ping", 4) == 0 ? 0 : 1);
    }

    /* Parent: write to sv[0] */
    close(sv[1]);
    ssize_t n = send(sv[0], "ping", 4, 0);
    TEST_ASSERT_EQUAL_INT(4, n);
    close(sv[0]);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
}

void test_main_signal_loop_sigterm_exits(void)
{
    /* Save signal mask */
    sigset_t old_mask;
    sigprocmask(SIG_BLOCK, nullptr, &old_mask);

    int fd = iog_main_create_signalfd();
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, fd);

    /* Send SIGTERM directly (already blocked, so it's queued) */
    kill(getpid(), SIGTERM);

    /* Poll with timeout to wait for signal availability */
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int pr = poll(&pfd, 1, 500);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, pr);

    /* Read signalfd — should get SIGTERM */
    struct signalfd_siginfo ssi;
    ssize_t n = read(fd, &ssi, sizeof(ssi));
    TEST_ASSERT_EQUAL_INT((int)sizeof(ssi), (int)n);
    TEST_ASSERT_EQUAL_UINT32(SIGTERM, ssi.ssi_signo);

    close(fd);

    /* Restore signal mask */
    sigprocmask(SIG_SETMASK, &old_mask, nullptr);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_main_parse_args_default_config);
    RUN_TEST(test_main_parse_args_custom_config);
    RUN_TEST(test_main_parse_args_help_flag);
    RUN_TEST(test_main_create_ipc_socketpair);
    RUN_TEST(test_main_create_accept_socketpair);
    RUN_TEST(test_main_signalfd_creation);
    RUN_TEST(test_main_fork_child_receives_fd);
    RUN_TEST(test_main_signal_loop_sigterm_exits);
    return UNITY_END();
}
