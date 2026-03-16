#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <unity/unity.h>
#include "io/uring.h"

/* Track whether io_uring syscalls are available in this environment */
static bool io_uring_available = false;

/* Test callback: sets int pointer to 1 */
static void test_complete_cb(int res, void *user_data)
{
    (void)res;
    int *flag = user_data;
    *flag = 1;
}

void setUp(void)
{
}
void tearDown(void)
{
}

void test_iog_io_init_creates_context(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    if (ctx == nullptr) {
        /* io_uring_setup syscall may be blocked by seccomp in containers */
        TEST_IGNORE_MESSAGE("io_uring not available (ENOSYS) — skipping");
    }
    io_uring_available = true;
    TEST_ASSERT_NOT_NULL(ctx);
    iog_io_destroy(ctx);
}

void test_iog_io_init_zero_depth_fails(void)
{
    /* This test does not touch the kernel — always runs */
    iog_io_ctx_t *ctx = iog_io_init(0, 0);
    TEST_ASSERT_NULL(ctx);
}

void test_iog_io_run_once_with_timeout(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Submit a timeout and run once — should complete after ~10ms */
    int fired = 0;
    int ret = iog_io_add_timeout(ctx, 10, &fired);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100); /* wait up to 100ms */
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(1, fired);

    iog_io_destroy(ctx);
}

void test_iog_io_nop_completes(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int completed = 0;
    int ret = iog_io_submit_nop(ctx, &completed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(1, completed);

    iog_io_destroy(ctx);
}

void test_iog_io_accept_and_recv(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const char *msg = "hello";
    write(sv[0], msg, 5);

    char buf[64] = {0};
    int recv_done = 0;
    ret = iog_io_prep_recv(ctx, sv[1], buf, sizeof(buf), &recv_done);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_EQUAL_INT(1, recv_done);
    TEST_ASSERT_EQUAL_STRING("hello", buf);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_iog_io_send(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const char *msg = "world";
    int send_done = 0;
    ret = iog_io_prep_send(ctx, sv[0], msg, 5, &send_done);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_EQUAL_INT(1, send_done);

    char buf[64] = {0};
    ssize_t n = read(sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(5, n);
    TEST_ASSERT_EQUAL_STRING("world", buf);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_iog_io_signalfd(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, nullptr);

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, sfd);

    struct signalfd_siginfo siginfo;
    int sig_received = 0;
    int ret = iog_io_prep_read(ctx, sfd, &siginfo, sizeof(siginfo), &sig_received);
    TEST_ASSERT_EQUAL_INT(0, ret);

    kill(getpid(), SIGUSR1);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_EQUAL_INT(1, sig_received);
    TEST_ASSERT_EQUAL_UINT32(SIGUSR1, siginfo.ssi_signo);

    close(sfd);
    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
    iog_io_destroy(ctx);
}

/* --- Task 4: IORING_REGISTER_RESTRICTIONS tests --- */

void test_io_restrict_worker_succeeds_or_unsupported(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    /* Restrictions require IORING_SETUP_R_DISABLED */
    iog_io_ctx_t *ctx = iog_io_init(64, IORING_SETUP_R_DISABLED);
    if (ctx == nullptr) {
        TEST_IGNORE_MESSAGE("IORING_SETUP_R_DISABLED not supported — skipping");
    }

    int ret = iog_io_restrict_worker(ctx);
    /* Must succeed (0) or gracefully report unsupported kernel (-ENOSYS, -EINVAL) */
    TEST_ASSERT_TRUE(ret == 0 || ret == -ENOSYS || ret == -EINVAL);

    iog_io_destroy(ctx);
}

void test_io_restrict_null_returns_einval(void)
{
    int ret = iog_io_restrict_worker(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = iog_io_restrict_authmod(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_io_restrictions_supported_no_crash(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    /* Must return true or false without crashing */
    bool supported = iog_io_restrictions_supported();
    TEST_ASSERT_TRUE(supported == true || supported == false);
}

/* --- Task 6: Send serialization tests --- */

void test_io_send_serialization_rejects_concurrent(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const char *msg = "test";
    int done1 = 0;
    int done2 = 0;

    /* First send should succeed */
    ret = iog_io_prep_send(ctx, sv[0], msg, 4, &done1);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Second send on same fd should be rejected */
    ret = iog_io_prep_send(ctx, sv[0], msg, 4, &done2);
    TEST_ASSERT_EQUAL_INT(-EBUSY, ret);

    /* Complete the first send, then second should work */
    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);

    ret = iog_io_prep_send(ctx, sv[0], msg, 4, &done2);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_io_send_cb_serialization_rejects_concurrent(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const char *msg = "data";
    int done1 = 0;
    int done2 = 0;

    /* First cb send should succeed */
    ret = iog_io_prep_send_cb(ctx, sv[0], msg, 4, test_complete_cb, &done1);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Second cb send on same fd should be rejected */
    ret = iog_io_prep_send_cb(ctx, sv[0], msg, 4, test_complete_cb, &done2);
    TEST_ASSERT_EQUAL_INT(-EBUSY, ret);

    /* Drain */
    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

/* --- Task 7: Destroy drain test --- */

void test_io_destroy_with_pending_ops(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Submit a long timeout that will be pending when we destroy */
    int fired1 = 0;
    int fired2 = 0;
    int ret = iog_io_add_timeout_cb(ctx, 60000, test_complete_cb, &fired1);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_add_timeout_cb(ctx, 60000, test_complete_cb, &fired2);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Submit so kernel sees them */
    io_uring_submit(&ctx->ring);

    /* Destroy should cancel pending ops, drain CQEs, then exit cleanly */
    iog_io_destroy(ctx);

    /* If we get here without hanging/crashing, the drain worked */
    TEST_PASS();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_iog_io_init_creates_context);
    RUN_TEST(test_iog_io_init_zero_depth_fails);
    RUN_TEST(test_iog_io_run_once_with_timeout);
    RUN_TEST(test_iog_io_nop_completes);
    RUN_TEST(test_iog_io_accept_and_recv);
    RUN_TEST(test_iog_io_send);
    RUN_TEST(test_iog_io_signalfd);
    /* Task 4: Ring restrictions */
    RUN_TEST(test_io_restrict_worker_succeeds_or_unsupported);
    RUN_TEST(test_io_restrict_null_returns_einval);
    RUN_TEST(test_io_restrictions_supported_no_crash);
    /* Task 6: Send serialization */
    RUN_TEST(test_io_send_serialization_rejects_concurrent);
    RUN_TEST(test_io_send_cb_serialization_rejects_concurrent);
    /* Task 7: Destroy drain */
    RUN_TEST(test_io_destroy_with_pending_ops);
    return UNITY_END();
}
