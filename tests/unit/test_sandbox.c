/**
 * @file test_sandbox.c
 * @brief Unit tests for seccomp BPF sandbox profiles.
 */

#include <unity/unity.h>
#include "security/sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void setUp(void)
{
}
void tearDown(void)
{
}

/* ---- Filter build tests ---- */

void test_sandbox_worker_filter_build(void)
{
    int count = 0;
    int rc = iog_sandbox_build(IOG_SANDBOX_WORKER, &count);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_GREATER_THAN(0, count);
}

void test_sandbox_authmod_filter_build(void)
{
    int count = 0;
    int rc = iog_sandbox_build(IOG_SANDBOX_AUTHMOD, &count);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_GREATER_THAN(0, count);
}

void test_sandbox_main_filter_build(void)
{
    int count = 0;
    int rc = iog_sandbox_build(IOG_SANDBOX_MAIN, &count);
    TEST_ASSERT_EQUAL_INT(0, rc);
    TEST_ASSERT_GREATER_THAN(0, count);
}

void test_sandbox_filter_syscall_count(void)
{
    int worker_count = 0, authmod_count = 0, main_count = 0;

    int rc = iog_sandbox_build(IOG_SANDBOX_WORKER, &worker_count);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = iog_sandbox_build(IOG_SANDBOX_AUTHMOD, &authmod_count);
    TEST_ASSERT_EQUAL_INT(0, rc);

    rc = iog_sandbox_build(IOG_SANDBOX_MAIN, &main_count);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Each profile is a strict superset. */
    TEST_ASSERT_GREATER_THAN(worker_count, authmod_count);
    TEST_ASSERT_GREATER_THAN(authmod_count, main_count);

    /* Verify exact expected counts:
     * worker=26, authmod=26+14=40, main=40+15=55 */
    TEST_ASSERT_EQUAL_INT(26, worker_count);
    TEST_ASSERT_EQUAL_INT(40, authmod_count);
    TEST_ASSERT_EQUAL_INT(55, main_count);
}

/* ---- Fork-based apply tests ---- */

void test_sandbox_worker_blocks_execve(void)
{
    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        /* Child: apply sandbox, then try execve (should be killed). */
        int rc = iog_sandbox_apply(IOG_SANDBOX_WORKER);
        if (rc != 0) {
            _exit(99);
        }

        /* execve is not in the worker allowlist. */
        char *argv[] = {"/bin/true", nullptr};
        char *envp[] = {nullptr};
        execve("/bin/true", argv, envp);

        /* If execve somehow returns, exit with an error code. */
        _exit(98);
    }

    /* Parent: wait for child. */
    int status = 0;
    pid_t w = waitpid(pid, &status, 0);
    TEST_ASSERT_EQUAL(pid, w);

    /* SCMP_ACT_KILL_PROCESS sends SIGSYS. */
    TEST_ASSERT_TRUE_MESSAGE(WIFSIGNALED(status), "child should have been killed by signal");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SIGSYS, WTERMSIG(status), "expected SIGSYS from seccomp");
}

void test_sandbox_worker_allows_read(void)
{
    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        /* Open /dev/null before applying sandbox (openat is allowed
         * in worker profile anyway, but open before to be safe). */
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            _exit(97);
        }

        int rc = iog_sandbox_apply(IOG_SANDBOX_WORKER);
        if (rc != 0) {
            _exit(99);
        }

        /* read is in the worker allowlist — should succeed. */
        char buf[1];
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);

        /* read from /dev/null returns 0 (EOF). */
        _exit(n == 0 ? 0 : 96);
    }

    int status = 0;
    pid_t w = waitpid(pid, &status, 0);
    TEST_ASSERT_EQUAL(pid, w);

    TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status), "child should have exited normally");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, WEXITSTATUS(status),
                                  "child read from /dev/null should succeed");
}

/* ---- Runner ---- */

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_sandbox_worker_filter_build);
    RUN_TEST(test_sandbox_authmod_filter_build);
    RUN_TEST(test_sandbox_main_filter_build);
    RUN_TEST(test_sandbox_filter_syscall_count);
    RUN_TEST(test_sandbox_worker_blocks_execve);
    RUN_TEST(test_sandbox_worker_allows_read);

    return UNITY_END();
}
