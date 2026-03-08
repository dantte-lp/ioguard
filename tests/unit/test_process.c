#define _GNU_SOURCE
#include <unity/unity.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "core/process.h"

void setUp(void) {}
void tearDown(void) {}

void test_rw_process_spawn_and_wait(void)
{
    rw_process_t proc;
    const char *argv[] = {"/bin/true", nullptr};
    int ret = rw_process_spawn(&proc, "/bin/true", argv);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, proc.pidfd);

    int exit_status;
    ret = rw_process_wait(&proc, &exit_status, 5000);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(0, exit_status);
    TEST_ASSERT_GREATER_THAN(0, proc.pid);

    rw_process_cleanup(&proc);
}

void test_rw_process_spawn_exit_code(void)
{
    rw_process_t proc;
    const char *argv[] = {"/bin/false", nullptr};
    int ret = rw_process_spawn(&proc, "/bin/false", argv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int exit_status;
    ret = rw_process_wait(&proc, &exit_status, 5000);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_EQUAL(0, exit_status);

    rw_process_cleanup(&proc);
}

void test_rw_process_spawn_nonexistent(void)
{
    rw_process_t proc;
    const char *argv[] = {"/nonexistent", nullptr};
    int ret = rw_process_spawn(&proc, "/nonexistent", argv);
    if (ret == 0) {
        int exit_status;
        ret = rw_process_wait(&proc, &exit_status, 5000);
        TEST_ASSERT_EQUAL_INT(0, ret);
        TEST_ASSERT_NOT_EQUAL(0, exit_status);
        rw_process_cleanup(&proc);
    } else {
        TEST_ASSERT_LESS_THAN(0, ret);
    }
}

void test_rw_process_kill(void)
{
    rw_process_t proc;
    const char *argv[] = {"/bin/sleep", "60", nullptr};
    int ret = rw_process_spawn(&proc, "/bin/sleep", argv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = rw_process_signal(&proc, SIGTERM);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int exit_status;
    ret = rw_process_wait(&proc, &exit_status, 5000);
    TEST_ASSERT_EQUAL_INT(0, ret);

    rw_process_cleanup(&proc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rw_process_spawn_and_wait);
    RUN_TEST(test_rw_process_spawn_exit_code);
    RUN_TEST(test_rw_process_spawn_nonexistent);
    RUN_TEST(test_rw_process_kill);
    return UNITY_END();
}
