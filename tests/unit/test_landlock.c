/**
 * @file test_landlock.c
 * @brief Unit tests for Landlock filesystem isolation profiles.
 */

#include <unity/unity.h>
#include "security/landlock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char tmp_dir[256];
static char allowed_file[512];
static char blocked_file[512];

void setUp(void)
{
}
void tearDown(void)
{
}

/** Create temporary directory with test files for fork-based tests. */
static void create_test_fixtures(void)
{
    snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/rw_landlock_test_XXXXXX");
    TEST_ASSERT_NOT_NULL(mkdtemp(tmp_dir));

    snprintf(allowed_file, sizeof(allowed_file), "%s/allowed.dat", tmp_dir);
    snprintf(blocked_file, sizeof(blocked_file), "%s/blocked.dat", tmp_dir);

    /* Create both files with some content. */
    int fd = open(allowed_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
    (void)write(fd, "test", 4);
    close(fd);

    fd = open(blocked_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    TEST_ASSERT_GREATER_OR_EQUAL(0, fd);
    (void)write(fd, "test", 4);
    close(fd);
}

static void remove_test_fixtures(void)
{
    unlink(allowed_file);
    unlink(blocked_file);
    rmdir(tmp_dir);
}

/* ---- Test: kernel support detection ---- */

void test_landlock_supported(void)
{
    /* Just verify the function returns without crashing.
     * The result depends on the kernel; either way is valid. */
    bool supported = rw_landlock_supported();
    if (!supported) {
        TEST_IGNORE_MESSAGE("Landlock not supported on this kernel");
    }
    TEST_ASSERT_TRUE(supported);
}

/* ---- Test: worker ruleset build ---- */

void test_landlock_worker_ruleset_build(void)
{
    if (!rw_landlock_supported()) {
        TEST_IGNORE_MESSAGE("Landlock not supported on this kernel");
    }

    create_test_fixtures();

    /* Fork so the Landlock apply does not affect this process. */
    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        int rc = rw_landlock_apply(RW_LANDLOCK_WORKER, allowed_file, nullptr);
        _exit(rc == 0 ? 0 : 1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    remove_test_fixtures();

    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
}

/* ---- Test: authmod ruleset build ---- */

void test_landlock_authmod_ruleset_build(void)
{
    if (!rw_landlock_supported()) {
        TEST_IGNORE_MESSAGE("Landlock not supported on this kernel");
    }

    create_test_fixtures();

    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        int rc = rw_landlock_apply(RW_LANDLOCK_AUTHMOD, allowed_file, blocked_file);
        _exit(rc == 0 ? 0 : 1);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    remove_test_fixtures();

    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
}

/* ---- Test: worker blocks write to non-allowed path ---- */

void test_landlock_worker_blocks_write(void)
{
    if (!rw_landlock_supported()) {
        TEST_IGNORE_MESSAGE("Landlock not supported on this kernel");
    }

    create_test_fixtures();

    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        /* Apply worker profile: only allowed_file readable. */
        int rc = rw_landlock_apply(RW_LANDLOCK_WORKER, allowed_file, nullptr);
        if (rc != 0) {
            _exit(99);
        }

        /* Try to open the blocked file for writing.
         * This should fail with EACCES. */
        int fd = open(blocked_file, O_WRONLY);
        if (fd < 0 && errno == EACCES) {
            _exit(0); /* Expected: blocked. */
        }
        if (fd >= 0) {
            close(fd);
        }
        _exit(1); /* Unexpected: access was not denied. */
    }

    int status = 0;
    waitpid(pid, &status, 0);
    remove_test_fixtures();

    TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status), "child should exit normally");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, WEXITSTATUS(status),
                                  "open(O_WRONLY) on blocked path "
                                  "should return EACCES");
}

/* ---- Test: worker allows read on permitted path ---- */

void test_landlock_worker_allows_read(void)
{
    if (!rw_landlock_supported()) {
        TEST_IGNORE_MESSAGE("Landlock not supported on this kernel");
    }

    create_test_fixtures();

    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);

    if (pid == 0) {
        int rc = rw_landlock_apply(RW_LANDLOCK_WORKER, allowed_file, nullptr);
        if (rc != 0) {
            _exit(99);
        }

        /* Read from allowed file should succeed. */
        int fd = open(allowed_file, O_RDONLY);
        if (fd < 0) {
            _exit(1);
        }

        char buf[8];
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);

        _exit(n > 0 ? 0 : 2);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    remove_test_fixtures();

    TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status), "child should exit normally");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, WEXITSTATUS(status),
                                  "open(O_RDONLY) on allowed path "
                                  "should succeed");
}

/* ---- Runner ---- */

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_landlock_supported);
    RUN_TEST(test_landlock_worker_ruleset_build);
    RUN_TEST(test_landlock_authmod_ruleset_build);
    RUN_TEST(test_landlock_worker_blocks_write);
    RUN_TEST(test_landlock_worker_allows_read);

    return UNITY_END();
}
