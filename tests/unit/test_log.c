#include <string.h>
#include <unity/unity.h>
#include "log/rw_log.h"

static rw_logger_t *logger;

void setUp(void)
{
    logger = nullptr;
}

void tearDown(void)
{
    rw_log_destroy(logger);
    logger = nullptr;
}

void test_log_init_returns_zero(void)
{
    int ret = rw_log_init(&logger, 4096);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(logger);
}

void test_log_write_info_message(void)
{
    int ret = rw_log_init(&logger, 4096);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = rw_log_write(logger, RW_LOG_INFO, "worker", "connection accepted");
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t n = rw_log_flush(logger, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);
    buf[n] = '\0';

    /* Verify the message content appears in the flushed output */
    TEST_ASSERT_NOT_NULL(strstr(buf, "connection accepted"));
}

void test_log_write_with_structured_data(void)
{
    int ret = rw_log_init(&logger, 4096);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const char *params[][2] = {
        {"user", "alice"},
        {"src", "10.0.0.1"},
    };

    ret = rw_log_write_sd(logger, RW_LOG_NOTICE, "auth",
                          "login successful", "auth@ringwall", params, 2);
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t n = rw_log_flush(logger, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);
    buf[n] = '\0';

    /* Verify structured data and message are present */
    TEST_ASSERT_NOT_NULL(strstr(buf, "login successful"));
}

void test_log_flush_reads_buffer(void)
{
    int ret = rw_log_init(&logger, 4096);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = rw_log_write(logger, RW_LOG_ERR, "tls", "handshake failed");
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t n = rw_log_flush(logger, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    /* Second flush should return 0 — buffer was drained */
    ssize_t n2 = rw_log_flush(logger, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, n2);
}

void test_log_destroy_null_safe(void)
{
    /* Must not crash when passed nullptr */
    rw_log_destroy(nullptr);
}

void test_log_severity_levels(void)
{
    int ret = rw_log_init(&logger, 4096);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Set minimum level to WARN — only WARN and above should be logged */
    rw_log_set_level(logger, RW_LOG_WARN);

    /* DEBUG message should be silently dropped */
    ret = rw_log_write(logger, RW_LOG_DEBUG, "io", "buffer allocated");
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* INFO message should also be dropped */
    ret = rw_log_write(logger, RW_LOG_INFO, "io", "listening on port 443");
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Flush should return empty — nothing was logged */
    char buf[4096];
    ssize_t n = rw_log_flush(logger, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(0, n);

    /* WARN message should be accepted */
    ret = rw_log_write(logger, RW_LOG_WARN, "io", "queue nearly full");
    TEST_ASSERT_EQUAL_INT(0, ret);

    n = rw_log_flush(logger, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_log_init_returns_zero);
    RUN_TEST(test_log_write_info_message);
    RUN_TEST(test_log_write_with_structured_data);
    RUN_TEST(test_log_flush_reads_buffer);
    RUN_TEST(test_log_destroy_null_safe);
    RUN_TEST(test_log_severity_levels);
    return UNITY_END();
}
