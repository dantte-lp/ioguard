#include <string.h>
#include <time.h>
#include <unity/unity.h>
#include "network/dpd.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_dpd_init_defaults(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 0, 0);

    TEST_ASSERT_EQUAL_UINT32(RW_DPD_DEFAULT_INTERVAL_S, ctx.interval_s);
    TEST_ASSERT_EQUAL_UINT32(30, ctx.interval_s);
    TEST_ASSERT_EQUAL_UINT32(RW_DPD_DEFAULT_MAX_RETRIES, ctx.max_retries);
    TEST_ASSERT_EQUAL_UINT32(3, ctx.max_retries);
}

void test_dpd_state_initial_idle(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 5);

    TEST_ASSERT_EQUAL_UINT8(RW_DPD_IDLE, ctx.state);
}

void test_dpd_timeout_idle_to_pending(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    rw_dpd_state_t st = rw_dpd_on_timeout(&ctx);

    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, st);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, ctx.state);
    TEST_ASSERT_EQUAL_UINT32(1, ctx.retry_count);
    TEST_ASSERT_TRUE(ctx.need_send_request);
    TEST_ASSERT_EQUAL_UINT16(1, ctx.sequence);
}

void test_dpd_response_pending_to_idle(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    /* move to PENDING first */
    (void)rw_dpd_on_timeout(&ctx);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, ctx.state);

    rw_dpd_state_t st = rw_dpd_on_response(&ctx, ctx.sequence);

    TEST_ASSERT_EQUAL_UINT8(RW_DPD_IDLE, st);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_IDLE, ctx.state);
    TEST_ASSERT_EQUAL_UINT32(0, ctx.retry_count);
}

void test_dpd_timeout_increments_retry(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    /* IDLE -> PENDING (retry=1) */
    (void)rw_dpd_on_timeout(&ctx);
    TEST_ASSERT_EQUAL_UINT32(1, ctx.retry_count);

    /* PENDING -> retry=2 */
    ctx.need_send_request = false;
    rw_dpd_state_t st = rw_dpd_on_timeout(&ctx);

    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, st);
    TEST_ASSERT_EQUAL_UINT32(2, ctx.retry_count);
    TEST_ASSERT_TRUE(ctx.need_send_request);
}

void test_dpd_max_retries_to_dead(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    /* 1st timeout: IDLE -> PENDING, retry=1 */
    rw_dpd_state_t st = rw_dpd_on_timeout(&ctx);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, st);
    TEST_ASSERT_EQUAL_UINT32(1, ctx.retry_count);

    /* 2nd timeout: retry=2 */
    st = rw_dpd_on_timeout(&ctx);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, st);
    TEST_ASSERT_EQUAL_UINT32(2, ctx.retry_count);

    /* 3rd timeout: retry=3 (== max, still PENDING) */
    st = rw_dpd_on_timeout(&ctx);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, st);
    TEST_ASSERT_EQUAL_UINT32(3, ctx.retry_count);

    /* 4th timeout: retry=4 > max_retries=3 -> DEAD */
    st = rw_dpd_on_timeout(&ctx);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_DEAD, st);
    TEST_ASSERT_EQUAL_UINT32(4, ctx.retry_count);
}

void test_dpd_request_sets_response_flag(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    TEST_ASSERT_FALSE(ctx.need_send_response);

    rw_dpd_state_t st = rw_dpd_on_request(&ctx, 42);

    TEST_ASSERT_EQUAL_UINT8(RW_DPD_IDLE, st);
    TEST_ASSERT_TRUE(ctx.need_send_response);
}

void test_dpd_channel_initial_cstp_only(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_CSTP_ONLY, ctx.channel);
}

void test_dpd_reset_clears_state(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 10, 3);

    /* drive into PENDING with flags set */
    (void)rw_dpd_on_timeout(&ctx);
    (void)rw_dpd_on_request(&ctx, 1);
    TEST_ASSERT_EQUAL_UINT8(RW_DPD_PENDING, ctx.state);
    TEST_ASSERT_TRUE(ctx.need_send_request);
    TEST_ASSERT_TRUE(ctx.need_send_response);
    TEST_ASSERT_TRUE(ctx.retry_count > 0);

    rw_dpd_reset(&ctx);

    TEST_ASSERT_EQUAL_UINT8(RW_DPD_IDLE, ctx.state);
    TEST_ASSERT_EQUAL_UINT32(0, ctx.retry_count);
    TEST_ASSERT_FALSE(ctx.need_send_request);
    TEST_ASSERT_FALSE(ctx.need_send_response);
}

void test_dpd_should_probe_interval(void)
{
    rw_dpd_ctx_t ctx;
    rw_dpd_init(&ctx, 30, 3);

    time_t now = time(nullptr);

    /* interval elapsed: last_send was 31s ago */
    ctx.last_send = now - 31;
    TEST_ASSERT_TRUE(rw_dpd_should_probe(&ctx, now));

    /* interval not elapsed: last_send was 10s ago */
    ctx.last_send = now - 10;
    TEST_ASSERT_FALSE(rw_dpd_should_probe(&ctx, now));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_dpd_init_defaults);
    RUN_TEST(test_dpd_state_initial_idle);
    RUN_TEST(test_dpd_timeout_idle_to_pending);
    RUN_TEST(test_dpd_response_pending_to_idle);
    RUN_TEST(test_dpd_timeout_increments_retry);
    RUN_TEST(test_dpd_max_retries_to_dead);
    RUN_TEST(test_dpd_request_sets_response_flag);
    RUN_TEST(test_dpd_channel_initial_cstp_only);
    RUN_TEST(test_dpd_reset_clears_state);
    RUN_TEST(test_dpd_should_probe_interval);
    return UNITY_END();
}
