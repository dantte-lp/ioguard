#include <unity/unity.h>
#include "network/channel.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_channel_init_cstp_only(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_CSTP_ONLY, ctx.state);
	TEST_ASSERT_TRUE(ctx.cstp_active);
	TEST_ASSERT_FALSE(ctx.dtls_active);
	TEST_ASSERT_EQUAL_UINT32(0, ctx.dtls_fail_count);
}

void test_channel_dtls_up(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	rw_channel_state_t s = rw_channel_on_dtls_up(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_PRIMARY, s);
	TEST_ASSERT_TRUE(ctx.dtls_active);
	TEST_ASSERT_TRUE(ctx.cstp_active); /* CSTP always active */
}

void test_channel_dtls_down_fallback(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	(void)rw_channel_on_dtls_up(&ctx);
	rw_channel_state_t s = rw_channel_on_dtls_down(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_FALLBACK, s);
	TEST_ASSERT_FALSE(ctx.dtls_active);
	TEST_ASSERT_TRUE(ctx.cstp_active);
}

void test_channel_dtls_down_max_fails(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	(void)rw_channel_on_dtls_up(&ctx);
	/* Fail 3 times (default max) */
	(void)rw_channel_on_dtls_down(&ctx);
	(void)rw_channel_on_dtls_down(&ctx);
	rw_channel_state_t s = rw_channel_on_dtls_down(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_CSTP_ONLY, s);
	TEST_ASSERT_FALSE(ctx.dtls_active);
}

void test_channel_dtls_recovery(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	(void)rw_channel_on_dtls_up(&ctx);
	(void)rw_channel_on_dtls_down(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_FALLBACK, ctx.state);

	rw_channel_state_t s = rw_channel_on_dtls_recovery(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_CHANNEL_DTLS_PRIMARY, s);
	TEST_ASSERT_TRUE(ctx.dtls_active);
	TEST_ASSERT_EQUAL_UINT32(0, ctx.dtls_fail_count);
}

void test_channel_use_dtls_primary(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	TEST_ASSERT_FALSE(rw_channel_use_dtls(&ctx)); /* CSTP_ONLY */

	(void)rw_channel_on_dtls_up(&ctx);
	TEST_ASSERT_TRUE(rw_channel_use_dtls(&ctx)); /* DTLS_PRIMARY */
}

void test_channel_use_dtls_fallback(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	(void)rw_channel_on_dtls_up(&ctx);
	(void)rw_channel_on_dtls_down(&ctx);
	TEST_ASSERT_FALSE(rw_channel_use_dtls(&ctx)); /* FALLBACK = use CSTP */
}

void test_channel_cstp_always_active(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	TEST_ASSERT_TRUE(ctx.cstp_active);
	(void)rw_channel_on_dtls_up(&ctx);
	TEST_ASSERT_TRUE(ctx.cstp_active);
	(void)rw_channel_on_dtls_down(&ctx);
	TEST_ASSERT_TRUE(ctx.cstp_active);
}

void test_channel_compress_type(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, ctx.compress_type);
	ctx.compress_type = RW_COMPRESS_LZS;
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZS, ctx.compress_type);
}

void test_channel_state_str(void)
{
	rw_channel_ctx_t ctx;
	rw_channel_init(&ctx);
	const char *s = rw_channel_state_str(&ctx);
	TEST_ASSERT_NOT_NULL(s);
	TEST_ASSERT_TRUE(strlen(s) > 0);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_channel_init_cstp_only);
	RUN_TEST(test_channel_dtls_up);
	RUN_TEST(test_channel_dtls_down_fallback);
	RUN_TEST(test_channel_dtls_down_max_fails);
	RUN_TEST(test_channel_dtls_recovery);
	RUN_TEST(test_channel_use_dtls_primary);
	RUN_TEST(test_channel_use_dtls_fallback);
	RUN_TEST(test_channel_cstp_always_active);
	RUN_TEST(test_channel_compress_type);
	RUN_TEST(test_channel_state_str);
	return UNITY_END();
}
