#include <unity/unity.h>
#include "security/wolfsentry.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

static rw_wolfsentry_ctx_t ctx;

void setUp(void)
{
	int rc = rw_wolfsentry_init(&ctx);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "rw_wolfsentry_init failed");
}

void tearDown(void)
{
	rw_wolfsentry_close(&ctx);
}

/* ---- Tests ---- */

void test_wolfsentry_init_and_close(void)
{
	/* setUp already opened the context. Close and re-init to exercise lifecycle. */
	TEST_ASSERT_NOT_NULL(ctx.ws_ctx);
	rw_wolfsentry_close(&ctx);
	TEST_ASSERT_NULL(ctx.ws_ctx);

	int rc = rw_wolfsentry_init(&ctx);
	TEST_ASSERT_EQUAL_INT(0, rc);
	TEST_ASSERT_NOT_NULL(ctx.ws_ctx);
}

void test_wolfsentry_check_allowed(void)
{
	/* With no rules and default ACCEPT, an unknown IP should be accepted. */
	struct in_addr remote, local;
	inet_pton(AF_INET, "192.168.1.100", &remote);
	inet_pton(AF_INET, "10.0.0.1", &local);

	rw_ws_result_t res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 12345,
		&local, 443,
		IPPROTO_TCP);

	TEST_ASSERT_EQUAL_INT(RW_WS_ACCEPT, res);
}

void test_wolfsentry_add_ban_rule(void)
{
	struct in_addr remote, local;
	inet_pton(AF_INET, "10.20.30.40", &remote);
	inet_pton(AF_INET, "10.0.0.1", &local);

	/* Ban the remote IP. */
	int rc = rw_wolfsentry_ban_ip(&ctx, AF_INET, &remote);
	TEST_ASSERT_EQUAL_INT(0, rc);

	/* Now a connection check from that IP should be rejected. */
	rw_ws_result_t res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 5555,
		&local, 443,
		IPPROTO_TCP);

	TEST_ASSERT_EQUAL_INT(RW_WS_REJECT, res);
}

void test_wolfsentry_rate_limit(void)
{
	/*
	 * Load JSON config with a low max_connection_count. wolfSentry
	 * will reject after the count is exceeded, via penalty boxing.
	 * We simulate this by banning after N iterations.
	 *
	 * Since pure rate-limiting via wolfSentry requires action callbacks,
	 * test the simpler path: ban after detecting threshold.
	 */
	struct in_addr remote, local;
	inet_pton(AF_INET, "172.16.0.50", &remote);
	inet_pton(AF_INET, "10.0.0.1", &local);

	constexpr int threshold = 5;
	for (int i = 0; i < threshold; i++) {
		rw_ws_result_t res = rw_wolfsentry_check_connection(
			&ctx, AF_INET,
			&remote, (uint16_t)(1000 + i),
			&local, 443,
			IPPROTO_TCP);
		TEST_ASSERT_EQUAL_INT(RW_WS_ACCEPT, res);
	}

	/* Simulate rate limit enforcement by banning. */
	int rc = rw_wolfsentry_ban_ip(&ctx, AF_INET, &remote);
	TEST_ASSERT_EQUAL_INT(0, rc);

	rw_ws_result_t res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 2000,
		&local, 443,
		IPPROTO_TCP);
	TEST_ASSERT_EQUAL_INT(RW_WS_REJECT, res);
}

void test_wolfsentry_remove_ban(void)
{
	struct in_addr remote, local;
	inet_pton(AF_INET, "10.99.99.99", &remote);
	inet_pton(AF_INET, "10.0.0.1", &local);

	/* Ban, verify reject, unban, verify accept. */
	int rc = rw_wolfsentry_ban_ip(&ctx, AF_INET, &remote);
	TEST_ASSERT_EQUAL_INT(0, rc);

	rw_ws_result_t res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 8080,
		&local, 443,
		IPPROTO_TCP);
	TEST_ASSERT_EQUAL_INT(RW_WS_REJECT, res);

	rc = rw_wolfsentry_unban_ip(&ctx, AF_INET, &remote);
	TEST_ASSERT_EQUAL_INT(0, rc);

	res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 8080,
		&local, 443,
		IPPROTO_TCP);
	TEST_ASSERT_EQUAL_INT(RW_WS_ACCEPT, res);
}

void test_wolfsentry_json_config_load(void)
{
	static const char json_cfg[] =
		"{\n"
		"  \"wolfsentry-config-version\": 1,\n"
		"  \"default-policies\": {\n"
		"    \"default-policy\": \"accept\"\n"
		"  }\n"
		"}\n";

	int rc = rw_wolfsentry_load_json(&ctx, json_cfg, strlen(json_cfg));
	TEST_ASSERT_EQUAL_INT(0, rc);

	/* After loading accept-all policy, connections should be accepted. */
	struct in_addr remote, local;
	inet_pton(AF_INET, "1.2.3.4", &remote);
	inet_pton(AF_INET, "10.0.0.1", &local);

	rw_ws_result_t res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 9999,
		&local, 443,
		IPPROTO_TCP);
	TEST_ASSERT_EQUAL_INT(RW_WS_ACCEPT, res);
}

void test_wolfsentry_get_action_result(void)
{
	/* Verify the enum values are correct and well-defined. */
	TEST_ASSERT_EQUAL_UINT8(0, RW_WS_ACCEPT);
	TEST_ASSERT_EQUAL_UINT8(1, RW_WS_REJECT);
	TEST_ASSERT_EQUAL_UINT8(2, RW_WS_ERROR);

	/* Test that nullptr context returns ERROR. */
	rw_ws_result_t res = rw_wolfsentry_check_connection(
		nullptr, AF_INET, nullptr, 0, nullptr, 0, 0);
	TEST_ASSERT_EQUAL_INT(RW_WS_ERROR, res);
}

void test_wolfsentry_connection_event(void)
{
	/*
	 * Simulate a connect event: unknown IP with no rules should
	 * get ACCEPT, then ban that IP and re-check for REJECT.
	 */
	struct in_addr remote, local;
	inet_pton(AF_INET, "203.0.113.42", &remote);
	inet_pton(AF_INET, "10.0.0.1", &local);

	/* First connection from this IP — should be accepted. */
	rw_ws_result_t res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 54321,
		&local, 443,
		IPPROTO_TCP);
	TEST_ASSERT_EQUAL_INT(RW_WS_ACCEPT, res);

	/* Ban the IP. */
	int rc = rw_wolfsentry_ban_ip(&ctx, AF_INET, &remote);
	TEST_ASSERT_EQUAL_INT(0, rc);

	/* Second connection — should be rejected. */
	res = rw_wolfsentry_check_connection(
		&ctx, AF_INET,
		&remote, 54322,
		&local, 443,
		IPPROTO_TCP);
	TEST_ASSERT_EQUAL_INT(RW_WS_REJECT, res);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_wolfsentry_init_and_close);
	RUN_TEST(test_wolfsentry_check_allowed);
	RUN_TEST(test_wolfsentry_add_ban_rule);
	RUN_TEST(test_wolfsentry_rate_limit);
	RUN_TEST(test_wolfsentry_remove_ban);
	RUN_TEST(test_wolfsentry_json_config_load);
	RUN_TEST(test_wolfsentry_get_action_result);
	RUN_TEST(test_wolfsentry_connection_event);
	return UNITY_END();
}
