/**
 * @file test_firewall.c
 * @brief Unit tests for nftables per-user firewall chains.
 */

#include <unity/unity.h>
#include "security/firewall.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setUp(void) {}
void tearDown(void) {}

/* ---- Test helpers ---- */

static rw_fw_session_t make_ipv4_session(void)
{
	rw_fw_session_t s = {0};
	s.af = AF_INET;
	inet_pton(AF_INET, "10.0.1.42", &s.assigned_ipv4);
	snprintf(s.username, sizeof(s.username), "alice");
	return s;
}

static rw_fw_session_t make_ipv6_session(void)
{
	rw_fw_session_t s = {0};
	s.af = AF_INET6;
	inet_pton(AF_INET6, "fd00::1:2:3:4", &s.assigned_ipv6);
	snprintf(s.username, sizeof(s.username), "bob");
	return s;
}

/* ---- Tests ---- */

void test_firewall_chain_name_format(void)
{
	rw_fw_session_t s = make_ipv4_session();
	char name[RW_FW_CHAIN_NAME_MAX];

	int ret = rw_fw_chain_name(&s, name, sizeof(name));
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Must start with "rw_" */
	TEST_ASSERT_EQUAL_STRING_LEN("rw_", name, 3);

	/* Must contain the username */
	TEST_ASSERT_NOT_NULL(strstr(name, "alice"));

	/* Must contain hex representation of 10.0.1.42 */
	TEST_ASSERT_NOT_NULL(strstr(name, "0a00012a"));

	/* IPv6 variant */
	rw_fw_session_t s6 = make_ipv6_session();
	ret = rw_fw_chain_name(&s6, name, sizeof(name));
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_STRING_LEN("rw_", name, 3);
	TEST_ASSERT_NOT_NULL(strstr(name, "bob"));

	/* Null checks */
	ret = rw_fw_chain_name(nullptr, name, sizeof(name));
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

	ret = rw_fw_chain_name(&s, nullptr, sizeof(name));
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

	ret = rw_fw_chain_name(&s, name, 0);
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

	/* Unsupported address family */
	rw_fw_session_t bad = s;
	bad.af = 999;
	ret = rw_fw_chain_name(&bad, name, sizeof(name));
	TEST_ASSERT_EQUAL_INT(-EAFNOSUPPORT, ret);
}

void test_firewall_rule_build_ipv4(void)
{
	rw_fw_session_t s = make_ipv4_session();
	void *buf = nullptr;
	size_t len = 0;

	int ret = rw_fw_build_create_batch(&s, &buf, &len);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_NOT_NULL(buf);
	TEST_ASSERT_GREATER_THAN(0, (int)len);

	free(buf);
}

void test_firewall_rule_build_ipv6(void)
{
	rw_fw_session_t s = make_ipv6_session();
	void *buf = nullptr;
	size_t len = 0;

	int ret = rw_fw_build_create_batch(&s, &buf, &len);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_NOT_NULL(buf);
	TEST_ASSERT_GREATER_THAN(0, (int)len);

	free(buf);
}

void test_firewall_batch_build(void)
{
	rw_fw_session_t s = make_ipv4_session();
	void *buf = nullptr;
	size_t len = 0;

	/* Create batch must produce a non-trivial buffer.
	 * Minimum: begin + chain + rule + end = 4 netlink messages. */
	int ret = rw_fw_build_create_batch(&s, &buf, &len);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_NOT_NULL(buf);

	/* Each nlmsghdr is at least 16 bytes; 4 messages = at least 64. */
	TEST_ASSERT_GREATER_THAN(64, (int)len);

	free(buf);

	/* Null parameter checks */
	ret = rw_fw_build_create_batch(nullptr, &buf, &len);
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

	ret = rw_fw_build_create_batch(&s, nullptr, &len);
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

	ret = rw_fw_build_create_batch(&s, &buf, nullptr);
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_firewall_chain_create_requires_root(void)
{
	if (geteuid() == 0)
		TEST_IGNORE_MESSAGE("running as root — cannot test EPERM");

	rw_fw_session_t s = make_ipv4_session();
	int ret = rw_fw_session_create(&s);
	TEST_ASSERT_EQUAL_INT(-EPERM, ret);
}

void test_firewall_cleanup_on_disconnect(void)
{
	rw_fw_session_t s = make_ipv4_session();
	void *buf = nullptr;
	size_t len = 0;

	/* Build destroy batch — must produce valid netlink messages
	 * (begin + delrule + delchain + end = 4 messages). */
	int ret = rw_fw_build_destroy_batch(&s, &buf, &len);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_NOT_NULL(buf);
	TEST_ASSERT_GREATER_THAN(64, (int)len);

	/* The destroy batch must be different from the create batch
	 * (different message types). */
	void *create_buf = nullptr;
	size_t create_len = 0;
	ret = rw_fw_build_create_batch(&s, &create_buf, &create_len);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* They should not be identical (different NFT_MSG types). */
	if (len == create_len) {
		TEST_ASSERT_FALSE(memcmp(buf, create_buf, len) == 0);
	}

	free(buf);
	free(create_buf);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_firewall_chain_name_format);
	RUN_TEST(test_firewall_rule_build_ipv4);
	RUN_TEST(test_firewall_rule_build_ipv6);
	RUN_TEST(test_firewall_batch_build);
	RUN_TEST(test_firewall_chain_create_requires_root);
	RUN_TEST(test_firewall_cleanup_on_disconnect);
	return UNITY_END();
}
