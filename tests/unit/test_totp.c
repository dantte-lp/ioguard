#include <string.h>
#include <unity/unity.h>
#include "auth/totp.h"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_totp_base32_decode_empty(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_totp_base32_decode_f(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("MY======", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(1, ret);
	TEST_ASSERT_EQUAL_UINT8('f', buf[0]);
}

void test_totp_base32_decode_fo(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("MZXQ====", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(2, ret);
	TEST_ASSERT_EQUAL_UINT8('f', buf[0]);
	TEST_ASSERT_EQUAL_UINT8('o', buf[1]);
}

void test_totp_base32_decode_foobar(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("MZXW6YTBOI======", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(6, ret);
	TEST_ASSERT_EQUAL_STRING_LEN("foobar", (char *)buf, 6);
}

void test_totp_base32_decode_no_padding(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("MZXW6YTBOI", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(6, ret);
	TEST_ASSERT_EQUAL_STRING_LEN("foobar", (char *)buf, 6);
}

void test_totp_base32_decode_lowercase(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("mzxw6ytboi", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(6, ret);
	TEST_ASSERT_EQUAL_STRING_LEN("foobar", (char *)buf, 6);
}

void test_totp_base32_decode_invalid_char(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("MZ!W6===", buf, sizeof(buf));
	TEST_ASSERT_TRUE(ret < 0);
}

void test_totp_base32_decode_buffer_too_small(void)
{
	uint8_t buf[1];
	ssize_t ret = rw_base32_decode("MZXW6YTBOI", buf, sizeof(buf));
	TEST_ASSERT_TRUE(ret < 0);
}

void test_totp_base32_decode_20byte_secret(void)
{
	uint8_t buf[32];
	ssize_t ret = rw_base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", buf, sizeof(buf));
	TEST_ASSERT_EQUAL_INT(20, ret);
	TEST_ASSERT_EQUAL_STRING_LEN("12345678901234567890", (char *)buf, 20);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_totp_base32_decode_empty);
	RUN_TEST(test_totp_base32_decode_f);
	RUN_TEST(test_totp_base32_decode_fo);
	RUN_TEST(test_totp_base32_decode_foobar);
	RUN_TEST(test_totp_base32_decode_no_padding);
	RUN_TEST(test_totp_base32_decode_lowercase);
	RUN_TEST(test_totp_base32_decode_invalid_char);
	RUN_TEST(test_totp_base32_decode_buffer_too_small);
	RUN_TEST(test_totp_base32_decode_20byte_secret);
	return UNITY_END();
}
