#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "network/dtls_headers.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_build_headers_basic(void)
{
    char buf[512];
    int ret = rw_dtls_build_headers(buf, sizeof(buf), "deadbeef", "AES256-SHA", nullptr);
    TEST_ASSERT_GREATER_THAN(0, ret);
    TEST_ASSERT_NOT_NULL(strstr(buf, "X-DTLS-Master-Secret: deadbeef"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "X-DTLS-CipherSuite: AES256-SHA"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "X-DTLS12-CipherSuite: AES256-SHA"));
}

void test_build_headers_with_encoding(void)
{
    char buf[512];
    int ret = rw_dtls_build_headers(buf, sizeof(buf), "aabbccdd", "AES128-SHA", "lzs,deflate");
    TEST_ASSERT_GREATER_THAN(0, ret);
    TEST_ASSERT_NOT_NULL(strstr(buf, "X-DTLS-Accept-Encoding: lzs"));
}

void test_build_headers_null_inputs(void)
{
    char buf[64];
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_build_headers(nullptr, 64, "aa", "AES", nullptr));
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_build_headers(buf, 64, nullptr, "AES", nullptr));
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_build_headers(buf, 64, "aa", nullptr, nullptr));
}

void test_build_headers_buffer_too_small(void)
{
    char buf[10]; /* way too small */
    int ret = rw_dtls_build_headers(buf, sizeof(buf), "deadbeef", "AES256-SHA", nullptr);
    TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);
}

void test_parse_accept_encoding_lzs(void)
{
    TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZS, rw_dtls_parse_accept_encoding("lzs,deflate"));
}

void test_parse_accept_encoding_lz4(void)
{
    TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZ4, rw_dtls_parse_accept_encoding("lz4"));
}

void test_parse_accept_encoding_none(void)
{
    TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, rw_dtls_parse_accept_encoding("deflate"));
    TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, rw_dtls_parse_accept_encoding(nullptr));
}

void test_build_headers_no_encoding(void)
{
    char buf[512];
    int ret = rw_dtls_build_headers(buf, sizeof(buf), "1234", "AES128", "deflate");
    TEST_ASSERT_GREATER_THAN(0, ret);
    TEST_ASSERT_NULL(strstr(buf, "X-DTLS-Accept-Encoding"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_build_headers_basic);
    RUN_TEST(test_build_headers_with_encoding);
    RUN_TEST(test_build_headers_null_inputs);
    RUN_TEST(test_build_headers_buffer_too_small);
    RUN_TEST(test_parse_accept_encoding_lzs);
    RUN_TEST(test_parse_accept_encoding_lz4);
    RUN_TEST(test_parse_accept_encoding_none);
    RUN_TEST(test_build_headers_no_encoding);
    return UNITY_END();
}
