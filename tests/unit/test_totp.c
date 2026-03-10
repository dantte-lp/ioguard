#include <errno.h>
#include <stdbool.h>
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

void test_totp_generate_rfc6238_time59(void)
{
    /* Time=59 -> counter = 59/30 = 1 (integer division) */
    uint8_t secret[] = "12345678901234567890";
    uint32_t code = 0;
    int ret = rw_totp_generate(secret, 20, 1, &code);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(287082, code);
}

void test_totp_generate_rfc6238_time1111111109(void)
{
    /* Time=1111111109 -> counter = 37037036 */
    uint8_t secret[] = "12345678901234567890";
    uint32_t code = 0;
    int ret = rw_totp_generate(secret, 20, 37037036, &code);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(81804, code);
}

void test_totp_generate_rfc6238_time1234567890(void)
{
    /* Time=1234567890 -> counter = 41152263 */
    uint8_t secret[] = "12345678901234567890";
    uint32_t code = 0;
    int ret = rw_totp_generate(secret, 20, 41152263, &code);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(5924, code);
}

void test_totp_generate_rfc6238_time2000000000(void)
{
    /* Time=2000000000 -> counter = 66666666 */
    uint8_t secret[] = "12345678901234567890";
    uint32_t code = 0;
    int ret = rw_totp_generate(secret, 20, 66666666, &code);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(279037, code);
}

void test_totp_generate_null_params(void)
{
    uint32_t code = 0;
    TEST_ASSERT_LESS_THAN_INT(0, rw_totp_generate(nullptr, 0, 1, &code));
    uint8_t s[20] = {0};
    TEST_ASSERT_LESS_THAN_INT(0, rw_totp_generate(s, 20, 1, nullptr));
}

/* --- Validation tests (Task 3) --- */

void test_totp_validate_exact_match(void)
{
    uint8_t secret[] = "12345678901234567890";
    /* counter=1 at time=30..59, code=287082 */
    int ret = rw_totp_validate(secret, 20, 287082, 59, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_totp_validate_wrong_code(void)
{
    uint8_t secret[] = "12345678901234567890";
    int ret = rw_totp_validate(secret, 20, 999999, 59, 0);
    TEST_ASSERT_EQUAL_INT(-EACCES, ret);
}

void test_totp_validate_window_drift(void)
{
    uint8_t secret[] = "12345678901234567890";
    /* Code for counter=1 should match at time=60 (counter=2) with window=1 */
    int ret = rw_totp_validate(secret, 20, 287082, 60, 1);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_totp_validate_window_too_far(void)
{
    uint8_t secret[] = "12345678901234567890";
    /* Code for counter=1 should NOT match at time=120 (counter=4) with window=1 */
    int ret = rw_totp_validate(secret, 20, 287082, 120, 1);
    TEST_ASSERT_EQUAL_INT(-EACCES, ret);
}

/* --- Provisioning tests (Task 4) --- */

void test_totp_generate_secret_produces_bytes(void)
{
    uint8_t secret[RW_TOTP_SECRET_SIZE];
    memset(secret, 0, sizeof(secret));
    int ret = rw_totp_generate_secret(secret, sizeof(secret));
    TEST_ASSERT_EQUAL_INT(0, ret);
    /* Secret should not be all zeros after generation */
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(secret); i++) {
        if (secret[i] != 0) {
            all_zero = false;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zero);
}

void test_totp_generate_secret_roundtrip(void)
{
    /* Generate secret, build URI, verify URI contains expected parts */
    uint8_t secret[RW_TOTP_SECRET_SIZE];
    int ret = rw_totp_generate_secret(secret, sizeof(secret));
    TEST_ASSERT_EQUAL_INT(0, ret);

    char uri[512];
    ssize_t ulen = rw_totp_build_uri(secret, sizeof(secret), "ringwall", "alice", uri, sizeof(uri));
    TEST_ASSERT_GREATER_THAN(0, (int)ulen);
    TEST_ASSERT_NOT_NULL(strstr(uri, "otpauth://totp/ringwall:alice"));
    TEST_ASSERT_NOT_NULL(strstr(uri, "digits=6"));
    TEST_ASSERT_NOT_NULL(strstr(uri, "period=30"));
}

void test_totp_build_uri_buffer_too_small(void)
{
    uint8_t secret[RW_TOTP_SECRET_SIZE] = {0x01};
    char uri[10];
    ssize_t ret = rw_totp_build_uri(secret, sizeof(secret), "ringwall", "alice", uri, sizeof(uri));
    TEST_ASSERT_LESS_THAN_INT(0, (int)ret);
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
    RUN_TEST(test_totp_generate_rfc6238_time59);
    RUN_TEST(test_totp_generate_rfc6238_time1111111109);
    RUN_TEST(test_totp_generate_rfc6238_time1234567890);
    RUN_TEST(test_totp_generate_rfc6238_time2000000000);
    RUN_TEST(test_totp_generate_null_params);
    RUN_TEST(test_totp_validate_exact_match);
    RUN_TEST(test_totp_validate_wrong_code);
    RUN_TEST(test_totp_validate_window_drift);
    RUN_TEST(test_totp_validate_window_too_far);
    RUN_TEST(test_totp_generate_secret_produces_bytes);
    RUN_TEST(test_totp_generate_secret_roundtrip);
    RUN_TEST(test_totp_build_uri_buffer_too_small);
    return UNITY_END();
}
