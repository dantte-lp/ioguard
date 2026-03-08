#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "network/dtls_keying.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_hex_encode_basic(void)
{
    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char hex[16];
    int ret = rw_dtls_hex_encode(data, sizeof(data), hex, sizeof(hex));
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("deadbeef", hex);
}

void test_hex_decode_basic(void)
{
    const char *hex = "deadbeef";
    uint8_t out[4];
    int ret = rw_dtls_hex_decode(hex, strlen(hex), out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(4, ret);
    TEST_ASSERT_EQUAL_UINT8(0xDE, out[0]);
    TEST_ASSERT_EQUAL_UINT8(0xAD, out[1]);
    TEST_ASSERT_EQUAL_UINT8(0xBE, out[2]);
    TEST_ASSERT_EQUAL_UINT8(0xEF, out[3]);
}

void test_hex_roundtrip(void)
{
    const uint8_t original[RW_DTLS_MASTER_SECRET_LEN] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
        0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x2A, 0x2B, 0x2C, 0x2D,
    };
    char hex[RW_DTLS_MASTER_SECRET_HEX_LEN + 1];
    uint8_t decoded[RW_DTLS_MASTER_SECRET_LEN];

    int ret = rw_dtls_hex_encode(original, sizeof(original), hex, sizeof(hex));
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = rw_dtls_hex_decode(hex, strlen(hex), decoded, sizeof(decoded));
    TEST_ASSERT_EQUAL_INT((int)sizeof(original), ret);
    TEST_ASSERT_EQUAL_MEMORY(original, decoded, sizeof(original));
}

void test_hex_decode_invalid_chars(void)
{
    uint8_t out[4];
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_hex_decode("ZZZZ", 4, out, sizeof(out)));
}

void test_hex_decode_odd_length(void)
{
    uint8_t out[4];
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_hex_decode("abc", 3, out, sizeof(out)));
}

void test_master_secret_clear(void)
{
    rw_dtls_master_secret_t ms;
    memset(ms.secret, 0xFF, sizeof(ms.secret));
    memcpy(ms.hex, "abcdef", 6);
    ms.valid = true;

    rw_dtls_master_secret_clear(&ms);

    uint8_t zero[RW_DTLS_MASTER_SECRET_LEN] = {0};
    TEST_ASSERT_EQUAL_MEMORY(zero, ms.secret, sizeof(zero));
    TEST_ASSERT_FALSE(ms.valid);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hex_encode_basic);
    RUN_TEST(test_hex_decode_basic);
    RUN_TEST(test_hex_roundtrip);
    RUN_TEST(test_hex_decode_invalid_chars);
    RUN_TEST(test_hex_decode_odd_length);
    RUN_TEST(test_master_secret_clear);
    return UNITY_END();
}
