#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "network/compress.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_compress_init_none(void)
{
    rw_compress_ctx_t ctx;
    int ret = rw_compress_init(&ctx, IOG_COMPRESS_NONE);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_NONE, ctx.type);
    rw_compress_destroy(&ctx);
}

void test_compress_init_null(void)
{
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_compress_init(nullptr, IOG_COMPRESS_NONE));
}

void test_compress_none_passthrough(void)
{
    rw_compress_ctx_t ctx;
    (void)rw_compress_init(&ctx, IOG_COMPRESS_NONE);

    const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t out[64];

    int ret = rw_compress(&ctx, data, sizeof(data), out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(4, ret);
    TEST_ASSERT_EQUAL_MEMORY(data, out, sizeof(data));

    rw_compress_destroy(&ctx);
}

void test_decompress_none_passthrough(void)
{
    rw_compress_ctx_t ctx;
    (void)rw_compress_init(&ctx, IOG_COMPRESS_NONE);

    const uint8_t data[] = {0xCA, 0xFE};
    uint8_t out[64];

    int ret = rw_decompress(&ctx, data, sizeof(data), out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(2, ret);
    TEST_ASSERT_EQUAL_MEMORY(data, out, sizeof(data));

    rw_compress_destroy(&ctx);
}

void test_compress_output_too_small(void)
{
    rw_compress_ctx_t ctx;
    (void)rw_compress_init(&ctx, IOG_COMPRESS_NONE);

    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t out[2];

    int ret = rw_compress(&ctx, data, sizeof(data), out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);

    rw_compress_destroy(&ctx);
}

void test_compress_input_too_large(void)
{
    rw_compress_ctx_t ctx;
    (void)rw_compress_init(&ctx, IOG_COMPRESS_NONE);

    uint8_t out[64];
    int ret = rw_compress(&ctx, out, IOG_COMPRESS_MAX_INPUT + 1, out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    rw_compress_destroy(&ctx);
}

void test_compress_type_name(void)
{
    TEST_ASSERT_EQUAL_STRING("none", rw_compress_type_name(IOG_COMPRESS_NONE));
    TEST_ASSERT_EQUAL_STRING("lz4", rw_compress_type_name(IOG_COMPRESS_LZ4));
    TEST_ASSERT_EQUAL_STRING("lzs", rw_compress_type_name(IOG_COMPRESS_LZS));
}

void test_compress_negotiate(void)
{
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_LZS, rw_compress_negotiate("lzs,deflate"));
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_LZ4, rw_compress_negotiate("lz4"));
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_NONE, rw_compress_negotiate("deflate"));
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_NONE, rw_compress_negotiate(nullptr));
}

void test_compress_destroy_null(void)
{
    rw_compress_destroy(nullptr);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_compress_init_none);
    RUN_TEST(test_compress_init_null);
    RUN_TEST(test_compress_none_passthrough);
    RUN_TEST(test_decompress_none_passthrough);
    RUN_TEST(test_compress_output_too_small);
    RUN_TEST(test_compress_input_too_large);
    RUN_TEST(test_compress_type_name);
    RUN_TEST(test_compress_negotiate);
    RUN_TEST(test_compress_destroy_null);
    return UNITY_END();
}
