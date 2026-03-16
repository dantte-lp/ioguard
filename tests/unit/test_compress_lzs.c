#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "network/compress_lzs.h"
#include "network/cstp.h"

static iog_lzs_ctx_t ctx;

void setUp(void)
{
    iog_lzs_init(&ctx);
}
void tearDown(void)
{
}

void test_lzs_init(void)
{
    TEST_ASSERT_EQUAL_size_t(0, ctx.window_pos);
}

void test_lzs_compress_empty(void)
{
    uint8_t out[16];
    int ret = iog_lzs_compress(&ctx, (const uint8_t *)"", 0, out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, ret); /* end marker only */
}

void test_lzs_compress_short(void)
{
    const uint8_t data[] = "Hello";
    uint8_t compressed[64];
    int clen = iog_lzs_compress(&ctx, data, 5, compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);
}

void test_lzs_roundtrip_short(void)
{
    const uint8_t data[] = "Hello, World!";
    uint8_t compressed[128];
    uint8_t decompressed[128];

    iog_lzs_ctx_t enc_ctx, dec_ctx;
    iog_lzs_init(&enc_ctx);
    iog_lzs_init(&dec_ctx);

    int clen = iog_lzs_compress(&enc_ctx, data, 13, compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);

    int dlen =
        iog_lzs_decompress(&dec_ctx, compressed, (size_t)clen, decompressed, sizeof(decompressed));
    TEST_ASSERT_EQUAL_INT(13, dlen);
    TEST_ASSERT_EQUAL_MEMORY(data, decompressed, 13);
}

void test_lzs_roundtrip_repeated(void)
{
    /* Repeated data should compress well */
    uint8_t data[256];
    memset(data, 'A', sizeof(data));
    uint8_t compressed[512];
    uint8_t decompressed[256];

    iog_lzs_ctx_t enc_ctx, dec_ctx;
    iog_lzs_init(&enc_ctx);
    iog_lzs_init(&dec_ctx);

    int clen = iog_lzs_compress(&enc_ctx, data, sizeof(data), compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);
    TEST_ASSERT_LESS_THAN((int)sizeof(data), clen); /* should compress */

    int dlen =
        iog_lzs_decompress(&dec_ctx, compressed, (size_t)clen, decompressed, sizeof(decompressed));
    TEST_ASSERT_EQUAL_INT((int)sizeof(data), dlen);
    TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data));
}

void test_lzs_roundtrip_binary(void)
{
    uint8_t data[64];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 7 + 13);
    }

    uint8_t compressed[256];
    uint8_t decompressed[64];

    iog_lzs_ctx_t enc_ctx, dec_ctx;
    iog_lzs_init(&enc_ctx);
    iog_lzs_init(&dec_ctx);

    int clen = iog_lzs_compress(&enc_ctx, data, sizeof(data), compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);

    int dlen =
        iog_lzs_decompress(&dec_ctx, compressed, (size_t)clen, decompressed, sizeof(decompressed));
    TEST_ASSERT_EQUAL_INT((int)sizeof(data), dlen);
    TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data));
}

void test_lzs_compress_null(void)
{
    uint8_t out[16];
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_lzs_compress(nullptr, out, 1, out, 16));
}

void test_lzs_decompress_null(void)
{
    uint8_t out[16];
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_lzs_decompress(nullptr, out, 1, out, 16));
}

void test_lzs_reset(void)
{
    iog_lzs_ctx_t c;
    iog_lzs_init(&c);
    /* Compress something to change window_pos */
    const uint8_t data[] = "test";
    uint8_t out[64];
    (void)iog_lzs_compress(&c, data, 4, out, sizeof(out));
    TEST_ASSERT_NOT_EQUAL(0, c.window_pos);

    iog_lzs_reset(&c);
    TEST_ASSERT_EQUAL_size_t(0, c.window_pos);
}

void test_lzs_decompress_rejects_extreme_length(void)
{
    /*
     * Craft a malicious bitstream that triggers the extended length loop
     * with many 0xF (15) chunks, producing a decoded length far exceeding
     * IOG_CSTP_MAX_PAYLOAD. The fix must reject this with -EINVAL or the
     * output must stay within IOG_CSTP_MAX_PAYLOAD bytes.
     *
     * Bitstream layout:
     *   [0] literal 'A' (0-bit flag + 8-bit 0x41) = 9 bits
     *   [1] match flag (1-bit) + offset=1 (11 bits: 00000000001)
     *       + len_bits=3 (2 bits: 11) + ext=3 (2 bits: 11)
     *       + repeated 0xF 4-bit chunks (many) + terminating 0x0 chunk
     *
     * 0xFF bytes provide a long run of 1-bits which naturally encode
     * the literal 'A', the match flag, offset bits, length prefix bits,
     * and many extended 0xF chunks. We append a few zero bytes at the
     * end to terminate the chunk loop and provide an end marker.
     */
    uint8_t crafted[256];
    memset(crafted, 0xFF, sizeof(crafted));
    /* Zero out the tail so the chunk loop eventually reads < 15 and exits,
     * and the end marker (offset=0) terminates decompression. */
    memset(crafted + 200, 0x00, 56);

    uint8_t out[32768];
    iog_lzs_ctx_t dec_ctx;
    iog_lzs_init(&dec_ctx);

    int ret = iog_lzs_decompress(&dec_ctx, crafted, sizeof(crafted), out, sizeof(out));

    /* Either an error or output bounded by IOG_CSTP_MAX_PAYLOAD */
    if (ret >= 0) {
        TEST_ASSERT_LESS_OR_EQUAL(IOG_CSTP_MAX_PAYLOAD, (size_t)ret);
    } else {
        TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
    }
}

void test_lzs_compress_hash_chain_repetitive(void)
{
    /* Highly repetitive data should compress well with hash chains */
    uint8_t input[4096];
    memset(input, 'A', 2048);
    memset(input + 2048, 'B', 2048);

    iog_lzs_ctx_t hctx;
    iog_lzs_init(&hctx);

    uint8_t compressed[4096];
    int clen = iog_lzs_compress(&hctx, input, sizeof(input), compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);
    /* Repetitive data should compress significantly */
    TEST_ASSERT_LESS_THAN((int)(sizeof(input) / 2), clen);

    /* Verify roundtrip */
    iog_lzs_ctx_t dec_ctx;
    iog_lzs_init(&dec_ctx);

    uint8_t decompressed[4096];
    int dlen =
        iog_lzs_decompress(&dec_ctx, compressed, (size_t)clen, decompressed, sizeof(decompressed));
    TEST_ASSERT_EQUAL_INT((int)sizeof(input), dlen);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(input, decompressed, sizeof(input));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_lzs_init);
    RUN_TEST(test_lzs_compress_empty);
    RUN_TEST(test_lzs_compress_short);
    RUN_TEST(test_lzs_roundtrip_short);
    RUN_TEST(test_lzs_roundtrip_repeated);
    RUN_TEST(test_lzs_roundtrip_binary);
    RUN_TEST(test_lzs_compress_null);
    RUN_TEST(test_lzs_decompress_null);
    RUN_TEST(test_lzs_reset);
    RUN_TEST(test_lzs_decompress_rejects_extreme_length);
    RUN_TEST(test_lzs_compress_hash_chain_repetitive);
    return UNITY_END();
}
