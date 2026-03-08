#include <unity/unity.h>
#include "network/compress_lzs.h"
#include <errno.h>
#include <string.h>

static rw_lzs_ctx_t ctx;

void setUp(void) { rw_lzs_init(&ctx); }
void tearDown(void) {}

void test_lzs_init(void)
{
	TEST_ASSERT_EQUAL_size_t(0, ctx.window_pos);
}

void test_lzs_compress_empty(void)
{
	uint8_t out[16];
	int ret = rw_lzs_compress(&ctx, (const uint8_t *)"", 0, out, sizeof(out));
	TEST_ASSERT_GREATER_THAN(0, ret); /* end marker only */
}

void test_lzs_compress_short(void)
{
	const uint8_t data[] = "Hello";
	uint8_t compressed[64];
	int clen = rw_lzs_compress(&ctx, data, 5, compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);
}

void test_lzs_roundtrip_short(void)
{
	const uint8_t data[] = "Hello, World!";
	uint8_t compressed[128];
	uint8_t decompressed[128];

	rw_lzs_ctx_t enc_ctx, dec_ctx;
	rw_lzs_init(&enc_ctx);
	rw_lzs_init(&dec_ctx);

	int clen = rw_lzs_compress(&enc_ctx, data, 13, compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);

	int dlen = rw_lzs_decompress(&dec_ctx, compressed, (size_t)clen,
	                              decompressed, sizeof(decompressed));
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

	rw_lzs_ctx_t enc_ctx, dec_ctx;
	rw_lzs_init(&enc_ctx);
	rw_lzs_init(&dec_ctx);

	int clen = rw_lzs_compress(&enc_ctx, data, sizeof(data),
	                            compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);
	TEST_ASSERT_LESS_THAN((int)sizeof(data), clen); /* should compress */

	int dlen = rw_lzs_decompress(&dec_ctx, compressed, (size_t)clen,
	                              decompressed, sizeof(decompressed));
	TEST_ASSERT_EQUAL_INT((int)sizeof(data), dlen);
	TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data));
}

void test_lzs_roundtrip_binary(void)
{
	uint8_t data[64];
	for (size_t i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 7 + 13);

	uint8_t compressed[256];
	uint8_t decompressed[64];

	rw_lzs_ctx_t enc_ctx, dec_ctx;
	rw_lzs_init(&enc_ctx);
	rw_lzs_init(&dec_ctx);

	int clen = rw_lzs_compress(&enc_ctx, data, sizeof(data),
	                            compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);

	int dlen = rw_lzs_decompress(&dec_ctx, compressed, (size_t)clen,
	                              decompressed, sizeof(decompressed));
	TEST_ASSERT_EQUAL_INT((int)sizeof(data), dlen);
	TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data));
}

void test_lzs_compress_null(void)
{
	uint8_t out[16];
	TEST_ASSERT_EQUAL_INT(-EINVAL, rw_lzs_compress(nullptr, out, 1, out, 16));
}

void test_lzs_decompress_null(void)
{
	uint8_t out[16];
	TEST_ASSERT_EQUAL_INT(-EINVAL, rw_lzs_decompress(nullptr, out, 1, out, 16));
}

void test_lzs_reset(void)
{
	rw_lzs_ctx_t c;
	rw_lzs_init(&c);
	/* Compress something to change window_pos */
	const uint8_t data[] = "test";
	uint8_t out[64];
	(void)rw_lzs_compress(&c, data, 4, out, sizeof(out));
	TEST_ASSERT_NOT_EQUAL(0, c.window_pos);

	rw_lzs_reset(&c);
	TEST_ASSERT_EQUAL_size_t(0, c.window_pos);
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
	return UNITY_END();
}
