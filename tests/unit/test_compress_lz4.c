#include <unity/unity.h>
#include "network/compress_lz4.h"
#include <errno.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_lz4_compress_short(void)
{
	const uint8_t data[] = "Hello, LZ4 World!";
	uint8_t compressed[256];
	int clen = rw_lz4_compress(data, sizeof(data) - 1,
	                            compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);
}

void test_lz4_roundtrip_short(void)
{
	const uint8_t data[] = "Hello, LZ4 World!";
	uint8_t compressed[256];
	uint8_t decompressed[256];

	int clen = rw_lz4_compress(data, sizeof(data) - 1,
	                            compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);

	int dlen = rw_lz4_decompress(compressed, (size_t)clen,
	                              decompressed, sizeof(decompressed));
	TEST_ASSERT_EQUAL_INT((int)(sizeof(data) - 1), dlen);
	TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data) - 1);
}

void test_lz4_roundtrip_repeated(void)
{
	uint8_t data[1024];
	memset(data, 'X', sizeof(data));
	uint8_t compressed[2048];
	uint8_t decompressed[1024];

	int clen = rw_lz4_compress(data, sizeof(data),
	                            compressed, sizeof(compressed));
	TEST_ASSERT_GREATER_THAN(0, clen);
	TEST_ASSERT_LESS_THAN((int)sizeof(data), clen); /* should compress */

	int dlen = rw_lz4_decompress(compressed, (size_t)clen,
	                              decompressed, sizeof(decompressed));
	TEST_ASSERT_EQUAL_INT((int)sizeof(data), dlen);
	TEST_ASSERT_EQUAL_MEMORY(data, decompressed, sizeof(data));
}

void test_lz4_compress_empty(void)
{
	uint8_t out[16];
	int ret = rw_lz4_compress((const uint8_t *)"", 0, out, sizeof(out));
	TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_lz4_compress_null(void)
{
	uint8_t out[16];
	TEST_ASSERT_EQUAL_INT(-EINVAL, rw_lz4_compress(nullptr, 1, out, 16));
}

void test_lz4_decompress_null(void)
{
	uint8_t out[16];
	TEST_ASSERT_EQUAL_INT(-EINVAL, rw_lz4_decompress(nullptr, 1, out, 16));
}

void test_lz4_output_too_small(void)
{
	const uint8_t data[] = "This data needs space to compress into";
	uint8_t out[1]; /* way too small */
	int ret = rw_lz4_compress(data, sizeof(data) - 1, out, sizeof(out));
	TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_lz4_compress_short);
	RUN_TEST(test_lz4_roundtrip_short);
	RUN_TEST(test_lz4_roundtrip_repeated);
	RUN_TEST(test_lz4_compress_empty);
	RUN_TEST(test_lz4_compress_null);
	RUN_TEST(test_lz4_decompress_null);
	RUN_TEST(test_lz4_output_too_small);
	return UNITY_END();
}
