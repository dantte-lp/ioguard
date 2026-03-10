# Sprint 4: DTLS & Compression

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add DTLS 1.2 for Cisco client compatibility, implement channel switching logic, and integrate compression codecs (LZ4, LZS).

**Architecture:** DTLS 1.2 session bootstrapped from CSTP TLS master secret (RFC 5705 keying material export). Channel state machine routes data over DTLS (primary) or CSTP (fallback). Compression abstraction layer with LZ4 (external lib) and LZS (custom RFC 1974) backends, negotiated via X-CSTP-Accept-Encoding headers. All UDP I/O via io_uring IORING_OP_SENDTO/RECVFROM.

**Tech Stack:** C23, wolfSSL 5.8.4+ (DTLS 1.2), liburing 2.7+, liblz4, Unity tests, Linux kernel 6.7+.

**User Stories:** US-114 (DTLS 1.2, P0, 5SP), US-115 (Channel switching, P0, 3SP), US-116 (LZ4, P1, 3SP), US-117 (LZS, P1, 5SP).

**Build/test:**
```bash
cmake --preset clang-debug
cmake --build --preset clang-debug
ctest --preset clang-debug
```

---

## Task 1: Compression abstraction layer (src/network/compress.h/c)

**Files:**
- Create: `src/network/compress.h`
- Create: `src/network/compress.c`
- Create: `tests/unit/test_compress.c`
- Modify: `CMakeLists.txt`

**Step 1: Write compress.h**

```c
/**
 * @file compress.h
 * @brief Compression abstraction layer for VPN data path.
 *
 * Codec-agnostic API: init/compress/decompress/destroy.
 * Backends: NONE (passthrough), LZ4, LZS.
 */

#ifndef RINGWALL_NETWORK_COMPRESS_H
#define RINGWALL_NETWORK_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_COMPRESS_MAX_INPUT = 16384;
constexpr size_t RW_COMPRESS_MAX_OUTPUT = 16384 + 256; /* headroom */

typedef enum : uint8_t {
	RW_COMPRESS_NONE,
	RW_COMPRESS_LZ4,
	RW_COMPRESS_LZS,
} rw_compress_type_t;

typedef struct {
	rw_compress_type_t type;
	void *codec_ctx; /* codec-private state */
} rw_compress_ctx_t;

/** Initialize compression context for given codec. */
[[nodiscard]] int rw_compress_init(rw_compress_ctx_t *ctx, rw_compress_type_t type);

/** Compress data. Returns bytes written to out, or negative errno. */
[[nodiscard]] int rw_compress(rw_compress_ctx_t *ctx,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t out_size);

/** Decompress data. Returns bytes written to out, or negative errno. */
[[nodiscard]] int rw_decompress(rw_compress_ctx_t *ctx,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t out_size);

/** Destroy compression context and free codec state. */
void rw_compress_destroy(rw_compress_ctx_t *ctx);

/** Get codec name string. */
[[nodiscard]] const char *rw_compress_type_name(rw_compress_type_t type);

/** Parse X-CSTP-Accept-Encoding header value. Returns best codec. */
[[nodiscard]] rw_compress_type_t rw_compress_negotiate(const char *accept_encoding);

#endif /* RINGWALL_NETWORK_COMPRESS_H */
```

**Step 2: Write compress.c**

```c
#include "network/compress.h"

#include <errno.h>
#include <string.h>

int rw_compress_init(rw_compress_ctx_t *ctx, rw_compress_type_t type)
{
	if (!ctx)
		return -EINVAL;

	ctx->type = type;
	ctx->codec_ctx = nullptr;

	switch (type) {
	case RW_COMPRESS_NONE:
		return 0;
	case RW_COMPRESS_LZ4:
	case RW_COMPRESS_LZS:
		/* backends registered by compress_lz4.c / compress_lzs.c */
		return -ENOTSUP;
	}
	return -EINVAL;
}

int rw_compress(rw_compress_ctx_t *ctx,
                const uint8_t *in, size_t in_len,
                uint8_t *out, size_t out_size)
{
	if (!ctx || !in || !out)
		return -EINVAL;
	if (in_len > RW_COMPRESS_MAX_INPUT)
		return -EINVAL;

	if (ctx->type == RW_COMPRESS_NONE) {
		if (out_size < in_len)
			return -ENOSPC;
		memcpy(out, in, in_len);
		return (int)in_len;
	}

	return -ENOTSUP;
}

int rw_decompress(rw_compress_ctx_t *ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_size)
{
	if (!ctx || !in || !out)
		return -EINVAL;

	if (ctx->type == RW_COMPRESS_NONE) {
		if (out_size < in_len)
			return -ENOSPC;
		memcpy(out, in, in_len);
		return (int)in_len;
	}

	return -ENOTSUP;
}

void rw_compress_destroy(rw_compress_ctx_t *ctx)
{
	if (!ctx)
		return;
	ctx->codec_ctx = nullptr;
	ctx->type = RW_COMPRESS_NONE;
}

const char *rw_compress_type_name(rw_compress_type_t type)
{
	switch (type) {
	case RW_COMPRESS_NONE: return "none";
	case RW_COMPRESS_LZ4:  return "lz4";
	case RW_COMPRESS_LZS:  return "lzs";
	}
	return "unknown";
}

rw_compress_type_t rw_compress_negotiate(const char *accept_encoding)
{
	if (!accept_encoding)
		return RW_COMPRESS_NONE;
	if (strstr(accept_encoding, "lz4"))
		return RW_COMPRESS_LZ4;
	if (strstr(accept_encoding, "lzs"))
		return RW_COMPRESS_LZS;
	return RW_COMPRESS_NONE;
}
```

**Step 3: Write tests (test_compress.c)**

```c
#include <unity/unity.h>
#include "network/compress.h"
#include <errno.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_compress_init_none(void)
{
	rw_compress_ctx_t ctx;
	int ret = rw_compress_init(&ctx, RW_COMPRESS_NONE);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, ctx.type);
	rw_compress_destroy(&ctx);
}

void test_compress_init_null(void)
{
	TEST_ASSERT_EQUAL_INT(-EINVAL, rw_compress_init(nullptr, RW_COMPRESS_NONE));
}

void test_compress_none_passthrough(void)
{
	rw_compress_ctx_t ctx;
	rw_compress_init(&ctx, RW_COMPRESS_NONE);

	const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	uint8_t out[64];

	int ret = rw_compress(&ctx, data, sizeof(data), out, sizeof(out));
	TEST_ASSERT_EQUAL_INT(4, ret);
	TEST_ASSERT_EQUAL_MEMORY(data, out, sizeof(data));

	rw_compress_destroy(&ctx);
}

void test_decompress_none_passthrough(void)
{
	rw_compress_ctx_t ctx;
	rw_compress_init(&ctx, RW_COMPRESS_NONE);

	const uint8_t data[] = { 0xCA, 0xFE };
	uint8_t out[64];

	int ret = rw_decompress(&ctx, data, sizeof(data), out, sizeof(out));
	TEST_ASSERT_EQUAL_INT(2, ret);
	TEST_ASSERT_EQUAL_MEMORY(data, out, sizeof(data));

	rw_compress_destroy(&ctx);
}

void test_compress_output_too_small(void)
{
	rw_compress_ctx_t ctx;
	rw_compress_init(&ctx, RW_COMPRESS_NONE);

	const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t out[2]; /* too small */

	int ret = rw_compress(&ctx, data, sizeof(data), out, sizeof(out));
	TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);

	rw_compress_destroy(&ctx);
}

void test_compress_input_too_large(void)
{
	rw_compress_ctx_t ctx;
	rw_compress_init(&ctx, RW_COMPRESS_NONE);

	uint8_t out[64];
	int ret = rw_compress(&ctx, out, RW_COMPRESS_MAX_INPUT + 1, out, sizeof(out));
	TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

	rw_compress_destroy(&ctx);
}

void test_compress_type_name(void)
{
	TEST_ASSERT_EQUAL_STRING("none", rw_compress_type_name(RW_COMPRESS_NONE));
	TEST_ASSERT_EQUAL_STRING("lz4", rw_compress_type_name(RW_COMPRESS_LZ4));
	TEST_ASSERT_EQUAL_STRING("lzs", rw_compress_type_name(RW_COMPRESS_LZS));
}

void test_compress_negotiate(void)
{
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZS, rw_compress_negotiate("lzs,deflate"));
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_LZ4, rw_compress_negotiate("lz4"));
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, rw_compress_negotiate("deflate"));
	TEST_ASSERT_EQUAL_UINT8(RW_COMPRESS_NONE, rw_compress_negotiate(nullptr));
}

void test_compress_destroy_null(void)
{
	rw_compress_destroy(nullptr); /* should not crash */
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
```

**Step 4: CMakeLists.txt — add before `message(STATUS "Unit test infrastructure ready")`:**

```cmake
        # Sprint 4 — Compression abstraction
        add_library(rw_compress STATIC src/network/compress.c)
        target_include_directories(rw_compress PUBLIC ${CMAKE_SOURCE_DIR}/src)

        rw_add_test(test_compress tests/unit/test_compress.c rw_compress)
```

**Step 5: Build, test, commit**

```bash
cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug -R test_compress --output-on-failure
git add src/network/compress.h src/network/compress.c tests/unit/test_compress.c CMakeLists.txt
git commit -m "feat: compression abstraction layer with NONE passthrough (9 tests)"
```

---

## Task 2: LZS compression codec (src/network/compress_lzs.c)

**Files:**
- Create: `src/network/compress_lzs.h`
- Create: `src/network/compress_lzs.c`
- Create: `tests/unit/test_compress_lzs.c`
- Modify: `src/network/compress.c` (register LZS backend)
- Modify: `CMakeLists.txt`

**Context:** LZS (Lempel-Ziv-Stac, RFC 1974) is mandatory for Cisco compatibility. Custom implementation with 2048-byte sliding window. No external dependency.

**Step 1: Write compress_lzs.h**

```c
/**
 * @file compress_lzs.h
 * @brief LZS (Lempel-Ziv-Stac) compression codec — RFC 1974.
 *
 * Custom implementation for Cisco Secure Client compatibility.
 * 2048-byte sliding window, bit-oriented output.
 */

#ifndef RINGWALL_NETWORK_COMPRESS_LZS_H
#define RINGWALL_NETWORK_COMPRESS_LZS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_LZS_WINDOW_SIZE = 2048;
constexpr size_t RW_LZS_MIN_MATCH = 2;
constexpr size_t RW_LZS_MAX_MATCH = 255 + 2; /* length encoding limit */

typedef struct {
	uint8_t window[RW_LZS_WINDOW_SIZE];
	size_t window_pos;
} rw_lzs_ctx_t;

/** Initialize LZS context. */
void rw_lzs_init(rw_lzs_ctx_t *ctx);

/** Reset LZS sliding window. */
void rw_lzs_reset(rw_lzs_ctx_t *ctx);

/** Compress data using LZS. Returns bytes written or negative errno. */
[[nodiscard]] int rw_lzs_compress(rw_lzs_ctx_t *ctx,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t out_size);

/** Decompress LZS data. Returns bytes written or negative errno. */
[[nodiscard]] int rw_lzs_decompress(rw_lzs_ctx_t *ctx,
                                     const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_size);

#endif /* RINGWALL_NETWORK_COMPRESS_LZS_H */
```

**Step 2: Write compress_lzs.c**

LZS encoding: 0-bit + 8 literal bits for literals; 1-bit + 11-bit offset + variable length for matches. End marker: 110000000 (9 bits).

Implementation: ~200 LOC. Sliding window with brute-force search (fine for VPN MTU-sized packets). Bit-writer helper for output.

```c
#include "network/compress_lzs.h"

#include <errno.h>
#include <string.h>

/* Bit writer helper */
typedef struct {
	uint8_t *buf;
	size_t capacity;
	size_t byte_pos;
	uint8_t bit_pos; /* 0-7, MSB first */
} bit_writer_t;

/* Bit reader helper */
typedef struct {
	const uint8_t *buf;
	size_t len;
	size_t byte_pos;
	uint8_t bit_pos;
} bit_reader_t;

static void bw_init(bit_writer_t *bw, uint8_t *buf, size_t cap)
{
	bw->buf = buf;
	bw->capacity = cap;
	bw->byte_pos = 0;
	bw->bit_pos = 0;
	if (cap > 0)
		buf[0] = 0;
}

static int bw_write_bit(bit_writer_t *bw, uint8_t bit)
{
	if (bw->byte_pos >= bw->capacity)
		return -ENOSPC;
	if (bit)
		bw->buf[bw->byte_pos] |= (uint8_t)(0x80 >> bw->bit_pos);
	bw->bit_pos++;
	if (bw->bit_pos == 8) {
		bw->bit_pos = 0;
		bw->byte_pos++;
		if (bw->byte_pos < bw->capacity)
			bw->buf[bw->byte_pos] = 0;
	}
	return 0;
}

static int bw_write_bits(bit_writer_t *bw, uint32_t val, int nbits)
{
	for (int i = nbits - 1; i >= 0; i--) {
		int ret = bw_write_bit(bw, (uint8_t)((val >> i) & 1));
		if (ret < 0)
			return ret;
	}
	return 0;
}

static size_t bw_bytes_written(const bit_writer_t *bw)
{
	return bw->bit_pos > 0 ? bw->byte_pos + 1 : bw->byte_pos;
}

static void br_init(bit_reader_t *br, const uint8_t *buf, size_t len)
{
	br->buf = buf;
	br->len = len;
	br->byte_pos = 0;
	br->bit_pos = 0;
}

static int br_read_bit(bit_reader_t *br)
{
	if (br->byte_pos >= br->len)
		return -EAGAIN;
	int bit = (br->buf[br->byte_pos] >> (7 - br->bit_pos)) & 1;
	br->bit_pos++;
	if (br->bit_pos == 8) {
		br->bit_pos = 0;
		br->byte_pos++;
	}
	return bit;
}

static int br_read_bits(bit_reader_t *br, int nbits)
{
	uint32_t val = 0;
	for (int i = 0; i < nbits; i++) {
		int bit = br_read_bit(br);
		if (bit < 0)
			return bit;
		val = (val << 1) | (uint32_t)bit;
	}
	return (int)val;
}

void rw_lzs_init(rw_lzs_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

void rw_lzs_reset(rw_lzs_ctx_t *ctx)
{
	memset(ctx->window, 0, sizeof(ctx->window));
	ctx->window_pos = 0;
}

static void window_add(rw_lzs_ctx_t *ctx, uint8_t byte)
{
	ctx->window[ctx->window_pos % RW_LZS_WINDOW_SIZE] = byte;
	ctx->window_pos++;
}

/* Find longest match in sliding window */
static int find_match(const rw_lzs_ctx_t *ctx, const uint8_t *in,
                      size_t in_len, size_t *match_offset, size_t *match_len)
{
	size_t best_len = 0;
	size_t best_off = 0;
	size_t win_used = ctx->window_pos < RW_LZS_WINDOW_SIZE
	                  ? ctx->window_pos : RW_LZS_WINDOW_SIZE;

	for (size_t off = 1; off <= win_used; off++) {
		size_t wi = (ctx->window_pos - off) % RW_LZS_WINDOW_SIZE;
		size_t len = 0;
		while (len < in_len && len < RW_LZS_MAX_MATCH) {
			size_t ci = (wi + len) % RW_LZS_WINDOW_SIZE;
			if (ctx->window[ci] != in[len])
				break;
			len++;
		}
		if (len >= RW_LZS_MIN_MATCH && len > best_len) {
			best_len = len;
			best_off = off;
		}
	}

	if (best_len >= RW_LZS_MIN_MATCH) {
		*match_offset = best_off;
		*match_len = best_len;
		return 1;
	}
	return 0;
}

/* Encode match length: 2=00, 3=01, 4=10, 5-7=1100-1110, 8+=11110000... */
static int encode_length(bit_writer_t *bw, size_t length)
{
	if (length <= 4) {
		return bw_write_bits(bw, (uint32_t)(length - 2), 2);
	} else if (length <= 7) {
		int ret = bw_write_bits(bw, 0x3, 2); /* 11 prefix */
		if (ret < 0) return ret;
		return bw_write_bits(bw, (uint32_t)(length - 5), 2);
	} else {
		/* length >= 8: encode as 1111 + (length-8) in 4-bit chunks */
		int ret = bw_write_bits(bw, 0xF, 4);
		if (ret < 0) return ret;
		size_t rem = length - 8;
		while (rem >= 15) {
			ret = bw_write_bits(bw, 0xF, 4);
			if (ret < 0) return ret;
			rem -= 15;
		}
		return bw_write_bits(bw, (uint32_t)rem, 4);
	}
}

int rw_lzs_compress(rw_lzs_ctx_t *ctx,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_size)
{
	if (!ctx || !in || !out)
		return -EINVAL;
	if (in_len == 0) {
		/* Write end marker only */
		bit_writer_t bw;
		bw_init(&bw, out, out_size);
		int ret = bw_write_bits(&bw, 0x180, 9); /* 110000000 */
		if (ret < 0) return ret;
		return (int)bw_bytes_written(&bw);
	}

	bit_writer_t bw;
	bw_init(&bw, out, out_size);

	size_t pos = 0;
	while (pos < in_len) {
		size_t match_off, match_len;
		if (find_match(ctx, in + pos, in_len - pos,
		               &match_off, &match_len)) {
			/* Match: 1-bit + 11-bit offset + variable length */
			int ret = bw_write_bit(&bw, 1);
			if (ret < 0) return ret;
			ret = bw_write_bits(&bw, (uint32_t)match_off, 11);
			if (ret < 0) return ret;
			ret = encode_length(&bw, match_len);
			if (ret < 0) return ret;
			for (size_t i = 0; i < match_len; i++)
				window_add(ctx, in[pos + i]);
			pos += match_len;
		} else {
			/* Literal: 0-bit + 8-bit value */
			int ret = bw_write_bit(&bw, 0);
			if (ret < 0) return ret;
			ret = bw_write_bits(&bw, in[pos], 8);
			if (ret < 0) return ret;
			window_add(ctx, in[pos]);
			pos++;
		}
	}

	/* End marker: 110000000 (9 bits) */
	int ret = bw_write_bits(&bw, 0x180, 9);
	if (ret < 0) return ret;

	return (int)bw_bytes_written(&bw);
}

int rw_lzs_decompress(rw_lzs_ctx_t *ctx,
                       const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_size)
{
	if (!ctx || !in || !out)
		return -EINVAL;

	bit_reader_t br;
	br_init(&br, in, in_len);

	size_t out_pos = 0;

	while (1) {
		int bit = br_read_bit(&br);
		if (bit < 0)
			break; /* end of input */

		if (bit == 0) {
			/* Literal */
			int val = br_read_bits(&br, 8);
			if (val < 0)
				break;
			if (out_pos >= out_size)
				return -ENOSPC;
			out[out_pos++] = (uint8_t)val;
			window_add(ctx, (uint8_t)val);
		} else {
			/* Match or end marker */
			int offset = br_read_bits(&br, 11);
			if (offset < 0)
				break;
			if (offset == 0)
				break; /* end marker: 1 + 00000000000 */

			/* Decode length */
			int len_bits = br_read_bits(&br, 2);
			if (len_bits < 0)
				break;
			size_t length;
			if (len_bits <= 2) {
				length = (size_t)len_bits + 2;
			} else { /* len_bits == 3 */
				int ext = br_read_bits(&br, 2);
				if (ext < 0)
					break;
				if (ext <= 2) {
					length = (size_t)ext + 5;
				} else {
					/* Extended: read 4-bit chunks */
					length = 8;
					while (1) {
						int chunk = br_read_bits(&br, 4);
						if (chunk < 0)
							return chunk;
						length += (size_t)chunk;
						if (chunk < 15)
							break;
					}
				}
			}

			/* Copy from window */
			for (size_t i = 0; i < length; i++) {
				size_t wi = (ctx->window_pos - (size_t)offset) % RW_LZS_WINDOW_SIZE;
				if (out_pos >= out_size)
					return -ENOSPC;
				uint8_t byte = ctx->window[wi];
				out[out_pos++] = byte;
				window_add(ctx, byte);
			}
		}
	}

	return (int)out_pos;
}
```

**Step 3: Write test_compress_lzs.c**

```c
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
	window_add is internal, so just test that reset clears state:
	rw_lzs_ctx_t c;
	rw_lzs_init(&c);
	/* Compress something to change window_pos */
	const uint8_t data[] = "test";
	uint8_t out[64];
	rw_lzs_compress(&c, data, 4, out, sizeof(out));
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
```

NOTE: `test_lzs_reset` has a comment typo — the implementer should fix "window_add is internal..." to be a proper C comment.

**Step 4: Modify compress.c to register LZS backend**

Update `rw_compress_init()` case `RW_COMPRESS_LZS` to allocate and init `rw_lzs_ctx_t`.
Update `rw_compress()` and `rw_decompress()` to call `rw_lzs_compress()`/`rw_lzs_decompress()`.
Update `rw_compress_destroy()` to free LZS context.

**Step 5: CMakeLists.txt**

```cmake
        # Sprint 4 — LZS compression
        add_library(rw_compress_lzs STATIC src/network/compress_lzs.c)
        target_include_directories(rw_compress_lzs PUBLIC ${CMAKE_SOURCE_DIR}/src)

        target_link_libraries(rw_compress PUBLIC rw_compress_lzs)
        rw_add_test(test_compress_lzs tests/unit/test_compress_lzs.c rw_compress_lzs)
```

**Step 6: Build, test, commit**

```bash
ctest --preset clang-debug -R "test_compress" --output-on-failure
git add src/network/compress_lzs.h src/network/compress_lzs.c src/network/compress.c tests/unit/test_compress_lzs.c CMakeLists.txt
git commit -m "feat: LZS compression codec — RFC 1974 with sliding window (9 tests)"
```

---

## Task 3: LZ4 compression codec

**Files:**
- Create: `src/network/compress_lz4.h`
- Create: `src/network/compress_lz4.c`
- Create: `tests/unit/test_compress_lz4.c`
- Modify: `src/network/compress.c` (register LZ4 backend)
- Modify: `CMakeLists.txt`

**Step 1: Write compress_lz4.h**

```c
#ifndef RINGWALL_NETWORK_COMPRESS_LZ4_H
#define RINGWALL_NETWORK_COMPRESS_LZ4_H

#include <stddef.h>
#include <stdint.h>

/** Compress using LZ4. Returns bytes written or negative errno. */
[[nodiscard]] int rw_lz4_compress(const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t out_size);

/** Decompress using LZ4. Returns bytes written or negative errno. */
[[nodiscard]] int rw_lz4_decompress(const uint8_t *in, size_t in_len,
                                     uint8_t *out, size_t out_size);

#endif /* RINGWALL_NETWORK_COMPRESS_LZ4_H */
```

**Step 2: Write compress_lz4.c** — wraps `LZ4_compress_default()` and `LZ4_decompress_safe()`.

**Step 3: Tests** — roundtrip, empty, large data, incompressible. Guard with runtime check for LZ4 availability.

**Step 4: CMakeLists.txt** — find liblz4, add library, link.

**Step 5: Build, test, commit**

```bash
git commit -m "feat: LZ4 compression codec wrapper (7 tests)"
```

---

## Task 4: DTLS context management (src/network/dtls.h/c)

**Files:**
- Create: `src/network/dtls.h`
- Create: `src/network/dtls.c`
- Create: `tests/unit/test_dtls.c`
- Modify: `CMakeLists.txt`

**Context:** DTLS 1.2 wolfSSL context creation. Config struct for cipher suites, MTU, cookie callbacks. No handshake yet — just context lifecycle.

**Step 1: Write dtls.h**

```c
#ifndef RINGWALL_NETWORK_DTLS_H
#define RINGWALL_NETWORK_DTLS_H

#include <stdbool.h>
#include <stdint.h>

constexpr uint32_t RW_DTLS_DEFAULT_MTU = 1400;
constexpr uint32_t RW_DTLS_DEFAULT_TIMEOUT_S = 5;
constexpr uint32_t RW_DTLS_DEFAULT_REKEY_S = 3600;

typedef struct {
	uint32_t mtu;
	uint32_t timeout_init_s;
	uint32_t rekey_interval_s;
	const char *cert_file;
	const char *key_file;
	const char *ca_file;
	const char *cipher_list;
	bool enable_cookies;
} rw_dtls_config_t;

typedef struct rw_dtls_ctx rw_dtls_ctx_t;

void rw_dtls_config_init(rw_dtls_config_t *cfg);
[[nodiscard]] int rw_dtls_config_validate(const rw_dtls_config_t *cfg);
[[nodiscard]] rw_dtls_ctx_t *rw_dtls_create(const rw_dtls_config_t *cfg);
void rw_dtls_destroy(rw_dtls_ctx_t *ctx);
[[nodiscard]] uint32_t rw_dtls_get_mtu(const rw_dtls_ctx_t *ctx);

/** Cisco-compatible DTLS 1.2 cipher list. */
[[nodiscard]] const char *rw_dtls_cisco_ciphers(void);

#endif /* RINGWALL_NETWORK_DTLS_H */
```

**Step 2: Write dtls.c** — `wolfSSL_CTX_new(wolfDTLSv1_2_server_method())`, set ciphers, MTU, cookie callbacks. Opaque struct holds `WOLFSSL_CTX *`.

**Step 3: Tests** — config defaults, validate, create/destroy (guarded by wolfSSL availability), cipher list string, MTU getter.

**Step 4: Build, test, commit**

```bash
git commit -m "feat: DTLS 1.2 context management with wolfSSL (8 tests)"
```

---

## Task 5: Master secret export (src/network/dtls_keying.h/c)

**Files:**
- Create: `src/network/dtls_keying.h`
- Create: `src/network/dtls_keying.c`
- Create: `tests/unit/test_dtls_keying.c`
- Modify: `CMakeLists.txt`

**Context:** Export keying material via RFC 5705 (`wolfSSL_export_keying_material()`). Hex encode for X-DTLS-Master-Secret header. Test with known hex values (no actual wolfSSL session needed for hex tests).

**Key types:**
```c
constexpr size_t RW_DTLS_MASTER_SECRET_LEN = 48;
constexpr size_t RW_DTLS_MASTER_SECRET_HEX_LEN = 96; /* 48 * 2 */

typedef struct {
	uint8_t secret[RW_DTLS_MASTER_SECRET_LEN];
	char hex[RW_DTLS_MASTER_SECRET_HEX_LEN + 1];
	bool valid;
} rw_dtls_master_secret_t;

[[nodiscard]] int rw_dtls_hex_encode(const uint8_t *in, size_t in_len,
                                      char *hex, size_t hex_size);
[[nodiscard]] int rw_dtls_hex_decode(const char *hex, size_t hex_len,
                                      uint8_t *out, size_t out_size);
```

**Tests:** hex encode, hex decode, roundtrip, invalid hex chars, odd-length hex, null checks.

```bash
git commit -m "feat: DTLS master secret hex encoding for X-DTLS-Master-Secret (6 tests)"
```

---

## Task 6: Channel state machine (src/network/channel.h/c)

**Files:**
- Create: `src/network/channel.h`
- Create: `src/network/channel.c`
- Create: `tests/unit/test_channel.c`
- Modify: `CMakeLists.txt`

**Context:** Channel switching logic. Uses existing `rw_channel_state_t` from dpd.h. Pure state machine — no I/O.

**Key types:**
```c
typedef struct {
	rw_channel_state_t state;
	bool cstp_active;
	bool dtls_active;
	uint32_t dtls_fail_count;
	uint32_t dtls_max_fails;
	rw_compress_type_t compress_type;
} rw_channel_ctx_t;

void rw_channel_init(rw_channel_ctx_t *ctx);
[[nodiscard]] rw_channel_state_t rw_channel_on_dtls_up(rw_channel_ctx_t *ctx);
[[nodiscard]] rw_channel_state_t rw_channel_on_dtls_down(rw_channel_ctx_t *ctx);
[[nodiscard]] rw_channel_state_t rw_channel_on_dtls_recovery(rw_channel_ctx_t *ctx);
[[nodiscard]] bool rw_channel_use_dtls(const rw_channel_ctx_t *ctx);
```

**Tests (10):** init state, CSTP_ONLY→DTLS_PRIMARY, DTLS_PRIMARY→DTLS_FALLBACK, DTLS_FALLBACK→DTLS_PRIMARY, routing decisions, CSTP always active, compress type tracking.

```bash
git commit -m "feat: channel state machine for CSTP/DTLS switching (10 tests)"
```

---

## Task 7: DTLS header builder (src/network/dtls_headers.h/c)

**Files:**
- Create: `src/network/dtls_headers.h`
- Create: `src/network/dtls_headers.c`
- Create: `tests/unit/test_dtls_headers.c`
- Modify: `CMakeLists.txt`

**Context:** Build X-DTLS-* HTTP response headers. Parse X-CSTP-Accept-Encoding from client.

**Key functions:**
```c
[[nodiscard]] int rw_dtls_build_headers(char *buf, size_t buf_size,
                                         const char *master_secret_hex,
                                         const char *cipher_suite,
                                         const char *accept_encoding);

[[nodiscard]] rw_compress_type_t rw_dtls_parse_accept_encoding(const char *header);
```

**Tests (8):** build full header string, parse lzs, parse lz4, parse deflate (→ NONE), null inputs, buffer too small.

```bash
git commit -m "feat: DTLS HTTP header builder/parser for Cisco compatibility (8 tests)"
```

---

## Task 8: Compression integration with CSTP

**Files:**
- Modify: `src/core/worker.h` (add compress_ctx to rw_connection_t)
- Modify: `src/core/worker.c` (init/destroy compress context)
- Create: `tests/unit/test_compress_cstp.c`
- Modify: `CMakeLists.txt`

**Context:** Add COMPRESSED packet type handling. Worker connection gets compression context. CSTP encode with COMPRESSED type wraps compressed payload.

**Tests (6):** encode DATA→compress→COMPRESSED, decode COMPRESSED→decompress→DATA, roundtrip with LZS, roundtrip with NONE.

```bash
git commit -m "feat: CSTP compression integration with worker connections (6 tests)"
```

---

## Task 9: Integration test — DTLS + channel + compression

**Files:**
- Create: `tests/integration/test_dtls_channel.c`
- Modify: `CMakeLists.txt`

**Tests (5):**
1. Channel state machine full lifecycle (CSTP_ONLY → DTLS_PRIMARY → DTLS_FALLBACK → recovery)
2. Compression negotiation + LZS roundtrip through CSTP framing
3. DTLS master secret hex roundtrip
4. DTLS headers build + parse roundtrip
5. Worker connection with compression context lifecycle

```bash
git commit -m "test: DTLS + channel + compression integration (5 tests)"
```

---

## Task 10: Sprint finalization

**Step 1: Full test suite with sanitizers**
```bash
cmake --preset clang-debug -DENABLE_SANITIZERS=ON
cmake --build --preset clang-debug
ctest --preset clang-debug --output-on-failure
```

**Step 2: Format check**
```bash
cmake --build --preset clang-debug --target format
```

**Step 3: Verify test count**
```bash
ctest --preset clang-debug -N | tail -1  # expect: ~30 total test targets
```

**Step 4: Commit**
```bash
git add -A
git commit -m "chore: Sprint 4 complete — DTLS, channel switching, LZ4/LZS compression"
```

---

## Summary

| Task | What | New Tests |
|------|------|-----------|
| 1 | Compression abstraction (NONE passthrough) | 9 |
| 2 | LZS codec (RFC 1974, custom) | 9 |
| 3 | LZ4 codec (liblz4 wrapper) | 7 |
| 4 | DTLS 1.2 context (wolfSSL) | 8 |
| 5 | Master secret hex encoding | 6 |
| 6 | Channel state machine | 10 |
| 7 | DTLS HTTP headers | 8 |
| 8 | CSTP compression integration | 6 |
| 9 | Integration test | 5 |
| 10 | Sprint finalization | — |

**New tests: ~68. Total after Sprint 4: ~110 (42 from S3 + 68 new).**

## Critical Files

**Existing (reuse):**
- `src/network/cstp.h/c` — CSTP framing, COMPRESSED packet type (0x08)
- `src/network/dpd.h` — `rw_channel_state_t` enum
- `src/core/worker.h/c` — connection tracking, add compress_ctx
- `src/crypto/tls_wolfssl.h/c` — TLS context for master secret export
- `CMakeLists.txt` — `rw_add_test()` macro

**New:**
- `src/network/compress.h/c` — Compression abstraction
- `src/network/compress_lzs.h/c` — LZS codec (RFC 1974)
- `src/network/compress_lz4.h/c` — LZ4 codec
- `src/network/dtls.h/c` — DTLS 1.2 context management
- `src/network/dtls_keying.h/c` — Master secret hex encoding
- `src/network/channel.h/c` — Channel state machine
- `src/network/dtls_headers.h/c` — DTLS HTTP header builder

**Reference:**
- `docs/ioguard-docs/ringwall/protocol/cisco-compatibility.md` — DTLS headers, cipher suites
- `docs/ioguard-docs/openconnect-protocol/protocol/crypto.md` — Crypto protocol details
- `.claude/skills/wolfssl-api/SKILL.md` — wolfSSL DTLS API patterns
- `.claude/skills/ocprotocol/SKILL.md` — OpenConnect protocol, compression negotiation
