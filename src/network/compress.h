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
constexpr size_t RW_COMPRESS_MAX_OUTPUT = 16384 + 256;

typedef enum : uint8_t {
	RW_COMPRESS_NONE,
	RW_COMPRESS_LZ4,
	RW_COMPRESS_LZS,
} rw_compress_type_t;

typedef struct {
	rw_compress_type_t type;
	void *codec_ctx;
} rw_compress_ctx_t;

[[nodiscard]] int rw_compress_init(rw_compress_ctx_t *ctx, rw_compress_type_t type);

[[nodiscard]] int rw_compress(rw_compress_ctx_t *ctx,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t out_size);

[[nodiscard]] int rw_decompress(rw_compress_ctx_t *ctx,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t out_size);

void rw_compress_destroy(rw_compress_ctx_t *ctx);

[[nodiscard]] const char *rw_compress_type_name(rw_compress_type_t type);

[[nodiscard]] rw_compress_type_t rw_compress_negotiate(const char *accept_encoding);

#endif /* RINGWALL_NETWORK_COMPRESS_H */
