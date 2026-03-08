/**
 * @file compress.h
 * @brief Compression abstraction layer for VPN data path.
 *
 * Codec-agnostic API: init/compress/decompress/destroy.
 * Backends: NONE (passthrough), LZ4, LZS.
 */

#ifndef WOLFGUARD_NETWORK_COMPRESS_H
#define WOLFGUARD_NETWORK_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t WG_COMPRESS_MAX_INPUT = 16384;
constexpr size_t WG_COMPRESS_MAX_OUTPUT = 16384 + 256;

typedef enum : uint8_t {
	WG_COMPRESS_NONE,
	WG_COMPRESS_LZ4,
	WG_COMPRESS_LZS,
} wg_compress_type_t;

typedef struct {
	wg_compress_type_t type;
	void *codec_ctx;
} wg_compress_ctx_t;

[[nodiscard]] int wg_compress_init(wg_compress_ctx_t *ctx, wg_compress_type_t type);

[[nodiscard]] int wg_compress(wg_compress_ctx_t *ctx,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t out_size);

[[nodiscard]] int wg_decompress(wg_compress_ctx_t *ctx,
                                 const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t out_size);

void wg_compress_destroy(wg_compress_ctx_t *ctx);

[[nodiscard]] const char *wg_compress_type_name(wg_compress_type_t type);

[[nodiscard]] wg_compress_type_t wg_compress_negotiate(const char *accept_encoding);

#endif /* WOLFGUARD_NETWORK_COMPRESS_H */
