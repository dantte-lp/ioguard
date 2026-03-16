/**
 * @file compress.h
 * @brief Compression abstraction layer for VPN data path.
 *
 * Codec-agnostic API: init/compress/decompress/destroy.
 * Backends: NONE (passthrough), LZ4, LZS.
 */

#ifndef IOGUARD_NETWORK_COMPRESS_H
#define IOGUARD_NETWORK_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t IOG_COMPRESS_MAX_INPUT = 16384;
constexpr size_t IOG_COMPRESS_MAX_OUTPUT = 16384 + 256;

typedef enum : uint8_t {
    IOG_COMPRESS_NONE,
    IOG_COMPRESS_LZ4,
    IOG_COMPRESS_LZS,
} iog_compress_type_t;

typedef struct {
    iog_compress_type_t type;
    void *codec_ctx;
} iog_compress_ctx_t;

[[nodiscard]] int iog_compress_init(iog_compress_ctx_t *ctx, iog_compress_type_t type);

[[nodiscard]] int iog_compress(iog_compress_ctx_t *ctx, const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t out_size);

[[nodiscard]] int iog_decompress(iog_compress_ctx_t *ctx, const uint8_t *in, size_t in_len,
                                 uint8_t *out, size_t out_size);

void iog_compress_destroy(iog_compress_ctx_t *ctx);

[[nodiscard]] const char *iog_compress_type_name(iog_compress_type_t type);

[[nodiscard]] iog_compress_type_t iog_compress_negotiate(const char *accept_encoding);

#endif /* IOGUARD_NETWORK_COMPRESS_H */
