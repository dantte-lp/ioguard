/**
 * @file compress_lzs.h
 * @brief LZS (Lempel-Ziv-Stac) compression codec — RFC 1974.
 *
 * Custom implementation for Cisco Secure Client compatibility.
 * 2048-byte sliding window, bit-oriented output.
 */

#ifndef IOGUARD_NETWORK_COMPRESS_LZS_H
#define IOGUARD_NETWORK_COMPRESS_LZS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t IOG_LZS_WINDOW_SIZE = 2048;
constexpr size_t IOG_LZS_MIN_MATCH = 2;
constexpr size_t IOG_LZS_MAX_MATCH = 255 + 2; /* length encoding limit */

typedef struct {
    uint8_t window[IOG_LZS_WINDOW_SIZE];
    size_t window_pos;
} iog_lzs_ctx_t;

/** Initialize LZS context. */
void iog_lzs_init(iog_lzs_ctx_t *ctx);

/** Reset LZS sliding window. */
void iog_lzs_reset(iog_lzs_ctx_t *ctx);

/** Compress data using LZS. Returns bytes written or negative errno. */
[[nodiscard]] int iog_lzs_compress(iog_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
                                  size_t out_size);

/** Decompress LZS data. Returns bytes written or negative errno. */
[[nodiscard]] int iog_lzs_decompress(iog_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t out_size);

#endif /* IOGUARD_NETWORK_COMPRESS_LZS_H */
