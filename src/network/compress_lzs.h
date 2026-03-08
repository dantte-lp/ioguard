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
