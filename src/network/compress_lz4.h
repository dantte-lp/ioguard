/**
 * @file compress_lz4.h
 * @brief LZ4 compression codec wrapper.
 *
 * Wraps liblz4 for fast compression in VPN data path.
 */

#ifndef IOGUARD_NETWORK_COMPRESS_LZ4_H
#define IOGUARD_NETWORK_COMPRESS_LZ4_H

#include <stddef.h>
#include <stdint.h>

/** Compress using LZ4. Returns bytes written or negative errno. */
[[nodiscard]] int iog_lz4_compress(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size);

/** Decompress using LZ4. Returns bytes written or negative errno. */
[[nodiscard]] int iog_lz4_decompress(const uint8_t *in, size_t in_len, uint8_t *out,
                                     size_t out_size);

#endif /* IOGUARD_NETWORK_COMPRESS_LZ4_H */
