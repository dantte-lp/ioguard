/**
 * @file dtls_keying.h
 * @brief DTLS master secret export and hex encoding.
 *
 * Hex encode/decode for X-DTLS-Master-Secret HTTP header.
 */

#ifndef IOGUARD_NETWORK_DTLS_KEYING_H
#define IOGUARD_NETWORK_DTLS_KEYING_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t IOG_DTLS_MASTER_SECRET_LEN = 48;
constexpr size_t IOG_DTLS_MASTER_SECRET_HEX_LEN = 96; /* 48 * 2 */

typedef struct {
    uint8_t secret[IOG_DTLS_MASTER_SECRET_LEN];
    char hex[IOG_DTLS_MASTER_SECRET_HEX_LEN + 1];
    bool valid;
} iog_dtls_master_secret_t;

/** Hex encode binary data. Returns 0 or negative errno. */
[[nodiscard]] int iog_dtls_hex_encode(const uint8_t *in, size_t in_len, char *hex, size_t hex_size);

/** Hex decode string to binary. Returns bytes written or negative errno. */
[[nodiscard]] int iog_dtls_hex_decode(const char *hex, size_t hex_len, uint8_t *out,
                                      size_t out_size);

/** Zero out master secret. */
void iog_dtls_master_secret_clear(iog_dtls_master_secret_t *ms);

#endif /* IOGUARD_NETWORK_DTLS_KEYING_H */
