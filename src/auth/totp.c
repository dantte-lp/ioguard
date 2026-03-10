#include "auth/totp.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_WOLFSSL
#    include <wolfssl/options.h>
#    include <wolfssl/wolfcrypt/hmac.h>
#    include <wolfssl/wolfcrypt/random.h>
#endif

/**
 * RFC 4648 Base32 alphabet lookup.
 * Returns 0-31 for valid characters, -1 for invalid.
 */
static int base32_char_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }
    return -1;
}

ssize_t rw_base32_decode(const char *encoded, uint8_t *out, size_t out_size)
{
    if (encoded == nullptr || out == nullptr) {
        return -EINVAL;
    }

    size_t len = strnlen(encoded, RW_TOTP_SECRET_B32_MAX + 1);

    /* Strip trailing padding */
    while (len > 0 && encoded[len - 1] == '=') {
        len--;
    }

    if (len == 0) {
        return 0;
    }

    /* Calculate decoded size: every 8 base32 chars produce 5 bytes.
     * For partial groups: bits = len * 5, bytes = bits / 8 */
    size_t total_bits = len * 5;
    size_t decoded_len = total_bits / 8;

    if (decoded_len > out_size) {
        return -ENOSPC;
    }

    uint64_t buffer = 0;
    int bits_in_buffer = 0;
    size_t out_idx = 0;

    for (size_t i = 0; i < len; i++) {
        int val = base32_char_value(encoded[i]);
        if (val < 0) {
            return -EINVAL;
        }

        buffer = (buffer << 5) | (uint64_t)val;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            out[out_idx++] = (uint8_t)(buffer >> bits_in_buffer);
            buffer &= ((uint64_t)1 << bits_in_buffer) - 1;
        }
    }

    return (ssize_t)out_idx;
}

int rw_totp_generate(const uint8_t *secret, size_t secret_len, uint64_t time_step,
                     uint32_t *code_out)
{
    if (secret == nullptr || secret_len == 0 || code_out == nullptr) {
        return -EINVAL;
    }

#ifdef USE_WOLFSSL
    /* Encode time_step as 8-byte big-endian message (RFC 4226 §5.2) */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(time_step & 0xFF);
        time_step >>= 8;
    }

    /* HMAC-SHA1 */
    Hmac hmac;
    uint8_t hash[20]; /* SHA-1 output is 20 bytes */
    int ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA, secret, (word32)secret_len);
    if (ret != 0) {
        goto hmac_err;
    }

    ret = wc_HmacUpdate(&hmac, msg, sizeof(msg));
    if (ret != 0) {
        goto hmac_err;
    }

    ret = wc_HmacFinal(&hmac, hash);
    if (ret != 0) {
        goto hmac_err;
    }

    wc_HmacFree(&hmac);

    /* Dynamic truncation (RFC 4226 §5.4) */
    int offset = hash[19] & 0x0F;
    uint32_t bin_code = ((uint32_t)(hash[offset] & 0x7F) << 24) |
                        ((uint32_t)hash[offset + 1] << 16) | ((uint32_t)hash[offset + 2] << 8) |
                        (uint32_t)hash[offset + 3];
    *code_out = bin_code % 1000000; /* 6 digits */

    explicit_bzero(hash, sizeof(hash));
    explicit_bzero(msg, sizeof(msg));
    return 0;

hmac_err:
    wc_HmacFree(&hmac);
    explicit_bzero(hash, sizeof(hash));
    explicit_bzero(msg, sizeof(msg));
    return -EIO;
#else
    return -ENOTSUP;
#endif
}

int rw_totp_validate(const uint8_t *secret, size_t secret_len, uint32_t code, uint64_t time_now,
                     uint32_t window)
{
    if (secret == nullptr || secret_len == 0) {
        return -EINVAL;
    }

    uint64_t current_counter = time_now / RW_TOTP_TIME_STEP;

    for (uint32_t i = 0; i <= window; i++) {
        uint32_t candidate = 0;
        int ret;

        /* Check current counter (or forward drift for i>0) */
        ret = rw_totp_generate(secret, secret_len, current_counter + i, &candidate);
        if (ret != 0) {
            return ret;
        }
        if (candidate == code) {
            return 0;
        }

        /* Check backward drift (i>0 only, guard underflow) */
        if (i > 0 && current_counter >= i) {
            ret = rw_totp_generate(secret, secret_len, current_counter - i, &candidate);
            if (ret != 0) {
                return ret;
            }
            if (candidate == code) {
                return 0;
            }
        }
    }

    return -EACCES;
}

/**
 * RFC 4648 Base32 encoding alphabet.
 */
static const char B32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static ssize_t base32_encode(const uint8_t *data, size_t data_len, char *out, size_t out_size)
{
    if (data == nullptr || out == nullptr) {
        return -EINVAL;
    }

    size_t needed = ((data_len * 8 + 4) / 5) + 1;
    if (needed > out_size) {
        return -ENOSPC;
    }

    size_t idx = 0;
    uint64_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < data_len; i++) {
        buf = (buf << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[idx++] = B32_ALPHA[(buf >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out[idx++] = B32_ALPHA[(buf << (5 - bits)) & 0x1F];
    }

    out[idx] = '\0';
    return (ssize_t)idx;
}

int rw_totp_generate_secret(uint8_t *secret, size_t secret_len)
{
    if (secret == nullptr || secret_len == 0) {
        return -EINVAL;
    }

#ifdef USE_WOLFSSL
    WC_RNG rng;

    if (wc_InitRng(&rng) != 0) {
        return -EIO;
    }

    int ret = wc_RNG_GenerateBlock(&rng, secret, (word32)secret_len);
    wc_FreeRng(&rng);

    if (ret != 0) {
        return -EIO;
    }

    return 0;
#else
    return -ENOTSUP;
#endif
}

ssize_t rw_totp_build_uri(const uint8_t *secret, size_t secret_len, const char *issuer,
                          const char *account, char *uri_out, size_t uri_size)
{
    if (secret == nullptr || secret_len == 0 || issuer == nullptr || account == nullptr ||
        uri_out == nullptr || uri_size == 0) {
        return -EINVAL;
    }

    /* Base32-encode the secret */
    char b32[RW_TOTP_SECRET_B32_MAX];
    ssize_t b32_len = base32_encode(secret, secret_len, b32, sizeof(b32));
    if (b32_len < 0) {
        return b32_len;
    }

    int written = snprintf(uri_out, uri_size,
                           "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30", issuer,
                           account, b32, issuer);

    if (written < 0) {
        return -EIO;
    }

    if ((size_t)written >= uri_size) {
        return -ENOSPC;
    }

    return (ssize_t)written;
}
