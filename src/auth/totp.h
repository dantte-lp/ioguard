#ifndef IOGUARD_AUTH_TOTP_H
#define IOGUARD_AUTH_TOTP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/** TOTP time step in seconds (RFC 6238). */
constexpr uint32_t IOG_TOTP_TIME_STEP = 30;

/** Number of TOTP digits in the output code. */
constexpr uint32_t IOG_TOTP_DIGITS = 6;

/** Raw TOTP secret size in bytes (160-bit SHA-1 key). */
constexpr size_t IOG_TOTP_SECRET_SIZE = 20;

/** Maximum Base32-encoded secret length (including NUL). */
constexpr size_t IOG_TOTP_SECRET_B32_MAX = 64;

/**
 * Decode a Base32-encoded string (RFC 4648).
 *
 * Accepts uppercase and lowercase input, with or without '=' padding.
 *
 * @param encoded  NUL-terminated Base32-encoded string.
 * @param out      Output buffer for decoded bytes.
 * @param out_size Size of the output buffer in bytes.
 * @return Number of decoded bytes on success, -EINVAL on invalid character,
 *         -ENOSPC if the output buffer is too small.
 */
[[nodiscard]] ssize_t iog_base32_decode(const char *encoded, uint8_t *out, size_t out_size);

/**
 * Generate a TOTP code for the given secret and time.
 *
 * @param secret     Raw secret bytes (IOG_TOTP_SECRET_SIZE).
 * @param secret_len Length of the secret in bytes.
 * @param time_step  Time counter value (unix_time / IOG_TOTP_TIME_STEP).
 * @param code_out   Pointer to store the generated numeric code.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_totp_generate(const uint8_t *secret, size_t secret_len, uint64_t time_step,
                                    uint32_t *code_out);

/**
 * Validate a TOTP code against the current time with a tolerance window.
 *
 * @param secret     Raw secret bytes.
 * @param secret_len Length of the secret in bytes.
 * @param code       The numeric TOTP code to validate.
 * @param time_now   Current Unix timestamp.
 * @param window     Number of time steps to check before/after current.
 * @return 0 on success (code valid), negative errno on failure or mismatch.
 */
[[nodiscard]] int iog_totp_validate(const uint8_t *secret, size_t secret_len, uint32_t code,
                                    uint64_t time_now, uint32_t window);

/**
 * Generate a random TOTP secret.
 *
 * @param secret     Output buffer for the raw secret (IOG_TOTP_SECRET_SIZE bytes).
 * @param secret_len Size of the output buffer.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_totp_generate_secret(uint8_t *secret, size_t secret_len);

/**
 * Build an otpauth:// URI for QR code provisioning.
 *
 * @param secret     Raw secret bytes.
 * @param secret_len Length of the secret in bytes.
 * @param issuer     Issuer name (e.g., "ioguard").
 * @param account    Account identifier (e.g., username or email).
 * @param uri_out    Output buffer for the URI string.
 * @param uri_size   Size of the URI output buffer.
 * @return Number of bytes written (excluding NUL) on success, negative errno on failure.
 */
[[nodiscard]] ssize_t iog_totp_build_uri(const uint8_t *secret, size_t secret_len,
                                         const char *issuer, const char *account, char *uri_out,
                                         size_t uri_size);

#endif /* IOGUARD_AUTH_TOTP_H */
