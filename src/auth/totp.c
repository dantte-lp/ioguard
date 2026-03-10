#include "auth/totp.h"

#include <errno.h>
#include <string.h>

/**
 * RFC 4648 Base32 alphabet lookup.
 * Returns 0-31 for valid characters, -1 for invalid.
 */
static int base32_char_value(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a';
	if (c >= '2' && c <= '7')
		return c - '2' + 26;
	return -1;
}

ssize_t rw_base32_decode(const char *encoded, uint8_t *out, size_t out_size)
{
	if (encoded == nullptr || out == nullptr)
		return -EINVAL;

	size_t len = strnlen(encoded, RW_TOTP_SECRET_B32_MAX + 1);

	/* Strip trailing padding */
	while (len > 0 && encoded[len - 1] == '=')
		len--;

	if (len == 0)
		return 0;

	/* Calculate decoded size: every 8 base32 chars produce 5 bytes.
	 * For partial groups: bits = len * 5, bytes = bits / 8 */
	size_t total_bits = len * 5;
	size_t decoded_len = total_bits / 8;

	if (decoded_len > out_size)
		return -ENOSPC;

	uint64_t buffer = 0;
	int bits_in_buffer = 0;
	size_t out_idx = 0;

	for (size_t i = 0; i < len; i++) {
		int val = base32_char_value(encoded[i]);
		if (val < 0)
			return -EINVAL;

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

int rw_totp_generate([[maybe_unused]] const uint8_t *secret,
                     [[maybe_unused]] size_t secret_len,
                     [[maybe_unused]] uint64_t time_step,
                     [[maybe_unused]] uint32_t *code_out)
{
	return -ENOTSUP;
}

int rw_totp_validate([[maybe_unused]] const uint8_t *secret,
                     [[maybe_unused]] size_t secret_len,
                     [[maybe_unused]] uint32_t code,
                     [[maybe_unused]] uint64_t time_now,
                     [[maybe_unused]] uint32_t window)
{
	return -ENOTSUP;
}

int rw_totp_generate_secret([[maybe_unused]] uint8_t *secret,
                            [[maybe_unused]] size_t secret_len)
{
	return -ENOTSUP;
}

ssize_t rw_totp_build_uri([[maybe_unused]] const uint8_t *secret,
                          [[maybe_unused]] size_t secret_len,
                          [[maybe_unused]] const char *issuer,
                          [[maybe_unused]] const char *account,
                          [[maybe_unused]] char *uri_out,
                          [[maybe_unused]] size_t uri_size)
{
	return -ENOTSUP;
}
