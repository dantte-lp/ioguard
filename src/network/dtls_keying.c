#include "network/dtls_keying.h"

#include <errno.h>
#include <string.h>

static constexpr char hex_chars[] = "0123456789abcdef";

int rw_dtls_hex_encode(const uint8_t *in, size_t in_len,
                        char *hex, size_t hex_size)
{
	if (!in || !hex)
		return -EINVAL;
	if (hex_size < in_len * 2 + 1)
		return -ENOSPC;

	for (size_t i = 0; i < in_len; i++) {
		hex[i * 2]     = hex_chars[(in[i] >> 4) & 0x0F];
		hex[i * 2 + 1] = hex_chars[in[i] & 0x0F];
	}
	hex[in_len * 2] = '\0';
	return 0;
}

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int rw_dtls_hex_decode(const char *hex, size_t hex_len,
                        uint8_t *out, size_t out_size)
{
	if (!hex || !out)
		return -EINVAL;
	if (hex_len % 2 != 0)
		return -EINVAL;

	size_t out_len = hex_len / 2;
	if (out_size < out_len)
		return -ENOSPC;

	for (size_t i = 0; i < out_len; i++) {
		int hi = hex_digit(hex[i * 2]);
		int lo = hex_digit(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return (int)out_len;
}

void rw_dtls_master_secret_clear(rw_dtls_master_secret_t *ms)
{
	if (!ms)
		return;
	explicit_bzero(ms->secret, sizeof(ms->secret));
	explicit_bzero(ms->hex, sizeof(ms->hex));
	ms->valid = false;
}
