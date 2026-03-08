#include "network/compress_lz4.h"

#include <errno.h>
#include <lz4.h>

int wg_lz4_compress(const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t out_size)
{
	if (!in || !out)
		return -EINVAL;
	if (in_len == 0)
		return 0;

	int ret = LZ4_compress_default((const char *)in, (char *)out,
	                               (int)in_len, (int)out_size);
	if (ret <= 0)
		return -ENOSPC;
	return ret;
}

int wg_lz4_decompress(const uint8_t *in, size_t in_len,
                       uint8_t *out, size_t out_size)
{
	if (!in || !out)
		return -EINVAL;
	if (in_len == 0)
		return 0;

	int ret = LZ4_decompress_safe((const char *)in, (char *)out,
	                              (int)in_len, (int)out_size);
	if (ret < 0)
		return -EINVAL;
	return ret;
}
