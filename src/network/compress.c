#include "network/compress.h"
#include "network/compress_lzs.h"
#include "network/compress_lz4.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int wg_compress_init(wg_compress_ctx_t *ctx, wg_compress_type_t type)
{
	if (!ctx)
		return -EINVAL;

	ctx->type = type;
	ctx->codec_ctx = nullptr;

	switch (type) {
	case WG_COMPRESS_NONE:
		return 0;
	case WG_COMPRESS_LZS: {
		wg_lzs_ctx_t *lzs = calloc(1, sizeof(*lzs));
		if (!lzs)
			return -ENOMEM;
		wg_lzs_init(lzs);
		ctx->codec_ctx = lzs;
		return 0;
	}
	case WG_COMPRESS_LZ4:
		return 0;
	}
	return -EINVAL;
}

int wg_compress(wg_compress_ctx_t *ctx,
                const uint8_t *in, size_t in_len,
                uint8_t *out, size_t out_size)
{
	if (!ctx || !in || !out)
		return -EINVAL;
	if (in_len > WG_COMPRESS_MAX_INPUT)
		return -EINVAL;

	if (ctx->type == WG_COMPRESS_NONE) {
		if (out_size < in_len)
			return -ENOSPC;
		memcpy(out, in, in_len);
		return (int)in_len;
	}

	if (ctx->type == WG_COMPRESS_LZS)
		return wg_lzs_compress(ctx->codec_ctx, in, in_len, out, out_size);

	if (ctx->type == WG_COMPRESS_LZ4)
		return wg_lz4_compress(in, in_len, out, out_size);

	return -ENOTSUP;
}

int wg_decompress(wg_compress_ctx_t *ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *out, size_t out_size)
{
	if (!ctx || !in || !out)
		return -EINVAL;

	if (ctx->type == WG_COMPRESS_NONE) {
		if (out_size < in_len)
			return -ENOSPC;
		memcpy(out, in, in_len);
		return (int)in_len;
	}

	if (ctx->type == WG_COMPRESS_LZS)
		return wg_lzs_decompress(ctx->codec_ctx, in, in_len, out, out_size);

	if (ctx->type == WG_COMPRESS_LZ4)
		return wg_lz4_decompress(in, in_len, out, out_size);

	return -ENOTSUP;
}

void wg_compress_destroy(wg_compress_ctx_t *ctx)
{
	if (!ctx)
		return;
	if (ctx->type == WG_COMPRESS_LZS) {
		free(ctx->codec_ctx);
	}
	ctx->codec_ctx = nullptr;
	ctx->type = WG_COMPRESS_NONE;
}

const char *wg_compress_type_name(wg_compress_type_t type)
{
	switch (type) {
	case WG_COMPRESS_NONE: return "none";
	case WG_COMPRESS_LZ4:  return "lz4";
	case WG_COMPRESS_LZS:  return "lzs";
	}
	return "unknown";
}

wg_compress_type_t wg_compress_negotiate(const char *accept_encoding)
{
	if (!accept_encoding)
		return WG_COMPRESS_NONE;
	if (strstr(accept_encoding, "lz4"))
		return WG_COMPRESS_LZ4;
	if (strstr(accept_encoding, "lzs"))
		return WG_COMPRESS_LZS;
	return WG_COMPRESS_NONE;
}
