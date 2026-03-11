#include "network/compress.h"
#include "network/compress_lz4.h"
#include "network/compress_lzs.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int iog_compress_init(iog_compress_ctx_t *ctx, iog_compress_type_t type)
{
    if (!ctx) {
        return -EINVAL;
    }

    ctx->type = type;
    ctx->codec_ctx = nullptr;

    switch (type) {
    case IOG_COMPRESS_NONE:
        return 0;
    case IOG_COMPRESS_LZS: {
        iog_lzs_ctx_t *lzs = calloc(1, sizeof(*lzs));
        if (!lzs) {
            return -ENOMEM;
        }
        iog_lzs_init(lzs);
        ctx->codec_ctx = lzs;
        return 0;
    }
    case IOG_COMPRESS_LZ4:
        return 0;
    }
    return -EINVAL;
}

int iog_compress(iog_compress_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
                size_t out_size)
{
    if (!ctx || !in || !out) {
        return -EINVAL;
    }
    if (in_len > IOG_COMPRESS_MAX_INPUT) {
        return -EINVAL;
    }

    if (ctx->type == IOG_COMPRESS_NONE) {
        if (out_size < in_len) {
            return -ENOSPC;
        }
        memcpy(out, in, in_len);
        return (int)in_len;
    }

    if (ctx->type == IOG_COMPRESS_LZS) {
        return iog_lzs_compress(ctx->codec_ctx, in, in_len, out, out_size);
    }

    if (ctx->type == IOG_COMPRESS_LZ4) {
        return rw_lz4_compress(in, in_len, out, out_size);
    }

    return -ENOTSUP;
}

int iog_decompress(iog_compress_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
                  size_t out_size)
{
    if (!ctx || !in || !out) {
        return -EINVAL;
    }

    if (ctx->type == IOG_COMPRESS_NONE) {
        if (out_size < in_len) {
            return -ENOSPC;
        }
        memcpy(out, in, in_len);
        return (int)in_len;
    }

    if (ctx->type == IOG_COMPRESS_LZS) {
        return iog_lzs_decompress(ctx->codec_ctx, in, in_len, out, out_size);
    }

    if (ctx->type == IOG_COMPRESS_LZ4) {
        return rw_lz4_decompress(in, in_len, out, out_size);
    }

    return -ENOTSUP;
}

void iog_compress_destroy(iog_compress_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->type == IOG_COMPRESS_LZS) {
        free(ctx->codec_ctx);
    }
    ctx->codec_ctx = nullptr;
    ctx->type = IOG_COMPRESS_NONE;
}

const char *iog_compress_type_name(iog_compress_type_t type)
{
    switch (type) {
    case IOG_COMPRESS_NONE:
        return "none";
    case IOG_COMPRESS_LZ4:
        return "lz4";
    case IOG_COMPRESS_LZS:
        return "lzs";
    }
    return "unknown";
}

iog_compress_type_t iog_compress_negotiate(const char *accept_encoding)
{
    if (!accept_encoding) {
        return IOG_COMPRESS_NONE;
    }
    if (strstr(accept_encoding, "lz4")) {
        return IOG_COMPRESS_LZ4;
    }
    if (strstr(accept_encoding, "lzs")) {
        return IOG_COMPRESS_LZS;
    }
    return IOG_COMPRESS_NONE;
}
