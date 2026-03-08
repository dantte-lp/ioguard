#include "network/compress_lzs.h"

#include <errno.h>
#include <string.h>

/* Bit writer helper */
typedef struct {
    uint8_t *buf;
    size_t capacity;
    size_t byte_pos;
    uint8_t bit_pos; /* 0-7, MSB first */
} bit_writer_t;

/* Bit reader helper */
typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t byte_pos;
    uint8_t bit_pos;
} bit_reader_t;

static void bw_init(bit_writer_t *bw, uint8_t *buf, size_t cap)
{
    bw->buf = buf;
    bw->capacity = cap;
    bw->byte_pos = 0;
    bw->bit_pos = 0;
    if (cap > 0) {
        buf[0] = 0;
    }
}

static int bw_write_bit(bit_writer_t *bw, uint8_t bit)
{
    if (bw->byte_pos >= bw->capacity) {
        return -ENOSPC;
    }
    if (bit) {
        bw->buf[bw->byte_pos] |= (uint8_t)(0x80 >> bw->bit_pos);
    }
    bw->bit_pos++;
    if (bw->bit_pos == 8) {
        bw->bit_pos = 0;
        bw->byte_pos++;
        if (bw->byte_pos < bw->capacity) {
            bw->buf[bw->byte_pos] = 0;
        }
    }
    return 0;
}

static int bw_write_bits(bit_writer_t *bw, uint32_t val, int nbits)
{
    for (int i = nbits - 1; i >= 0; i--) {
        int ret = bw_write_bit(bw, (uint8_t)((val >> i) & 1));
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

static size_t bw_bytes_written(const bit_writer_t *bw)
{
    return bw->bit_pos > 0 ? bw->byte_pos + 1 : bw->byte_pos;
}

static void br_init(bit_reader_t *br, const uint8_t *buf, size_t len)
{
    br->buf = buf;
    br->len = len;
    br->byte_pos = 0;
    br->bit_pos = 0;
}

static int br_read_bit(bit_reader_t *br)
{
    if (br->byte_pos >= br->len) {
        return -EAGAIN;
    }
    int bit = (br->buf[br->byte_pos] >> (7 - br->bit_pos)) & 1;
    br->bit_pos++;
    if (br->bit_pos == 8) {
        br->bit_pos = 0;
        br->byte_pos++;
    }
    return bit;
}

static int br_read_bits(bit_reader_t *br, int nbits)
{
    uint32_t val = 0;
    for (int i = 0; i < nbits; i++) {
        int bit = br_read_bit(br);
        if (bit < 0) {
            return bit;
        }
        val = (val << 1) | (uint32_t)bit;
    }
    return (int)val;
}

void rw_lzs_init(rw_lzs_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void rw_lzs_reset(rw_lzs_ctx_t *ctx)
{
    memset(ctx->window, 0, sizeof(ctx->window));
    ctx->window_pos = 0;
}

static void window_add(rw_lzs_ctx_t *ctx, uint8_t byte)
{
    ctx->window[ctx->window_pos % RW_LZS_WINDOW_SIZE] = byte;
    ctx->window_pos++;
}

/* Find longest match in sliding window */
static int find_match(const rw_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len,
                      size_t *match_offset, size_t *match_len)
{
    size_t best_len = 0;
    size_t best_off = 0;
    size_t win_used = ctx->window_pos < RW_LZS_WINDOW_SIZE ? ctx->window_pos : RW_LZS_WINDOW_SIZE;

    for (size_t off = 1; off <= win_used; off++) {
        size_t wi = (ctx->window_pos - off) % RW_LZS_WINDOW_SIZE;
        size_t len = 0;
        while (len < in_len && len < RW_LZS_MAX_MATCH) {
            size_t ci = (wi + len) % RW_LZS_WINDOW_SIZE;
            if (ctx->window[ci] != in[len]) {
                break;
            }
            len++;
        }
        if (len >= RW_LZS_MIN_MATCH && len > best_len) {
            best_len = len;
            best_off = off;
        }
    }

    if (best_len >= RW_LZS_MIN_MATCH) {
        *match_offset = best_off;
        *match_len = best_len;
        return 1;
    }
    return 0;
}

/* Encode match length: 2=00, 3=01, 4=10, 5-7=1100-1110, 8+=11110000... */
static int encode_length(bit_writer_t *bw, size_t length)
{
    if (length <= 4) {
        return bw_write_bits(bw, (uint32_t)(length - 2), 2);
    } else if (length <= 7) {
        int ret = bw_write_bits(bw, 0x3, 2); /* 11 prefix */
        if (ret < 0) {
            return ret;
        }
        return bw_write_bits(bw, (uint32_t)(length - 5), 2);
    } else {
        /* length >= 8: encode as 1111 + (length-8) in 4-bit chunks */
        int ret = bw_write_bits(bw, 0xF, 4);
        if (ret < 0) {
            return ret;
        }
        size_t rem = length - 8;
        while (rem >= 15) {
            ret = bw_write_bits(bw, 0xF, 4);
            if (ret < 0) {
                return ret;
            }
            rem -= 15;
        }
        return bw_write_bits(bw, (uint32_t)rem, 4);
    }
}

int rw_lzs_compress(rw_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
                    size_t out_size)
{
    if (!ctx || !in || !out) {
        return -EINVAL;
    }
    if (in_len == 0) {
        /* Write end marker only */
        bit_writer_t bw;
        bw_init(&bw, out, out_size);
        int ret = bw_write_bit(&bw, 1);
        if (ret < 0) {
            return ret;
        }
        ret = bw_write_bits(&bw, 0x000, 11);
        if (ret < 0) {
            return ret;
        }
        return (int)bw_bytes_written(&bw);
    }

    bit_writer_t bw;
    bw_init(&bw, out, out_size);

    size_t pos = 0;
    while (pos < in_len) {
        size_t match_off, match_len;
        if (find_match(ctx, in + pos, in_len - pos, &match_off, &match_len)) {
            /* Match: 1-bit + 11-bit offset + variable length */
            int ret = bw_write_bit(&bw, 1);
            if (ret < 0) {
                return ret;
            }
            ret = bw_write_bits(&bw, (uint32_t)match_off, 11);
            if (ret < 0) {
                return ret;
            }
            ret = encode_length(&bw, match_len);
            if (ret < 0) {
                return ret;
            }
            for (size_t i = 0; i < match_len; i++) {
                window_add(ctx, in[pos + i]);
            }
            pos += match_len;
        } else {
            /* Literal: 0-bit + 8-bit value */
            int ret = bw_write_bit(&bw, 0);
            if (ret < 0) {
                return ret;
            }
            ret = bw_write_bits(&bw, in[pos], 8);
            if (ret < 0) {
                return ret;
            }
            window_add(ctx, in[pos]);
            pos++;
        }
    }

    /* End marker: 1-bit flag + 11 zero bits (offset=0) */
    int ret = bw_write_bit(&bw, 1);
    if (ret < 0) {
        return ret;
    }
    ret = bw_write_bits(&bw, 0x000, 11);
    if (ret < 0) {
        return ret;
    }

    return (int)bw_bytes_written(&bw);
}

int rw_lzs_decompress(rw_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
                      size_t out_size)
{
    if (!ctx || !in || !out) {
        return -EINVAL;
    }

    bit_reader_t br;
    br_init(&br, in, in_len);

    size_t out_pos = 0;

    while (1) {
        int bit = br_read_bit(&br);
        if (bit < 0) {
            break; /* end of input */
        }

        if (bit == 0) {
            /* Literal */
            int val = br_read_bits(&br, 8);
            if (val < 0) {
                break;
            }
            if (out_pos >= out_size) {
                return -ENOSPC;
            }
            out[out_pos++] = (uint8_t)val;
            window_add(ctx, (uint8_t)val);
        } else {
            /* Match or end marker */
            int offset = br_read_bits(&br, 11);
            if (offset < 0) {
                break;
            }
            if (offset == 0) {
                break; /* end marker: 1 + 00000000000 */
            }

            /* Decode length */
            int len_bits = br_read_bits(&br, 2);
            if (len_bits < 0) {
                break;
            }
            size_t length;
            if (len_bits <= 2) {
                length = (size_t)len_bits + 2;
            } else { /* len_bits == 3 */
                int ext = br_read_bits(&br, 2);
                if (ext < 0) {
                    break;
                }
                if (ext <= 2) {
                    length = (size_t)ext + 5;
                } else {
                    /* Extended: read 4-bit chunks */
                    length = 8;
                    while (1) {
                        int chunk = br_read_bits(&br, 4);
                        if (chunk < 0) {
                            return chunk;
                        }
                        length += (size_t)chunk;
                        if (chunk < 15) {
                            break;
                        }
                    }
                }
            }

            /* Copy from window */
            for (size_t i = 0; i < length; i++) {
                size_t wi = (ctx->window_pos - (size_t)offset) % RW_LZS_WINDOW_SIZE;
                if (out_pos >= out_size) {
                    return -ENOSPC;
                }
                uint8_t byte = ctx->window[wi];
                out[out_pos++] = byte;
                window_add(ctx, byte);
            }
        }
    }

    return (int)out_pos;
}
