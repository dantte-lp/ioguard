#include "network/compress_lzs.h"
#include "network/cstp.h"

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

void iog_lzs_init(iog_lzs_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    memset(ctx->hash_head, 0xFF, sizeof(ctx->hash_head));
    memset(ctx->hash_chain, 0xFF, sizeof(ctx->hash_chain));
}

void iog_lzs_reset(iog_lzs_ctx_t *ctx)
{
    memset(ctx->window, 0, sizeof(ctx->window));
    ctx->window_pos = 0;
    memset(ctx->hash_head, 0xFF, sizeof(ctx->hash_head));
    memset(ctx->hash_chain, 0xFF, sizeof(ctx->hash_chain));
}

static void window_add(iog_lzs_ctx_t *ctx, uint8_t byte)
{
    ctx->window[ctx->window_pos % IOG_LZS_WINDOW_SIZE] = byte;
    ctx->window_pos++;
}

static inline uint32_t lzs_hash(uint8_t b0, uint8_t b1)
{
    return (((uint32_t)b0 << 4) ^ (uint32_t)b1) & (IOG_LZS_HASH_SIZE - 1);
}

/* Insert current window position into the hash chain */
static void hash_insert(iog_lzs_ctx_t *ctx, uint16_t win_idx, uint32_t h)
{
    ctx->hash_chain[win_idx] = ctx->hash_head[h];
    ctx->hash_head[h] = win_idx;
}

/* Find longest match using hash-chain lookup */
static int find_match(iog_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len, size_t *match_offset,
                      size_t *match_len)
{
    if (in_len < IOG_LZS_MIN_MATCH) {
        return 0;
    }

    size_t win_used = ctx->window_pos < IOG_LZS_WINDOW_SIZE ? ctx->window_pos : IOG_LZS_WINDOW_SIZE;
    if (win_used == 0) {
        return 0;
    }

    uint32_t h = lzs_hash(in[0], in[1]);
    uint16_t pos = ctx->hash_head[h];
    size_t best_len = 0;
    size_t best_off = 0;
    uint32_t steps = 0;

    while (pos != IOG_LZS_HASH_NIL && steps < IOG_LZS_MAX_CHAIN) {
        /* Convert absolute window index to offset from current window_pos */
        size_t cur_win = ctx->window_pos % IOG_LZS_WINDOW_SIZE;
        size_t off;
        if (cur_win > pos) {
            off = cur_win - pos;
        } else {
            off = cur_win + IOG_LZS_WINDOW_SIZE - pos;
        }

        /* Offset must be within valid window range and encodable in 11 bits */
        if (off >= 1 && off <= win_used && off < IOG_LZS_WINDOW_SIZE) {
            size_t wi = pos;
            size_t len = 0;
            while (len < in_len && len < IOG_LZS_MAX_MATCH) {
                size_t ci = (wi + len) % IOG_LZS_WINDOW_SIZE;
                if (ctx->window[ci] != in[len]) {
                    break;
                }
                len++;
            }
            if (len >= IOG_LZS_MIN_MATCH && len > best_len) {
                best_len = len;
                best_off = off;
                if (best_len == IOG_LZS_MAX_MATCH) {
                    break; /* can't do better */
                }
            }
        }

        pos = ctx->hash_chain[pos];
        steps++;
    }

    if (best_len >= IOG_LZS_MIN_MATCH) {
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

int iog_lzs_compress(iog_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
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
                /* Insert hash for 2-byte pair starting at this position */
                if (pos + i + 1 < in_len) {
                    uint16_t wi = (uint16_t)(ctx->window_pos % IOG_LZS_WINDOW_SIZE);
                    uint32_t h = lzs_hash(in[pos + i], in[pos + i + 1]);
                    hash_insert(ctx, wi, h);
                }
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
            /* Insert hash for 2-byte pair starting at this position */
            if (pos + 1 < in_len) {
                uint16_t wi = (uint16_t)(ctx->window_pos % IOG_LZS_WINDOW_SIZE);
                uint32_t h = lzs_hash(in[pos], in[pos + 1]);
                hash_insert(ctx, wi, h);
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

int iog_lzs_decompress(iog_lzs_ctx_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out,
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
                    /* Reject absurd lengths to prevent CPU exhaustion */
                    if (length > IOG_CSTP_MAX_PAYLOAD) {
                        return -EINVAL;
                    }
                }
            }

            /* Copy from window */
            for (size_t i = 0; i < length; i++) {
                size_t wi = (ctx->window_pos - (size_t)offset) % IOG_LZS_WINDOW_SIZE;
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
