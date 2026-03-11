#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "core/worker.h"
#include "network/compress.h"
#include "network/cstp.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_cstp_encode_compressed_type(void)
{
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t buf[IOG_CSTP_HEADER_SIZE + 4];

    int encoded = rw_cstp_encode(buf, sizeof(buf), IOG_CSTP_COMPRESSED, data, sizeof(data));
    TEST_ASSERT_EQUAL_INT((int)(IOG_CSTP_HEADER_SIZE + 4), encoded);

    rw_cstp_packet_t pkt;
    int consumed = rw_cstp_decode(buf, (size_t)encoded, &pkt);
    TEST_ASSERT_EQUAL_INT(encoded, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_COMPRESSED, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(4, pkt.payload_len);
}

void test_compress_none_cstp_roundtrip(void)
{
    /* Compress with NONE, wrap in CSTP COMPRESSED, decode, decompress */
    iog_compress_ctx_t comp;
    (void)iog_compress_init(&comp, IOG_COMPRESS_NONE);

    const uint8_t payload[] = "Hello, VPN!";
    uint8_t compressed[64];

    int clen = iog_compress(&comp, payload, sizeof(payload) - 1, compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);

    /* Wrap compressed data in CSTP COMPRESSED frame */
    uint8_t frame[IOG_CSTP_HEADER_SIZE + 64];
    int flen = rw_cstp_encode(frame, sizeof(frame), IOG_CSTP_COMPRESSED, compressed, (size_t)clen);
    TEST_ASSERT_GREATER_THAN(0, flen);

    /* Decode CSTP frame */
    rw_cstp_packet_t pkt;
    int consumed = rw_cstp_decode(frame, (size_t)flen, &pkt);
    TEST_ASSERT_EQUAL_INT(flen, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_COMPRESSED, pkt.type);

    /* Decompress */
    uint8_t decompressed[64];
    int dlen =
        iog_decompress(&comp, pkt.payload, pkt.payload_len, decompressed, sizeof(decompressed));
    TEST_ASSERT_EQUAL_INT((int)(sizeof(payload) - 1), dlen);
    TEST_ASSERT_EQUAL_MEMORY(payload, decompressed, sizeof(payload) - 1);

    iog_compress_destroy(&comp);
}

void test_compress_lzs_cstp_roundtrip(void)
{
    iog_compress_ctx_t comp;
    int ret = iog_compress_init(&comp, IOG_COMPRESS_LZS);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const uint8_t payload[] = "AAAAAAAAAAAAAAAA"; /* repeated for compression */
    uint8_t compressed[128];

    int clen = iog_compress(&comp, payload, sizeof(payload) - 1, compressed, sizeof(compressed));
    TEST_ASSERT_GREATER_THAN(0, clen);

    /* Wrap in CSTP frame */
    uint8_t frame[IOG_CSTP_HEADER_SIZE + 128];
    int flen = rw_cstp_encode(frame, sizeof(frame), IOG_CSTP_COMPRESSED, compressed, (size_t)clen);
    TEST_ASSERT_GREATER_THAN(0, flen);

    /* Decode CSTP + decompress with fresh context */
    iog_compress_ctx_t decomp;
    ret = iog_compress_init(&decomp, IOG_COMPRESS_LZS);
    TEST_ASSERT_EQUAL_INT(0, ret);

    rw_cstp_packet_t pkt;
    (void)rw_cstp_decode(frame, (size_t)flen, &pkt);

    uint8_t decompressed[64];
    int dlen =
        iog_decompress(&decomp, pkt.payload, pkt.payload_len, decompressed, sizeof(decompressed));
    TEST_ASSERT_EQUAL_INT((int)(sizeof(payload) - 1), dlen);
    TEST_ASSERT_EQUAL_MEMORY(payload, decompressed, sizeof(payload) - 1);

    iog_compress_destroy(&comp);
    iog_compress_destroy(&decomp);
}

void test_worker_connection_has_compress(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t conn_id = iog_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(0, conn_id);

    iog_connection_t *conn = iog_worker_find_connection(w, (uint64_t)conn_id);
    TEST_ASSERT_NOT_NULL(conn);
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_NONE, conn->compress.type);

    (void)iog_worker_remove_connection(w, (uint64_t)conn_id);
    iog_worker_destroy(w);
}

void test_data_cstp_not_compressed(void)
{
    /* DATA type should not be treated as compressed */
    const uint8_t data[] = {0xDE, 0xAD};
    uint8_t buf[IOG_CSTP_HEADER_SIZE + 2];

    int encoded = rw_cstp_encode(buf, sizeof(buf), IOG_CSTP_DATA, data, sizeof(data));
    TEST_ASSERT_GREATER_THAN(0, encoded);

    rw_cstp_packet_t pkt;
    int consumed = rw_cstp_decode(buf, (size_t)encoded, &pkt);
    TEST_ASSERT_EQUAL_INT(encoded, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DATA, pkt.type);
    /* DATA payload is raw, not compressed */
    TEST_ASSERT_EQUAL_MEMORY(data, pkt.payload, sizeof(data));
}

void test_compress_type_in_connection(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 2;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t cid = iog_worker_add_connection(w, 5, 6);
    iog_connection_t *conn = iog_worker_find_connection(w, (uint64_t)cid);
    TEST_ASSERT_NOT_NULL(conn);

    /* Default is NONE */
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_NONE, conn->compress.type);

    /* Can reinit to LZS */
    iog_compress_destroy(&conn->compress);
    int ret = iog_compress_init(&conn->compress, IOG_COMPRESS_LZS);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT8(IOG_COMPRESS_LZS, conn->compress.type);

    (void)iog_worker_remove_connection(w, (uint64_t)cid);
    iog_worker_destroy(w);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cstp_encode_compressed_type);
    RUN_TEST(test_compress_none_cstp_roundtrip);
    RUN_TEST(test_compress_lzs_cstp_roundtrip);
    RUN_TEST(test_worker_connection_has_compress);
    RUN_TEST(test_data_cstp_not_compressed);
    RUN_TEST(test_compress_type_in_connection);
    return UNITY_END();
}
