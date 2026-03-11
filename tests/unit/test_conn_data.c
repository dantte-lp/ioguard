#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/conn_data.h"
#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

/* ============================================================================
 * Mock TLS I/O over socketpairs
 * ============================================================================ */

static int tls_sv[2]; /* sv[0] = conn_data reads/writes, sv[1] = test injects/reads */
static int tun_sv[2]; /* sv[0] = conn_data writes to, sv[1] = test reads from */

/* Mock read: read from socketpair fd */
static ssize_t mock_tls_read(void *ctx, void *buf, size_t len)
{
    int fd = *(int *)ctx;
    ssize_t n = read(fd, buf, len);
    if (n < 0) {
        return -errno;
    }
    return n;
}

/* Mock write: write to socketpair fd */
static ssize_t mock_tls_write(void *ctx, const void *buf, size_t len)
{
    int fd = *(int *)ctx;
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
        return -errno;
    }
    return n;
}

static iog_dpd_ctx_t dpd;
static iog_compress_ctx_t compress_ctx;

void setUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, tls_sv));
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, tun_sv));
    iog_dpd_init(&dpd, 30, 3);
    TEST_ASSERT_EQUAL_INT(0, iog_compress_init(&compress_ctx, IOG_COMPRESS_NONE));
}

void tearDown(void)
{
    iog_compress_destroy(&compress_ctx);
    close(tls_sv[0]);
    close(tls_sv[1]);
    close(tun_sv[0]);
    close(tun_sv[1]);
}

/* Helper: inject a CSTP-encoded frame into the test end of TLS socketpair */
static int inject_cstp(iog_cstp_type_t type, const uint8_t *payload, size_t payload_len)
{
    uint8_t buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];
    int encoded = iog_cstp_encode(buf, sizeof(buf), type, payload, payload_len);
    if (encoded < 0) {
        return encoded;
    }
    ssize_t written = write(tls_sv[1], buf, (size_t)encoded);
    if (written < 0) {
        return -errno;
    }
    return (int)written;
}

/* Helper: create initialized conn_data with mock I/O */
static int make_conn_data(iog_conn_data_t *data)
{
    iog_conn_data_config_t cfg = {
        .tls_read = mock_tls_read,
        .tls_write = mock_tls_write,
        .tls_ctx = &tls_sv[0],
        .tun_fd = tun_sv[0],
        .dpd = &dpd,
        .compress = &compress_ctx,
    };
    return iog_conn_data_init(data, &cfg);
}

/* ============================================================================
 * Tests
 * ============================================================================ */

void test_conn_data_init_destroy(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));
    TEST_ASSERT_NOT_NULL(data.tls_read);
    TEST_ASSERT_NOT_NULL(data.tls_write);
    TEST_ASSERT_FALSE(data.disconnected);
    TEST_ASSERT_EQUAL_UINT(0, data.recv_len);
}

void test_conn_data_tls_to_tun(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Inject a DATA packet into mock TLS */
    const uint8_t payload[] = {0x45, 0x00, 0x00, 0x1C, 0xDE, 0xAD};
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DATA, payload, sizeof(payload)));

    /* Process TLS input */
    int ret = iog_conn_data_process_tls(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read from TUN end */
    uint8_t tun_buf[64];
    ssize_t n = read(tun_sv[1], tun_buf, sizeof(tun_buf));
    TEST_ASSERT_EQUAL_INT((int)sizeof(payload), (int)n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, tun_buf, sizeof(payload));
}

void test_conn_data_tun_to_tls(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Send a TUN packet */
    const uint8_t pkt[] = {0x45, 0x00, 0x00, 0x14, 0xBE, 0xEF, 0xCA, 0xFE};
    int ret = iog_conn_data_process_tun(&data, pkt, sizeof(pkt));
    TEST_ASSERT_GREATER_THAN(0, ret);

    /* Read CSTP frame from mock TLS */
    uint8_t tls_buf[128];
    ssize_t n = read(tls_sv[1], tls_buf, sizeof(tls_buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    /* Decode and verify */
    iog_cstp_packet_t decoded;
    int consumed = iog_cstp_decode(tls_buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DATA, decoded.type);
    TEST_ASSERT_EQUAL_UINT(sizeof(pkt), decoded.payload_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(pkt, decoded.payload, sizeof(pkt));
}

void test_conn_data_dpd_request_response(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Inject DPD_REQ */
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DPD_REQ, nullptr, 0));

    /* Process */
    int ret = iog_conn_data_process_tls(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read DPD_RESP from mock TLS */
    uint8_t tls_buf[64];
    ssize_t n = read(tls_sv[1], tls_buf, sizeof(tls_buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    iog_cstp_packet_t decoded;
    int consumed = iog_cstp_decode(tls_buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DPD_RESP, decoded.type);
}

void test_conn_data_keepalive_passthrough(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Inject KEEPALIVE */
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_KEEPALIVE, nullptr, 0));

    /* Process */
    int ret = iog_conn_data_process_tls(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Nothing should arrive on TUN */
    uint8_t tun_buf[64];
    ssize_t n = read(tun_sv[1], tun_buf, sizeof(tun_buf));
    TEST_ASSERT_EQUAL_INT(-1, (int)n); /* EAGAIN on non-blocking */
}

void test_conn_data_disconnect_cleanup(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Inject DISCONNECT */
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DISCONNECT, nullptr, 0));

    /* Process — should return -ECONNRESET */
    int ret = iog_conn_data_process_tls(&data);
    TEST_ASSERT_EQUAL_INT(-ECONNRESET, ret);
    TEST_ASSERT_TRUE(data.disconnected);
}

void test_conn_data_compressed_lz4(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Switch to LZ4 compression */
    iog_compress_destroy(&compress_ctx);
    TEST_ASSERT_EQUAL_INT(0, iog_compress_init(&compress_ctx, IOG_COMPRESS_LZ4));

    /* Create repeating payload that compresses well */
    uint8_t payload[256];
    memset(payload, 0x42, sizeof(payload));

    /* Send via TUN path (compresses + encodes) */
    int ret = iog_conn_data_process_tun(&data, payload, sizeof(payload));
    TEST_ASSERT_GREATER_THAN(0, ret);

    /* Read CSTP frame from mock TLS */
    uint8_t tls_buf[512];
    ssize_t n = read(tls_sv[1], tls_buf, sizeof(tls_buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    /* Decode — should be COMPRESSED type */
    iog_cstp_packet_t decoded;
    int consumed = iog_cstp_decode(tls_buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_COMPRESSED, decoded.type);
    /* Compressed payload should be smaller than original */
    TEST_ASSERT_LESS_THAN((unsigned int)sizeof(payload), decoded.payload_len);

    /* Now inject that compressed frame back to verify decompression */
    ssize_t w = write(tls_sv[1], tls_buf, (size_t)n);
    TEST_ASSERT_GREATER_THAN(0, (int)w);

    /* Process TLS input — should decompress and write to TUN */
    ret = iog_conn_data_process_tls(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read from TUN */
    uint8_t tun_buf[512];
    ssize_t tn = read(tun_sv[1], tun_buf, sizeof(tun_buf));
    TEST_ASSERT_EQUAL_INT((int)sizeof(payload), (int)tn);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, tun_buf, sizeof(payload));
}

void test_conn_data_multiple_packets_batch(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    /* Inject 3 DATA packets in one burst */
    const uint8_t p1[] = {0x01, 0x02, 0x03};
    const uint8_t p2[] = {0x04, 0x05};
    const uint8_t p3[] = {0x06, 0x07, 0x08, 0x09};

    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DATA, p1, sizeof(p1)));
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DATA, p2, sizeof(p2)));
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DATA, p3, sizeof(p3)));

    /* Process all at once */
    int ret = iog_conn_data_process_tls(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read all 3 packets from TUN */
    uint8_t buf[64];
    ssize_t n;

    n = read(tun_sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(3, (int)n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p1, buf, 3);

    n = read(tun_sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(2, (int)n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p2, buf, 2);

    n = read(tun_sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(4, (int)n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p3, buf, 4);
}

void test_conn_data_send_dpd_req(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    int ret = iog_conn_data_send_dpd_req(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read from mock TLS */
    uint8_t buf[64];
    ssize_t n = read(tls_sv[1], buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    iog_cstp_packet_t decoded;
    int consumed = iog_cstp_decode(buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DPD_REQ, decoded.type);
}

void test_conn_data_send_keepalive(void)
{
    iog_conn_data_t data;
    TEST_ASSERT_EQUAL_INT(0, make_conn_data(&data));

    int ret = iog_conn_data_send_keepalive(&data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read from mock TLS */
    uint8_t buf[64];
    ssize_t n = read(tls_sv[1], buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    iog_cstp_packet_t decoded;
    int consumed = iog_cstp_decode(buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_KEEPALIVE, decoded.type);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_conn_data_init_destroy);
    RUN_TEST(test_conn_data_tls_to_tun);
    RUN_TEST(test_conn_data_tun_to_tls);
    RUN_TEST(test_conn_data_dpd_request_response);
    RUN_TEST(test_conn_data_keepalive_passthrough);
    RUN_TEST(test_conn_data_disconnect_cleanup);
    RUN_TEST(test_conn_data_compressed_lz4);
    RUN_TEST(test_conn_data_multiple_packets_batch);
    RUN_TEST(test_conn_data_send_dpd_req);
    RUN_TEST(test_conn_data_send_keepalive);
    return UNITY_END();
}
