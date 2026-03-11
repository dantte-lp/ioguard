#ifndef _GNU_SOURCE
#    define _GNU_SOURCE
#endif
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/worker.h"
#include "io/uring.h"
#include "network/cstp.h"
#include "network/dpd.h"

/* Track whether io_uring syscalls are available in this environment */
static bool io_uring_available = false;

void setUp(void)
{
}
void tearDown(void)
{
}

/**
 * Encode a DATA packet with 20-byte payload, decode it, verify round-trip.
 */
void test_cstp_encode_decode_roundtrip(void)
{
    const uint8_t payload[20] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };
    uint8_t buf[IOG_CSTP_HEADER_SIZE + 20];

    int encoded = iog_cstp_encode(buf, sizeof(buf), IOG_CSTP_DATA, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT((int)(IOG_CSTP_HEADER_SIZE + sizeof(payload)), encoded);

    iog_cstp_packet_t pkt;
    int consumed = iog_cstp_decode(buf, (size_t)encoded, &pkt);
    TEST_ASSERT_EQUAL_INT(encoded, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DATA, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(sizeof(payload), pkt.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, pkt.payload, sizeof(payload));
}

/**
 * Encode 3 different packets (DATA, DPD_REQ, KEEPALIVE) into a single
 * buffer sequentially. Decode them one by one using the consumed bytes
 * offset. Verify each decoded packet matches.
 */
void test_cstp_multiple_packets_stream(void)
{
    const uint8_t data_payload[8] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0x11, 0x22, 0x33, 0x44,
    };

    /* Buffer large enough for all 3 packets */
    uint8_t buf[256];
    size_t offset = 0;

    /* Packet 1: DATA with 8-byte payload */
    int n = iog_cstp_encode(buf + offset, sizeof(buf) - offset, IOG_CSTP_DATA, data_payload,
                           sizeof(data_payload));
    TEST_ASSERT_GREATER_THAN(0, n);
    offset += (size_t)n;

    /* Packet 2: DPD_REQ with zero payload */
    n = iog_cstp_encode(buf + offset, sizeof(buf) - offset, IOG_CSTP_DPD_REQ, nullptr, 0);
    TEST_ASSERT_GREATER_THAN(0, n);
    offset += (size_t)n;

    /* Packet 3: KEEPALIVE with zero payload */
    n = iog_cstp_encode(buf + offset, sizeof(buf) - offset, IOG_CSTP_KEEPALIVE, nullptr, 0);
    TEST_ASSERT_GREATER_THAN(0, n);
    offset += (size_t)n;

    /* Decode packet 1 */
    size_t read_offset = 0;
    iog_cstp_packet_t pkt;

    int consumed = iog_cstp_decode(buf + read_offset, offset - read_offset, &pkt);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DATA, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(sizeof(data_payload), pkt.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(data_payload, pkt.payload, sizeof(data_payload));
    read_offset += (size_t)consumed;

    /* Decode packet 2 */
    consumed = iog_cstp_decode(buf + read_offset, offset - read_offset, &pkt);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DPD_REQ, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(0, pkt.payload_len);
    read_offset += (size_t)consumed;

    /* Decode packet 3 */
    consumed = iog_cstp_decode(buf + read_offset, offset - read_offset, &pkt);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_KEEPALIVE, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(0, pkt.payload_len);
    read_offset += (size_t)consumed;

    /* All bytes consumed */
    TEST_ASSERT_EQUAL_size_t(offset, read_offset);
}

/**
 * Full data-path integration: CSTP encode -> io_uring send/recv over
 * socketpair -> CSTP decode -> verify payload match.
 */
void test_data_path_socketpair_roundtrip(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available — skipping");
    }

    /* 1. Create socketpair */
    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* 2. CSTP-encode a test payload */
    const uint8_t payload[20] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    };
    uint8_t send_buf[IOG_CSTP_HEADER_SIZE + 20];
    int encoded =
        iog_cstp_encode(send_buf, sizeof(send_buf), IOG_CSTP_DATA, payload, sizeof(payload));
    TEST_ASSERT_EQUAL_INT((int)(IOG_CSTP_HEADER_SIZE + sizeof(payload)), encoded);

    /* 3. Create io_uring context */
    iog_io_ctx_t *ctx = iog_io_init(8, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* 4. Submit send to sv[0] */
    int send_done = 0;
    ret = iog_io_prep_send(ctx, sv[0], send_buf, (size_t)encoded, &send_done);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* 5. Submit recv from sv[1] */
    uint8_t recv_buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];
    int recv_done = 0;
    ret = iog_io_prep_recv(ctx, sv[1], recv_buf, sizeof(recv_buf), &recv_done);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* 6. Process both ops (may need two iterations) */
    for (int i = 0; i < 5 && (!send_done || !recv_done); i++) {
        ret = iog_io_run_once(ctx, 1000);
        TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);
    }
    TEST_ASSERT_EQUAL_INT(1, send_done);
    TEST_ASSERT_EQUAL_INT(1, recv_done);

    /* 7. CSTP-decode the read buffer and verify */
    iog_cstp_packet_t pkt;
    int consumed = iog_cstp_decode(recv_buf, (size_t)encoded, &pkt);
    TEST_ASSERT_EQUAL_INT(encoded, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DATA, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(sizeof(payload), pkt.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(payload, pkt.payload, sizeof(payload));

    /* 8. Cleanup */
    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

/**
 * DPD state machine + CSTP framing integration:
 * timeout -> PENDING -> encode DPD_REQ -> decode -> response -> IDLE.
 */
void test_dpd_probe_response_roundtrip(void)
{
    /* 1. Init DPD, trigger timeout -> PENDING */
    iog_dpd_ctx_t dpd;
    iog_dpd_init(&dpd, 30, 3);
    TEST_ASSERT_EQUAL_UINT8(IOG_DPD_IDLE, dpd.state);

    iog_dpd_state_t state = iog_dpd_on_timeout(&dpd);
    TEST_ASSERT_EQUAL_UINT8(IOG_DPD_PENDING, state);
    TEST_ASSERT_TRUE(dpd.need_send_request);

    /* 2. CSTP-encode a DPD_REQ packet (zero payload) */
    uint8_t buf[IOG_CSTP_HEADER_SIZE];
    int encoded = iog_cstp_encode(buf, sizeof(buf), IOG_CSTP_DPD_REQ, nullptr, 0);
    TEST_ASSERT_EQUAL_INT((int)IOG_CSTP_HEADER_SIZE, encoded);

    /* 3. CSTP-decode it back */
    iog_cstp_packet_t pkt;
    int consumed = iog_cstp_decode(buf, (size_t)encoded, &pkt);
    TEST_ASSERT_EQUAL_INT(encoded, consumed);

    /* 4. Verify decoded type is DPD_REQ */
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DPD_REQ, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(0, pkt.payload_len);

    /* 5. DPD on_response -> state back to IDLE */
    state = iog_dpd_on_response(&dpd, dpd.sequence);
    TEST_ASSERT_EQUAL_UINT8(IOG_DPD_IDLE, state);

    /* 6. CSTP-encode DPD_RESP */
    encoded = iog_cstp_encode(buf, sizeof(buf), IOG_CSTP_DPD_RESP, nullptr, 0);
    TEST_ASSERT_EQUAL_INT((int)IOG_CSTP_HEADER_SIZE, encoded);

    /* 7. CSTP-decode, verify type DPD_RESP */
    consumed = iog_cstp_decode(buf, (size_t)encoded, &pkt);
    TEST_ASSERT_EQUAL_INT(encoded, consumed);
    TEST_ASSERT_EQUAL_UINT8(IOG_CSTP_DPD_RESP, pkt.type);
    TEST_ASSERT_EQUAL_UINT32(0, pkt.payload_len);
}

/**
 * Worker connection lifecycle: create -> add -> find -> remove -> verify.
 */
void test_worker_connection_lifecycle(void)
{
    /* 1. Create worker with max_conns=4 */
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    /* 2. Add connection with dummy fds */
    int64_t conn_id = iog_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(0, conn_id);

    /* 3. Find connection, verify tls_fd and tun_fd */
    iog_connection_t *conn = iog_worker_find_connection(w, (uint64_t)conn_id);
    TEST_ASSERT_NOT_NULL(conn);
    TEST_ASSERT_EQUAL_INT(10, conn->tls_fd);
    TEST_ASSERT_EQUAL_INT(11, conn->tun_fd);
    TEST_ASSERT_EQUAL_UINT32(1, iog_worker_connection_count(w));

    /* 4. Remove connection */
    int ret = iog_worker_remove_connection(w, (uint64_t)conn_id);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* 5. Verify count=0, find returns nullptr */
    TEST_ASSERT_EQUAL_UINT32(0, iog_worker_connection_count(w));
    conn = iog_worker_find_connection(w, (uint64_t)conn_id);
    TEST_ASSERT_NULL(conn);

    /* 6. Destroy worker */
    iog_worker_destroy(w);
}

int main(void)
{
    /* Probe io_uring availability before running tests */
    iog_io_ctx_t *probe = iog_io_init(4, 0);
    if (probe != nullptr) {
        io_uring_available = true;
        iog_io_destroy(probe);
    }

    UNITY_BEGIN();
    RUN_TEST(test_cstp_encode_decode_roundtrip);
    RUN_TEST(test_cstp_multiple_packets_stream);
    RUN_TEST(test_data_path_socketpair_roundtrip);
    RUN_TEST(test_dpd_probe_response_roundtrip);
    RUN_TEST(test_worker_connection_lifecycle);
    return UNITY_END();
}
