#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/conn_data.h"
#include "core/conn_timer.h"
#include "core/shutdown.h"
#include "core/worker.h"
#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

/* ============================================================================
 * Mock TLS I/O over socketpairs
 * ============================================================================ */

static ssize_t mock_tls_read(void *ctx, void *buf, size_t len)
{
    int fd = *(int *)ctx;
    ssize_t n = read(fd, buf, len);
    if (n < 0) {
        return -errno;
    }
    return n;
}

static ssize_t mock_tls_write(void *ctx, const void *buf, size_t len)
{
    int fd = *(int *)ctx;
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
        return -errno;
    }
    return n;
}

/* Per-test state */
static int tls_sv[2]; /* sv[0] = server (conn_data), sv[1] = client (test) */
static int tun_sv[2]; /* sv[0] = server writes, sv[1] = test reads */
static rw_dpd_ctx_t dpd;
static rw_compress_ctx_t compress_ctx;
static iog_conn_data_t conn_data;
static iog_worker_t *worker;

/* Dead callback tracking */
static int dead_called;
static void on_dead_cb(uint64_t conn_id, void *user_data)
{
    (void)conn_id;
    (void)user_data;
    dead_called++;
}

static int inject_cstp(rw_cstp_type_t type, const uint8_t *payload, size_t payload_len)
{
    uint8_t buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];
    int encoded = rw_cstp_encode(buf, sizeof(buf), type, payload, payload_len);
    if (encoded < 0) {
        return encoded;
    }
    ssize_t written = write(tls_sv[1], buf, (size_t)encoded);
    if (written < 0) {
        return -errno;
    }
    return (int)written;
}

void setUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, tls_sv));
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, tun_sv));
    rw_dpd_init(&dpd, 30, 3);
    TEST_ASSERT_EQUAL_INT(0, rw_compress_init(&compress_ctx, IOG_COMPRESS_NONE));

    iog_conn_data_config_t data_cfg = {
        .tls_read = mock_tls_read,
        .tls_write = mock_tls_write,
        .tls_ctx = &tls_sv[0],
        .tun_fd = tun_sv[0],
        .dpd = &dpd,
        .compress = &compress_ctx,
    };
    TEST_ASSERT_EQUAL_INT(0, iog_conn_data_init(&conn_data, &data_cfg));

    iog_worker_config_t wcfg;
    iog_worker_config_init(&wcfg);
    wcfg.max_connections = 8;
    worker = iog_worker_create(&wcfg);
    TEST_ASSERT_NOT_NULL(worker);

    dead_called = 0;
}

void tearDown(void)
{
    iog_worker_destroy(worker);
    worker = nullptr;
    rw_compress_destroy(&compress_ctx);
    close(tls_sv[0]);
    close(tls_sv[1]);
    close(tun_sv[0]);
    close(tun_sv[1]);
}

/* ============================================================================
 * Integration Tests — Full vertical path
 * ============================================================================ */

void test_vpn_flow_cstp_data_roundtrip(void)
{
    /* Client sends DATA → server decodes → writes to TUN */
    const uint8_t payload[] = {0x45, 0x00, 0x00, 0x1C, 0xDE, 0xAD, 0xBE, 0xEF};
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DATA, payload, sizeof(payload)));

    int ret = iog_conn_data_process_tls(&conn_data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read from TUN end — should match original payload */
    uint8_t tun_buf[64];
    ssize_t n = read(tun_sv[1], tun_buf, sizeof(tun_buf));
    TEST_ASSERT_EQUAL_INT((int)sizeof(payload), (int)n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, tun_buf, sizeof(payload));

    /* Reverse: TUN → server encodes → client reads CSTP frame */
    const uint8_t reply[] = {0x45, 0x00, 0x00, 0x14, 0xCA, 0xFE};
    ret = iog_conn_data_process_tun(&conn_data, reply, sizeof(reply));
    TEST_ASSERT_GREATER_THAN(0, ret);

    uint8_t tls_buf[128];
    n = read(tls_sv[1], tls_buf, sizeof(tls_buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    rw_cstp_packet_t decoded;
    int consumed = rw_cstp_decode(tls_buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DATA, decoded.type);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(reply, decoded.payload, sizeof(reply));
}

void test_vpn_flow_dpd_probe_response(void)
{
    /* Server-side DPD probe: timer fires → send DPD_REQ → client sees it */
    iog_conn_timer_t timer;
    iog_conn_timer_config_t tcfg = {
        .dpd = &dpd,
        .data = &conn_data,
        .conn_id = 1,
        .dpd_interval_s = 30,
        .keepalive_interval_s = 20,
        .idle_timeout_s = 300,
        .on_dead = on_dead_cb,
    };
    TEST_ASSERT_EQUAL_INT(0, iog_conn_timer_init(&timer, &tcfg));

    /* Trigger DPD probe */
    int ret = iog_conn_timer_handle_dpd(&timer);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Client reads DPD_REQ */
    uint8_t buf[64];
    ssize_t n = read(tls_sv[1], buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    rw_cstp_packet_t pkt;
    int consumed = rw_cstp_decode(buf, (size_t)n, &pkt);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DPD_REQ, pkt.type);

    /* Client sends DPD_RESP */
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DPD_RESP, nullptr, 0));

    /* Server processes response */
    ret = iog_conn_data_process_tls(&conn_data);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* DPD should be back to IDLE */
    TEST_ASSERT_EQUAL_INT(IOG_DPD_IDLE, dpd.state);
}

void test_vpn_flow_client_disconnect(void)
{
    /* Client sends DISCONNECT → server detects it */
    TEST_ASSERT_GREATER_THAN(0, inject_cstp(IOG_CSTP_DISCONNECT, nullptr, 0));

    int ret = iog_conn_data_process_tls(&conn_data);
    TEST_ASSERT_EQUAL_INT(-ECONNRESET, ret);
    TEST_ASSERT_TRUE(conn_data.disconnected);
}

void test_vpn_flow_server_shutdown_sends_disconnect(void)
{
    /* Worker has active connections */
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    int64_t id = iog_worker_add_connection(worker, sv[0], sv[1]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id);

    /* Shutdown encodes DISCONNECT frame */
    uint8_t disc_buf[IOG_CSTP_HEADER_SIZE + 4];
    int len = iog_shutdown_encode_disconnect(disc_buf, sizeof(disc_buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Drain removes connections */
    iog_shutdown_ctx_t sctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&sctx, worker, 5));
    int drained = iog_shutdown_drain(&sctx);
    TEST_ASSERT_EQUAL_INT(1, drained);
    TEST_ASSERT_EQUAL_UINT(0, iog_worker_connection_count(worker));

    close(sv[0]);
    close(sv[1]);
}

void test_vpn_flow_multiple_clients(void)
{
    /* Simulate 3 independent client data paths */
    int cli_tls[3][2];
    int cli_tun[3][2];
    rw_dpd_ctx_t cli_dpd[3];
    rw_compress_ctx_t cli_comp[3];
    iog_conn_data_t cli_data[3];

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, cli_tls[i]));
        TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, cli_tun[i]));
        rw_dpd_init(&cli_dpd[i], 30, 3);
        TEST_ASSERT_EQUAL_INT(0, rw_compress_init(&cli_comp[i], IOG_COMPRESS_NONE));

        iog_conn_data_config_t cfg = {
            .tls_read = mock_tls_read,
            .tls_write = mock_tls_write,
            .tls_ctx = &cli_tls[i][0],
            .tun_fd = cli_tun[i][0],
            .dpd = &cli_dpd[i],
            .compress = &cli_comp[i],
        };
        TEST_ASSERT_EQUAL_INT(0, iog_conn_data_init(&cli_data[i], &cfg));
    }

    /* Send unique data through each client */
    for (int i = 0; i < 3; i++) {
        uint8_t payload[4] = {0x45, 0x00, (uint8_t)(i + 1), 0x00};

        /* Inject CSTP DATA via "client" end */
        uint8_t cstp_buf[IOG_CSTP_HEADER_SIZE + 4];
        int encoded =
            rw_cstp_encode(cstp_buf, sizeof(cstp_buf), IOG_CSTP_DATA, payload, sizeof(payload));
        TEST_ASSERT_GREATER_THAN(0, encoded);
        ssize_t w = write(cli_tls[i][1], cstp_buf, (size_t)encoded);
        TEST_ASSERT_GREATER_THAN(0, (int)w);

        /* Process on server side */
        int ret = iog_conn_data_process_tls(&cli_data[i]);
        TEST_ASSERT_EQUAL_INT(0, ret);

        /* Read from TUN — verify correct payload */
        uint8_t tun_buf[32];
        ssize_t n = read(cli_tun[i][1], tun_buf, sizeof(tun_buf));
        TEST_ASSERT_EQUAL_INT(4, (int)n);
        TEST_ASSERT_EQUAL_UINT8(i + 1, tun_buf[2]);
    }

    /* Cleanup */
    for (int i = 0; i < 3; i++) {
        rw_compress_destroy(&cli_comp[i]);
        close(cli_tls[i][0]);
        close(cli_tls[i][1]);
        close(cli_tun[i][0]);
        close(cli_tun[i][1]);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vpn_flow_cstp_data_roundtrip);
    RUN_TEST(test_vpn_flow_dpd_probe_response);
    RUN_TEST(test_vpn_flow_client_disconnect);
    RUN_TEST(test_vpn_flow_server_shutdown_sends_disconnect);
    RUN_TEST(test_vpn_flow_multiple_clients);
    return UNITY_END();
}
