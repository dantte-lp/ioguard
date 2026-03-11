#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/conn_timer.h"
#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

/* ============================================================================
 * Mock TLS I/O over socketpairs (same pattern as test_conn_data)
 * ============================================================================ */

static int tls_sv[2];
static int tun_sv[2];

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

static rw_dpd_ctx_t dpd;
static rw_compress_ctx_t compress_ctx;
static iog_conn_data_t conn_data;

/* Dead callback tracking */
static uint64_t dead_conn_id;
static int dead_called;

static void on_dead_cb(uint64_t conn_id, void *user_data)
{
    dead_conn_id = conn_id;
    dead_called++;
    (void)user_data;
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

    dead_conn_id = 0;
    dead_called = 0;
}

void tearDown(void)
{
    rw_compress_destroy(&compress_ctx);
    close(tls_sv[0]);
    close(tls_sv[1]);
    close(tun_sv[0]);
    close(tun_sv[1]);
}

/* Helper: make timer with standard config */
static int make_timer(iog_conn_timer_t *timer)
{
    iog_conn_timer_config_t cfg = {
        .dpd = &dpd,
        .data = &conn_data,
        .conn_id = 42,
        .dpd_interval_s = 30,
        .keepalive_interval_s = 20,
        .idle_timeout_s = 300,
        .on_dead = on_dead_cb,
        .on_dead_user_data = nullptr,
    };
    return iog_conn_timer_init(timer, &cfg);
}

/* ============================================================================
 * Tests
 * ============================================================================ */

void test_timer_init_destroy(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));
    TEST_ASSERT_TRUE(timer.active);
    TEST_ASSERT_EQUAL_UINT64(42, timer.conn_id);
    TEST_ASSERT_EQUAL_UINT(30000, timer.dpd_interval_ms);
    TEST_ASSERT_EQUAL_UINT(20000, timer.keepalive_interval_ms);

    iog_conn_timer_stop(&timer);
    TEST_ASSERT_FALSE(timer.active);
}

void test_timer_init_null_params(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_conn_timer_init(nullptr, nullptr));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_conn_timer_init(&timer, nullptr));

    iog_conn_timer_config_t cfg = {
        .dpd = nullptr,
        .data = &conn_data,
    };
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_conn_timer_init(&timer, &cfg));
}

void test_timer_dpd_probe_fires(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));

    /* First DPD tick: IDLE → PENDING, sends DPD request */
    int ret = iog_conn_timer_handle_dpd(&timer);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(IOG_DPD_PENDING, dpd.state);

    /* Verify DPD request was sent via TLS */
    uint8_t buf[64];
    ssize_t n = read(tls_sv[1], buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    rw_cstp_packet_t decoded;
    int consumed = rw_cstp_decode(buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DPD_REQ, decoded.type);
}

void test_timer_dpd_response_resets(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));

    /* Trigger DPD probe */
    (void)iog_conn_timer_handle_dpd(&timer);
    TEST_ASSERT_EQUAL_INT(IOG_DPD_PENDING, dpd.state);

    /* Drain TLS output */
    uint8_t drain[64];
    (void)read(tls_sv[1], drain, sizeof(drain));

    /* Simulate activity (peer responded) */
    iog_conn_timer_on_activity(&timer);
    TEST_ASSERT_EQUAL_INT(IOG_DPD_IDLE, dpd.state);
    TEST_ASSERT_EQUAL_INT(0, dead_called);
}

void test_timer_dpd_dead_callback(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));

    /* DPD with max_retries=3: need 4 timeouts to reach DEAD */
    /* Timeout 1: IDLE → PENDING (retry=1) */
    TEST_ASSERT_EQUAL_INT(0, iog_conn_timer_handle_dpd(&timer));
    /* Drain TLS */
    uint8_t drain[64];
    (void)read(tls_sv[1], drain, sizeof(drain));

    /* Timeout 2: PENDING, retry=2 */
    TEST_ASSERT_EQUAL_INT(0, iog_conn_timer_handle_dpd(&timer));
    (void)read(tls_sv[1], drain, sizeof(drain));

    /* Timeout 3: PENDING, retry=3 */
    TEST_ASSERT_EQUAL_INT(0, iog_conn_timer_handle_dpd(&timer));
    (void)read(tls_sv[1], drain, sizeof(drain));

    /* Timeout 4: retry > max_retries → DEAD */
    int ret = iog_conn_timer_handle_dpd(&timer);
    TEST_ASSERT_EQUAL_INT(1, ret); /* peer dead */
    TEST_ASSERT_EQUAL_INT(1, dead_called);
    TEST_ASSERT_EQUAL_UINT64(42, dead_conn_id);
    TEST_ASSERT_FALSE(timer.active);
}

void test_timer_keepalive_fires(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));

    int ret = iog_conn_timer_handle_keepalive(&timer);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify keepalive was sent via TLS */
    uint8_t buf[64];
    ssize_t n = read(tls_sv[1], buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, (int)n);

    rw_cstp_packet_t decoded;
    int consumed = rw_cstp_decode(buf, (size_t)n, &decoded);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_KEEPALIVE, decoded.type);
}

void test_timer_connection_idle_timeout(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));

    /* Not idle immediately */
    TEST_ASSERT_FALSE(iog_conn_timer_is_idle(&timer, timer.last_activity));

    /* Simulate time passing beyond idle timeout (300s) */
    TEST_ASSERT_TRUE(iog_conn_timer_is_idle(&timer, timer.last_activity + 301));

    /* Exactly at boundary — not idle yet */
    TEST_ASSERT_FALSE(iog_conn_timer_is_idle(&timer, timer.last_activity + 299));
}

void test_timer_reschedule_after_activity(void)
{
    iog_conn_timer_t timer;
    TEST_ASSERT_EQUAL_INT(0, make_timer(&timer));

    time_t start = timer.last_activity;

    /* Simulate activity updates last_activity */
    iog_conn_timer_on_activity(&timer);
    TEST_ASSERT_GREATER_OR_EQUAL(start, timer.last_activity);

    /* After activity, should not be idle relative to new activity time */
    TEST_ASSERT_FALSE(iog_conn_timer_is_idle(&timer, timer.last_activity + 100));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_timer_init_destroy);
    RUN_TEST(test_timer_init_null_params);
    RUN_TEST(test_timer_dpd_probe_fires);
    RUN_TEST(test_timer_dpd_response_resets);
    RUN_TEST(test_timer_dpd_dead_callback);
    RUN_TEST(test_timer_keepalive_fires);
    RUN_TEST(test_timer_connection_idle_timeout);
    RUN_TEST(test_timer_reschedule_after_activity);
    return UNITY_END();
}
