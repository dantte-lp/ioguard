#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/shutdown.h"
#include "core/worker.h"
#include "network/cstp.h"

static rw_worker_t *worker;

void setUp(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 16;
    worker = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(worker);
}

void tearDown(void)
{
    rw_worker_destroy(worker);
    worker = nullptr;
}

/* ============================================================================
 * Tests
 * ============================================================================ */

void test_shutdown_init_defaults(void)
{
    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, rw_shutdown_init(&ctx, worker, 0));
    TEST_ASSERT_EQUAL_UINT(RW_SHUTDOWN_DRAIN_TIMEOUT_S, ctx.drain_timeout_s);
    TEST_ASSERT_FALSE(ctx.drain_started);
    TEST_ASSERT_EQUAL_UINT(0, ctx.connections_drained);
}

void test_shutdown_init_custom_timeout(void)
{
    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, rw_shutdown_init(&ctx, worker, 60));
    TEST_ASSERT_EQUAL_UINT(60, ctx.drain_timeout_s);
}

void test_shutdown_init_null_params(void)
{
    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_shutdown_init(nullptr, worker, 0));
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_shutdown_init(&ctx, nullptr, 0));
}

void test_shutdown_encode_disconnect(void)
{
    uint8_t buf[RW_CSTP_HEADER_SIZE + 16];
    int len = rw_shutdown_encode_disconnect(buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Verify it decodes as DISCONNECT */
    rw_cstp_packet_t pkt;
    int consumed = rw_cstp_decode(buf, (size_t)len, &pkt);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(RW_CSTP_DISCONNECT, pkt.type);
    TEST_ASSERT_EQUAL_UINT(0, pkt.payload_len);
}

void test_shutdown_encode_disconnect_small_buf(void)
{
    uint8_t buf[2]; /* too small */
    TEST_ASSERT_EQUAL_INT(-EINVAL,
                           rw_shutdown_encode_disconnect(buf, sizeof(buf)));
}

void test_shutdown_drain_empty_worker(void)
{
    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, rw_shutdown_init(&ctx, worker, 30));

    int drained = rw_shutdown_drain(&ctx);
    TEST_ASSERT_EQUAL_INT(0, drained);
    TEST_ASSERT_TRUE(ctx.drain_started);
    TEST_ASSERT_EQUAL_UINT(0, ctx.connections_drained);
}

void test_shutdown_drain_active_connections(void)
{
    /* Add some mock connections */
    int sv1[2], sv2[2], sv3[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv1));
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv2));
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv3));

    int64_t id1 = rw_worker_add_connection(worker, sv1[0], sv1[1]);
    int64_t id2 = rw_worker_add_connection(worker, sv2[0], sv2[1]);
    int64_t id3 = rw_worker_add_connection(worker, sv3[0], sv3[1]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id1);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id2);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id3);
    TEST_ASSERT_EQUAL_UINT(3, rw_worker_connection_count(worker));

    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, rw_shutdown_init(&ctx, worker, 30));

    int drained = rw_shutdown_drain(&ctx);
    TEST_ASSERT_EQUAL_INT(3, drained);
    TEST_ASSERT_TRUE(ctx.drain_started);
    TEST_ASSERT_EQUAL_UINT(3, ctx.connections_drained);
    TEST_ASSERT_EQUAL_UINT(0, rw_worker_connection_count(worker));

    /* Clean up socketpairs (worker_remove_connection doesn't close fds) */
    close(sv1[0]); close(sv1[1]);
    close(sv2[0]); close(sv2[1]);
    close(sv3[0]); close(sv3[1]);
}

void test_shutdown_timeout_check(void)
{
    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, rw_shutdown_init(&ctx, worker, 30));

    /* Not timed out yet */
    TEST_ASSERT_FALSE(rw_shutdown_timed_out(&ctx, 0));
    TEST_ASSERT_FALSE(rw_shutdown_timed_out(&ctx, 29));

    /* At boundary and beyond */
    TEST_ASSERT_TRUE(rw_shutdown_timed_out(&ctx, 30));
    TEST_ASSERT_TRUE(rw_shutdown_timed_out(&ctx, 60));
}

void test_shutdown_force_close_after_timeout(void)
{
    /* Add connection, drain starts but simulate timeout */
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    int64_t id = rw_worker_add_connection(worker, sv[0], sv[1]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id);

    rw_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, rw_shutdown_init(&ctx, worker, 5));

    /* Timeout exceeded → caller should force close */
    TEST_ASSERT_TRUE(rw_shutdown_timed_out(&ctx, 6));

    /* Force drain regardless */
    int drained = rw_shutdown_drain(&ctx);
    TEST_ASSERT_EQUAL_INT(1, drained);

    close(sv[0]); close(sv[1]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_shutdown_init_defaults);
    RUN_TEST(test_shutdown_init_custom_timeout);
    RUN_TEST(test_shutdown_init_null_params);
    RUN_TEST(test_shutdown_encode_disconnect);
    RUN_TEST(test_shutdown_encode_disconnect_small_buf);
    RUN_TEST(test_shutdown_drain_empty_worker);
    RUN_TEST(test_shutdown_drain_active_connections);
    RUN_TEST(test_shutdown_timeout_check);
    RUN_TEST(test_shutdown_force_close_after_timeout);
    return UNITY_END();
}
