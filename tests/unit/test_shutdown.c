#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/shutdown.h"
#include "core/worker.h"
#include "network/cstp.h"

static iog_worker_t *worker;

void setUp(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 16;
    worker = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(worker);
}

void tearDown(void)
{
    iog_worker_destroy(worker);
    worker = nullptr;
}

/* ============================================================================
 * Tests
 * ============================================================================ */

void test_shutdown_init_defaults(void)
{
    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&ctx, worker, 0));
    TEST_ASSERT_EQUAL_UINT(RW_SHUTDOWN_DRAIN_TIMEOUT_S, ctx.drain_timeout_s);
    TEST_ASSERT_FALSE(ctx.drain_started);
    TEST_ASSERT_EQUAL_UINT(0, ctx.connections_drained);
}

void test_shutdown_init_custom_timeout(void)
{
    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&ctx, worker, 60));
    TEST_ASSERT_EQUAL_UINT(60, ctx.drain_timeout_s);
}

void test_shutdown_init_null_params(void)
{
    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_shutdown_init(nullptr, worker, 0));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_shutdown_init(&ctx, nullptr, 0));
}

void test_shutdown_encode_disconnect(void)
{
    uint8_t buf[IOG_CSTP_HEADER_SIZE + 16];
    int len = iog_shutdown_encode_disconnect(buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Verify it decodes as DISCONNECT */
    rw_cstp_packet_t pkt;
    int consumed = rw_cstp_decode(buf, (size_t)len, &pkt);
    TEST_ASSERT_GREATER_THAN(0, consumed);
    TEST_ASSERT_EQUAL_INT(IOG_CSTP_DISCONNECT, pkt.type);
    TEST_ASSERT_EQUAL_UINT(0, pkt.payload_len);
}

void test_shutdown_encode_disconnect_small_buf(void)
{
    uint8_t buf[2]; /* too small */
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_shutdown_encode_disconnect(buf, sizeof(buf)));
}

void test_shutdown_drain_empty_worker(void)
{
    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&ctx, worker, 30));

    int drained = iog_shutdown_drain(&ctx);
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

    int64_t id1 = iog_worker_add_connection(worker, sv1[0], sv1[1]);
    int64_t id2 = iog_worker_add_connection(worker, sv2[0], sv2[1]);
    int64_t id3 = iog_worker_add_connection(worker, sv3[0], sv3[1]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id1);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id2);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id3);
    TEST_ASSERT_EQUAL_UINT(3, iog_worker_connection_count(worker));

    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&ctx, worker, 30));

    int drained = iog_shutdown_drain(&ctx);
    TEST_ASSERT_EQUAL_INT(3, drained);
    TEST_ASSERT_TRUE(ctx.drain_started);
    TEST_ASSERT_EQUAL_UINT(3, ctx.connections_drained);
    TEST_ASSERT_EQUAL_UINT(0, iog_worker_connection_count(worker));

    /* Clean up socketpairs (worker_remove_connection doesn't close fds) */
    close(sv1[0]);
    close(sv1[1]);
    close(sv2[0]);
    close(sv2[1]);
    close(sv3[0]);
    close(sv3[1]);
}

void test_shutdown_timeout_check(void)
{
    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&ctx, worker, 30));

    /* Not timed out yet */
    TEST_ASSERT_FALSE(iog_shutdown_timed_out(&ctx, 0));
    TEST_ASSERT_FALSE(iog_shutdown_timed_out(&ctx, 29));

    /* At boundary and beyond */
    TEST_ASSERT_TRUE(iog_shutdown_timed_out(&ctx, 30));
    TEST_ASSERT_TRUE(iog_shutdown_timed_out(&ctx, 60));
}

void test_shutdown_force_close_after_timeout(void)
{
    /* Add connection, drain starts but simulate timeout */
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    int64_t id = iog_worker_add_connection(worker, sv[0], sv[1]);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, (int)id);

    iog_shutdown_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_shutdown_init(&ctx, worker, 5));

    /* Timeout exceeded → caller should force close */
    TEST_ASSERT_TRUE(iog_shutdown_timed_out(&ctx, 6));

    /* Force drain regardless */
    int drained = iog_shutdown_drain(&ctx);
    TEST_ASSERT_EQUAL_INT(1, drained);

    close(sv[0]);
    close(sv[1]);
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
