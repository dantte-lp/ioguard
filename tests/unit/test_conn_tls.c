#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>

#include "core/conn_tls.h"
#include "crypto/tls_abstract.h"

#ifndef TEST_FIXTURES_DIR
#define TEST_FIXTURES_DIR "tests"
#endif

static char cert_path[512];
static char key_path[512];

void setUp(void)
{
    /* TEST_FIXTURES_DIR = <srcdir>/tests/fixtures, certs are at <srcdir>/tests/certs */
    snprintf(cert_path, sizeof(cert_path), "%s/../certs/server-cert.pem",
             TEST_FIXTURES_DIR);
    snprintf(key_path, sizeof(key_path), "%s/../certs/server-key.pem",
             TEST_FIXTURES_DIR);
}

void tearDown(void) {}

/* ============================================================================
 * Test: server context create/destroy
 * ============================================================================ */

void test_conn_tls_ctx_create_destroy(void)
{
    rw_tls_server_t srv;
    rw_tls_server_config_t cfg = {
        .cert_file = cert_path,
        .key_file = key_path,
        .ca_file = nullptr,
        .ciphers = nullptr,
    };

    int ret = rw_tls_server_init(&srv, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(srv.ctx);

    rw_tls_server_destroy(&srv);
}

/* ============================================================================
 * Test: null/invalid params
 * ============================================================================ */

void test_conn_tls_null_params(void)
{
    rw_tls_server_t srv;
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_tls_server_init(nullptr, nullptr));
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_tls_server_init(&srv, nullptr));

    rw_tls_server_config_t cfg = {
        .cert_file = nullptr,
        .key_file = nullptr,
    };
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_tls_server_init(&srv, &cfg));

    /* destroy with nullptr should be safe */
    rw_tls_server_destroy(nullptr);
    rw_tls_conn_destroy(nullptr);
}

/* ============================================================================
 * Test: connection init/destroy without handshake
 * ============================================================================ */

void test_conn_tls_conn_init_destroy(void)
{
    rw_tls_server_t srv;
    rw_tls_server_config_t cfg = {
        .cert_file = cert_path,
        .key_file = key_path,
    };
    TEST_ASSERT_EQUAL_INT(0, rw_tls_server_init(&srv, &cfg));

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    rw_tls_conn_t conn;
    int ret = rw_tls_conn_init(&conn, &srv, sv[0]);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(conn.session);
    TEST_ASSERT_EQUAL_INT(sv[0], conn.fd);
    TEST_ASSERT_FALSE(conn.handshake_done);

    rw_tls_conn_destroy(&conn);
    close(sv[0]);
    close(sv[1]);
    rw_tls_server_destroy(&srv);
}

/* ============================================================================
 * Helper: client thread for loopback handshake
 * ============================================================================ */

typedef struct {
    int fd;
    int result;
    bool handshake_done;
    char recv_buf[256];
    int recv_len;
} client_thread_ctx_t;

static void *client_thread_fn(void *arg)
{
    client_thread_ctx_t *ctx = arg;
    ctx->result = -1;

    /* Create client-side TLS context */
    tls_context_t *client_ctx = tls_context_new(false, false);
    if (client_ctx == nullptr) {
        ctx->result = -ENOMEM;
        return nullptr;
    }

    /* Disable server cert verification for self-signed test cert */
    (void)tls_context_set_verify(client_ctx, false, nullptr, nullptr);

    tls_session_t *session = tls_session_new(client_ctx);
    if (session == nullptr) {
        tls_context_free(client_ctx);
        ctx->result = -ENOMEM;
        return nullptr;
    }

    int ret = tls_session_set_fd(session, ctx->fd);
    if (ret != TLS_E_SUCCESS) {
        tls_session_free(session);
        tls_context_free(client_ctx);
        ctx->result = -EIO;
        return nullptr;
    }

    /* Perform client handshake (blocking — retry on EAGAIN) */
    for (int i = 0; i < 100; i++) {
        ret = tls_handshake(session);
        if (ret == TLS_E_SUCCESS) {
            ctx->handshake_done = true;
            break;
        }
        if (ret != TLS_E_AGAIN) {
            break;
        }
        usleep(1000);
    }

    if (ctx->handshake_done) {
        ctx->result = 0;

        /* Try reading data if server sends something (retry for non-blocking) */
        for (int i = 0; i < 200; i++) {
            ssize_t n = tls_recv(session, ctx->recv_buf,
                                  sizeof(ctx->recv_buf) - 1);
            if (n > 0) {
                ctx->recv_len = (int)n;
                ctx->recv_buf[n] = '\0';
                break;
            }
            if (n != TLS_E_AGAIN) {
                break;
            }
            usleep(1000);
        }
    }

    (void)tls_bye(session);
    tls_session_free(session);
    tls_context_free(client_ctx);
    return nullptr;
}

/* ============================================================================
 * Test: loopback handshake via socketpair
 * ============================================================================ */

void test_conn_tls_handshake_loopback(void)
{
    rw_tls_server_t srv;
    rw_tls_server_config_t cfg = {
        .cert_file = cert_path,
        .key_file = key_path,
    };
    TEST_ASSERT_EQUAL_INT(0, rw_tls_server_init(&srv, &cfg));

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    /* Server side */
    rw_tls_conn_t conn;
    TEST_ASSERT_EQUAL_INT(0, rw_tls_conn_init(&conn, &srv, sv[0]));

    /* Client side in separate thread */
    client_thread_ctx_t client_ctx;
    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.fd = sv[1];

    pthread_t client_thread;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&client_thread, nullptr,
                                             client_thread_fn, &client_ctx));

    /* Server handshake (retry on EAGAIN) */
    int ret = -EAGAIN;
    for (int i = 0; i < 100 && ret == -EAGAIN; i++) {
        ret = rw_tls_conn_handshake(&conn);
        if (ret == -EAGAIN) {
            usleep(1000);
        }
    }
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(conn.handshake_done);

    pthread_join(client_thread, nullptr);
    TEST_ASSERT_EQUAL_INT(0, client_ctx.result);
    TEST_ASSERT_TRUE(client_ctx.handshake_done);

    rw_tls_conn_destroy(&conn);
    close(sv[0]);
    close(sv[1]);
    rw_tls_server_destroy(&srv);
}

/* ============================================================================
 * Test: read after handshake
 * ============================================================================ */

void test_conn_tls_read_after_handshake(void)
{
    rw_tls_server_t srv;
    rw_tls_server_config_t cfg = {
        .cert_file = cert_path,
        .key_file = key_path,
    };
    TEST_ASSERT_EQUAL_INT(0, rw_tls_server_init(&srv, &cfg));

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    rw_tls_conn_t conn;
    TEST_ASSERT_EQUAL_INT(0, rw_tls_conn_init(&conn, &srv, sv[0]));

    /* Client thread does handshake then we read */
    client_thread_ctx_t client_ctx;
    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.fd = sv[1];

    pthread_t client_thread;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&client_thread, nullptr,
                                             client_thread_fn, &client_ctx));

    /* Server handshake */
    int ret = -EAGAIN;
    for (int i = 0; i < 100 && ret == -EAGAIN; i++) {
        ret = rw_tls_conn_handshake(&conn);
        if (ret == -EAGAIN) {
            usleep(1000);
        }
    }
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read before handshake done should fail */
    /* (handshake is done, so test read when no data available) */
    /* We'd get -EAGAIN or similar */

    pthread_join(client_thread, nullptr);

    rw_tls_conn_destroy(&conn);
    close(sv[0]);
    close(sv[1]);
    rw_tls_server_destroy(&srv);
}

/* ============================================================================
 * Test: write after handshake — server writes, client reads
 * ============================================================================ */

void test_conn_tls_write_after_handshake(void)
{
    rw_tls_server_t srv;
    rw_tls_server_config_t cfg = {
        .cert_file = cert_path,
        .key_file = key_path,
    };
    TEST_ASSERT_EQUAL_INT(0, rw_tls_server_init(&srv, &cfg));

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    rw_tls_conn_t conn;
    TEST_ASSERT_EQUAL_INT(0, rw_tls_conn_init(&conn, &srv, sv[0]));

    client_thread_ctx_t client_ctx;
    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.fd = sv[1];

    pthread_t client_thread;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&client_thread, nullptr,
                                             client_thread_fn, &client_ctx));

    /* Server handshake */
    int ret = -EAGAIN;
    for (int i = 0; i < 100 && ret == -EAGAIN; i++) {
        ret = rw_tls_conn_handshake(&conn);
        if (ret == -EAGAIN) {
            usleep(1000);
        }
    }
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Server writes data */
    const char *msg = "hello from server";
    ssize_t written = rw_tls_conn_write(&conn, msg, strlen(msg));
    TEST_ASSERT_GREATER_THAN(0, (int)written);

    /* Wait for client to read it */
    pthread_join(client_thread, nullptr);
    TEST_ASSERT_EQUAL_INT(0, client_ctx.result);
    TEST_ASSERT_EQUAL_INT((int)strlen(msg), client_ctx.recv_len);
    TEST_ASSERT_EQUAL_STRING(msg, client_ctx.recv_buf);

    rw_tls_conn_destroy(&conn);
    close(sv[0]);
    close(sv[1]);
    rw_tls_server_destroy(&srv);
}

/* ============================================================================
 * Test: read/write before handshake returns error
 * ============================================================================ */

void test_conn_tls_io_before_handshake(void)
{
    rw_tls_server_t srv;
    rw_tls_server_config_t cfg = {
        .cert_file = cert_path,
        .key_file = key_path,
    };
    TEST_ASSERT_EQUAL_INT(0, rw_tls_server_init(&srv, &cfg));

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    rw_tls_conn_t conn;
    TEST_ASSERT_EQUAL_INT(0, rw_tls_conn_init(&conn, &srv, sv[0]));

    /* Read before handshake */
    char buf[64];
    ssize_t ret = rw_tls_conn_read(&conn, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EPROTO, (int)ret);

    /* Write before handshake */
    ret = rw_tls_conn_write(&conn, "test", 4);
    TEST_ASSERT_EQUAL_INT(-EPROTO, (int)ret);

    rw_tls_conn_destroy(&conn);
    close(sv[0]);
    close(sv[1]);
    rw_tls_server_destroy(&srv);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_conn_tls_ctx_create_destroy);
    RUN_TEST(test_conn_tls_null_params);
    RUN_TEST(test_conn_tls_conn_init_destroy);
    RUN_TEST(test_conn_tls_handshake_loopback);
    RUN_TEST(test_conn_tls_read_after_handshake);
    RUN_TEST(test_conn_tls_write_after_handshake);
    RUN_TEST(test_conn_tls_io_before_handshake);
    return UNITY_END();
}
