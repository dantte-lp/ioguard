#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unity/unity.h>
#include "io/uring.h"

static bool io_uring_available = false;

void setUp(void)
{
}
void tearDown(void)
{
}

/* Test callback context */
typedef struct {
    int result;
    bool called;
} test_cb_ctx_t;

static void test_cb(int res, void *user_data)
{
    test_cb_ctx_t *ctx = user_data;
    ctx->result = res;
    ctx->called = true;
}

void test_io_prep_recv_cb_roundtrip(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    if (ctx == nullptr) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }
    io_uring_available = true;

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    write(sv[0], "test", 4);

    char buf[64] = {0};
    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_prep_recv_cb(ctx, sv[1], buf, sizeof(buf), test_cb, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_EQUAL_INT(4, cb_ctx.result);
    TEST_ASSERT_EQUAL_STRING("test", buf);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_io_prep_send_cb_roundtrip(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_prep_send_cb(ctx, sv[0], "hello", 5, test_cb, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_EQUAL_INT(5, cb_ctx.result);

    char buf[64] = {0};
    ssize_t n = read(sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(5, n);
    TEST_ASSERT_EQUAL_STRING("hello", buf);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_io_prep_read_cb_fires(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int pfd[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd));

    write(pfd[1], "data", 4);

    char buf[64] = {0};
    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_prep_read_cb(ctx, pfd[0], buf, sizeof(buf), test_cb, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_EQUAL_INT(4, cb_ctx.result);
    TEST_ASSERT_EQUAL_STRING("data", buf);

    close(pfd[0]);
    close(pfd[1]);
    iog_io_destroy(ctx);
}

void test_io_prep_write_cb_fires(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int pfd[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd));

    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_prep_write_cb(ctx, pfd[1], "pipe", 4, test_cb, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_EQUAL_INT(4, cb_ctx.result);

    char buf[64] = {0};
    ssize_t n = read(pfd[0], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(4, n);
    TEST_ASSERT_EQUAL_STRING("pipe", buf);

    close(pfd[0]);
    close(pfd[1]);
    iog_io_destroy(ctx);
}

void test_io_prep_accept_cb(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Create a listening TCP socket on loopback */
    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, lfd);

    int optval = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    TEST_ASSERT_EQUAL_INT(0, bind(lfd, (struct sockaddr *)&addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_INT(0, listen(lfd, 1));

    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);

    /* Submit accept */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_prep_accept_cb(ctx, lfd, (struct sockaddr *)&client_addr, &client_len, test_cb,
                                   &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Connect */
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, cfd);
    connect(cfd, (struct sockaddr *)&addr, sizeof(addr));

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, cb_ctx.result);

    close(cb_ctx.result);
    close(cfd);
    close(lfd);
    iog_io_destroy(ctx);
}

void test_io_add_timeout_cb_fires(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_add_timeout_cb(ctx, 10, test_cb, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_EQUAL_INT(-ETIME, cb_ctx.result);

    iog_io_destroy(ctx);
}

void test_io_cancel_operation(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));

    /* Submit recv that will block (no data) */
    char buf[64] = {0};
    test_cb_ctx_t cb_ctx = {0};
    int ret = iog_io_prep_recv_cb(ctx, sv[1], buf, sizeof(buf), test_cb, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Submit and wait for SQE to be in flight */
    io_uring_submit(&ctx->ring);

    /* Cancel it */
    ret = iog_io_cancel(ctx, &cb_ctx);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Run to get cancellation CQE(s) */
    for (int i = 0; i < 3; i++) {
        (void)iog_io_run_once(ctx, 200);
        if (cb_ctx.called) {
            break;
        }
    }
    TEST_ASSERT_TRUE(cb_ctx.called);
    TEST_ASSERT_EQUAL_INT(-ECANCELED, cb_ctx.result);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_io_multiple_callbacks_concurrent(void)
{
    if (!io_uring_available) {
        TEST_IGNORE_MESSAGE("io_uring not available");
    }

    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* 3 concurrent pipe read operations */
    int pfd1[2], pfd2[2], pfd3[2];
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd1));
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd2));
    TEST_ASSERT_EQUAL_INT(0, pipe(pfd3));

    write(pfd1[1], "a", 1);
    write(pfd2[1], "bb", 2);
    write(pfd3[1], "ccc", 3);

    char buf1[8] = {0}, buf2[8] = {0}, buf3[8] = {0};
    test_cb_ctx_t ctx1 = {0}, ctx2 = {0}, ctx3 = {0};

    TEST_ASSERT_EQUAL_INT(0, iog_io_prep_read_cb(ctx, pfd1[0], buf1, sizeof(buf1), test_cb, &ctx1));
    TEST_ASSERT_EQUAL_INT(0, iog_io_prep_read_cb(ctx, pfd2[0], buf2, sizeof(buf2), test_cb, &ctx2));
    TEST_ASSERT_EQUAL_INT(0, iog_io_prep_read_cb(ctx, pfd3[0], buf3, sizeof(buf3), test_cb, &ctx3));

    /* May need multiple run_once calls to get all CQEs */
    for (int i = 0; i < 3; i++) {
        (void)iog_io_run_once(ctx, 100);
    }

    TEST_ASSERT_TRUE(ctx1.called);
    TEST_ASSERT_TRUE(ctx2.called);
    TEST_ASSERT_TRUE(ctx3.called);
    TEST_ASSERT_EQUAL_INT(1, ctx1.result);
    TEST_ASSERT_EQUAL_INT(2, ctx2.result);
    TEST_ASSERT_EQUAL_INT(3, ctx3.result);

    close(pfd1[0]);
    close(pfd1[1]);
    close(pfd2[0]);
    close(pfd2[1]);
    close(pfd3[0]);
    close(pfd3[1]);
    iog_io_destroy(ctx);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_io_prep_recv_cb_roundtrip);
    RUN_TEST(test_io_prep_send_cb_roundtrip);
    RUN_TEST(test_io_prep_read_cb_fires);
    RUN_TEST(test_io_prep_write_cb_fires);
    RUN_TEST(test_io_prep_accept_cb);
    RUN_TEST(test_io_add_timeout_cb_fires);
    RUN_TEST(test_io_cancel_operation);
    RUN_TEST(test_io_multiple_callbacks_concurrent);
    return UNITY_END();
}
