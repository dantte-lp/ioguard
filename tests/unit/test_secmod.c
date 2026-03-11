#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <unity/unity.h>

#include "config/config.h"
#include "core/secmod.h"
#include "core/session.h"
#include "ipc/messages.h"
#include "ipc/transport.h"

/* Shared test fixtures */
static iog_ipc_channel_t ch;
static iog_secmod_ctx_t ctx;
static iog_config_t config;

void setUp(void)
{
    memset(&ch, 0, sizeof(ch));
    memset(&ctx, 0, sizeof(ctx));

    iog_config_set_defaults(&config);

    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_secmod_init(&ctx, ch.parent_fd, &config);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void tearDown(void)
{
    iog_secmod_destroy(&ctx);
    iog_ipc_close(&ch);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

void test_secmod_init(void)
{
    /* setUp already called init — verify state */
    TEST_ASSERT_EQUAL_INT(ch.parent_fd, ctx.ipc_fd);
    TEST_ASSERT_NOT_NULL(ctx.sessions);
    TEST_ASSERT_FALSE(ctx.running);
    TEST_ASSERT_EQUAL_PTR(&config, ctx.config);
}

void test_secmod_init_null_ctx(void)
{
    int ret = iog_secmod_init(nullptr, 0, &config);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_secmod_init_null_config(void)
{
    iog_secmod_ctx_t tmp;
    int ret = iog_secmod_init(&tmp, 0, nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_secmod_auth_request_failure(void)
{
    /* Pack an auth request with bad credentials */
    iog_ipc_auth_request_t req;
    memset(&req, 0, sizeof(req));
    req.username = "testuser";
    req.password = "wrongpass";

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    /* Feed the raw bytes to handle_message (sends response on ipc_fd) */
    int ret = iog_secmod_handle_message(&ctx, buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read response from child_fd */
    uint8_t recv_buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t n = iog_ipc_recv(ch.child_fd, recv_buf, sizeof(recv_buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    iog_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    ret = iog_ipc_unpack_auth_response(recv_buf, (size_t)n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.error_msg);

    iog_ipc_free_auth_response(&resp);
}

void test_secmod_auth_request_sends_response(void)
{
    /* Send a well-formed auth request and verify we get a response back */
    iog_ipc_auth_request_t req;
    memset(&req, 0, sizeof(req));
    req.username = "alice";
    req.password = "somepassword";
    req.source_ip = "192.168.1.100";

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    int ret = iog_secmod_handle_message(&ctx, buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read the response */
    uint8_t recv_buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t n = iog_ipc_recv(ch.child_fd, recv_buf, sizeof(recv_buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    iog_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    ret = iog_ipc_unpack_auth_response(recv_buf, (size_t)n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* We got a well-formed response (PAM result may vary by environment) */
    if (resp.success) {
        TEST_ASSERT_NOT_NULL(resp.session_cookie);
        TEST_ASSERT_GREATER_THAN(0, resp.session_cookie_len);
        TEST_ASSERT_GREATER_THAN(0, resp.session_ttl);
    } else {
        TEST_ASSERT_NOT_NULL(resp.error_msg);
    }

    iog_ipc_free_auth_response(&resp);
}

void test_secmod_session_validate_invalid(void)
{
    /* Send a session_validate with a bogus cookie */
    uint8_t bogus_cookie[IOG_SESSION_COOKIE_SIZE];
    memset(bogus_cookie, 0xBB, sizeof(bogus_cookie));

    iog_ipc_session_validate_t sv;
    memset(&sv, 0, sizeof(sv));
    sv.cookie = bogus_cookie;
    sv.cookie_len = sizeof(bogus_cookie);

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_session_validate(&sv, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    int ret = iog_secmod_handle_message(&ctx, buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Read the response */
    uint8_t recv_buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t n = iog_ipc_recv(ch.child_fd, recv_buf, sizeof(recv_buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    iog_ipc_auth_response_t resp;
    memset(&resp, 0, sizeof(resp));
    ret = iog_ipc_unpack_auth_response(recv_buf, (size_t)n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.error_msg);

    iog_ipc_free_auth_response(&resp);
}

void test_secmod_stop(void)
{
    ctx.running = true;
    TEST_ASSERT_TRUE(ctx.running);

    iog_secmod_stop(&ctx);
    TEST_ASSERT_FALSE(ctx.running);
}

void test_secmod_stop_null(void)
{
    /* Must not crash */
    iog_secmod_stop(nullptr);
}

void test_secmod_destroy_null(void)
{
    /* Must not crash */
    iog_secmod_destroy(nullptr);
}

void test_secmod_handle_message_null(void)
{
    int ret = iog_secmod_handle_message(nullptr, (const uint8_t *)"x", 1);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = iog_secmod_handle_message(&ctx, nullptr, 1);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = iog_secmod_handle_message(&ctx, (const uint8_t *)"x", 0);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_secmod_init);
    RUN_TEST(test_secmod_init_null_ctx);
    RUN_TEST(test_secmod_init_null_config);
    RUN_TEST(test_secmod_auth_request_failure);
    RUN_TEST(test_secmod_auth_request_sends_response);
    RUN_TEST(test_secmod_session_validate_invalid);
    RUN_TEST(test_secmod_stop);
    RUN_TEST(test_secmod_stop_null);
    RUN_TEST(test_secmod_destroy_null);
    RUN_TEST(test_secmod_handle_message_null);
    return UNITY_END();
}
