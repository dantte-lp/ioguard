#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unity/unity.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include "ipc/transport.h"
#include "ipc/messages.h"
#include "core/secmod.h"
#include "config/config.h"
#include "core/session.h"

static wg_ipc_channel_t ch;
static wg_secmod_ctx_t ctx;
static wg_config_t config;

void setUp(void)
{
    memset(&ch, 0, sizeof(ch));
    memset(&ctx, 0, sizeof(ctx));

    wg_config_set_defaults(&config);

    int ret = wg_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = wg_secmod_init(&ctx, ch.parent_fd, &config);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void tearDown(void)
{
    wg_secmod_destroy(&ctx);
    close(ch.parent_fd);
    close(ch.child_fd);
}

/**
 * Test 1: Full auth flow with a nonexistent user — PAM must deny.
 *
 * Worker sends auth request on child_fd, secmod processes via
 * handle_message (which sends response on parent_fd / ipc_fd),
 * worker reads response from child_fd.
 */
void test_auth_flow_failed_auth(void)
{
    /* Pack an auth request with credentials that PAM will reject */
    wg_ipc_auth_request_t req = {
        .username  = "wg_nonexistent_user",
        .password  = "wrong",
        .group     = "default",
        .source_ip = "192.168.1.1",
    };

    uint8_t send_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_auth_request(&req, send_buf, sizeof(send_buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    /* Worker sends request on child_fd */
    int ret = wg_ipc_send(ch.child_fd, send_buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Sec-mod reads from parent_fd (its ipc_fd) */
    uint8_t recv_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t n = wg_ipc_recv(ch.parent_fd, recv_buf, sizeof(recv_buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    /* Sec-mod processes the message — sends response on parent_fd */
    ret = wg_secmod_handle_message(&ctx, recv_buf, (size_t)n);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Worker reads response from child_fd */
    uint8_t resp_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t resp_n = wg_ipc_recv(ch.child_fd, resp_buf, sizeof(resp_buf));
    TEST_ASSERT_GREATER_THAN(0, resp_n);

    /* Unpack and verify failure */
    wg_ipc_auth_response_t resp;
    ret = wg_ipc_unpack_auth_response(resp_buf, (size_t)resp_n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.error_msg);
    TEST_ASSERT_GREATER_THAN((size_t)0, strlen(resp.error_msg));

    wg_ipc_free_auth_response(&resp);
}

/**
 * Test 2: Verify response format on failed auth.
 *
 * Same flow as test 1 but checks structural properties of the
 * response: it must unpack without corruption and have expected
 * field values for a failure case.
 */
void test_auth_flow_response_format(void)
{
    wg_ipc_auth_request_t req = {
        .username  = "wg_nonexistent_user",
        .password  = "wrong",
        .group     = "default",
        .source_ip = "10.0.0.1",
    };

    uint8_t send_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_auth_request(&req, send_buf, sizeof(send_buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    int ret = wg_ipc_send(ch.child_fd, send_buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t recv_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t n = wg_ipc_recv(ch.parent_fd, recv_buf, sizeof(recv_buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    ret = wg_secmod_handle_message(&ctx, recv_buf, (size_t)n);
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t resp_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t resp_n = wg_ipc_recv(ch.child_fd, resp_buf, sizeof(resp_buf));
    TEST_ASSERT_GREATER_THAN(0, resp_n);

    wg_ipc_auth_response_t resp;
    ret = wg_ipc_unpack_auth_response(resp_buf, (size_t)resp_n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* On failure: no session cookie should be issued */
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_EQUAL_size_t(0, resp.session_cookie_len);
    TEST_ASSERT_EQUAL_UINT32(0, resp.session_ttl);

    wg_ipc_free_auth_response(&resp);
}

/**
 * Test 3: Session validation with a bogus cookie — must fail.
 *
 * Sends a session_validate request with a random 32-byte cookie
 * that does not correspond to any session.
 */
void test_auth_flow_session_validate_bogus(void)
{
    /* Fabricate a random 32-byte cookie */
    uint8_t bogus_cookie[WG_SESSION_COOKIE_SIZE];
    memset(bogus_cookie, 0xAB, sizeof(bogus_cookie));

    wg_ipc_session_validate_t sv_req = {
        .cookie     = bogus_cookie,
        .cookie_len = WG_SESSION_COOKIE_SIZE,
    };

    uint8_t send_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_session_validate(&sv_req, send_buf,
                                                   sizeof(send_buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    int ret = wg_ipc_send(ch.child_fd, send_buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t recv_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t n = wg_ipc_recv(ch.parent_fd, recv_buf, sizeof(recv_buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    ret = wg_secmod_handle_message(&ctx, recv_buf, (size_t)n);
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t resp_buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t resp_n = wg_ipc_recv(ch.child_fd, resp_buf, sizeof(resp_buf));
    TEST_ASSERT_GREATER_THAN(0, resp_n);

    wg_ipc_auth_response_t resp;
    ret = wg_ipc_unpack_auth_response(resp_buf, (size_t)resp_n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Bogus cookie must not validate */
    TEST_ASSERT_FALSE(resp.success);
    TEST_ASSERT_NOT_NULL(resp.error_msg);

    wg_ipc_free_auth_response(&resp);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_auth_flow_failed_auth);
    RUN_TEST(test_auth_flow_response_format);
    RUN_TEST(test_auth_flow_session_validate_bogus);
    return UNITY_END();
}
