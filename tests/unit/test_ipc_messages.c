#include <string.h>
#include <unity/unity.h>
#include "ipc/messages.h"

#define RW_IPC_MAX_MSG_SIZE 4096

void setUp(void)
{
}
void tearDown(void)
{
}

void test_pack_unpack_auth_request(void)
{
    iog_ipc_msg_t msg;
    iog_ipc_msg_init(&msg, IOG_IPC_MSG_AUTH_REQUEST);

    iog_ipc_auth_request_t req = {
        .username = "testuser",
        .group = "vpn-users",
        .source_ip = "10.0.0.1",
        .password = "s3cret!Pass",
        .otp = "123456",
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_auth_request_t decoded;
    int ret = iog_ipc_unpack_auth_request(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("testuser", decoded.username);
    TEST_ASSERT_EQUAL_STRING("vpn-users", decoded.group);
    TEST_ASSERT_EQUAL_STRING("10.0.0.1", decoded.source_ip);
    TEST_ASSERT_EQUAL_STRING("s3cret!Pass", decoded.password);
    TEST_ASSERT_EQUAL_STRING("123456", decoded.otp);

    iog_ipc_free_auth_request(&decoded);
    TEST_ASSERT_NULL(decoded.password);
}

void test_pack_unpack_auth_response(void)
{
    const char *test_routes[] = {"10.0.0.0/8", "172.16.0.0/12"};
    iog_ipc_auth_response_t resp = {
        .success = true,
        .assigned_ip = "10.0.1.100",
        .dns_server = "10.0.0.53",
        .session_ttl = 3600,
        .default_domain = "vpn.example.com",
        .routes = test_routes,
        .route_count = 2,
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_response(&resp, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_auth_response_t decoded;
    int ret = iog_ipc_unpack_auth_response(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(decoded.success);
    TEST_ASSERT_EQUAL_STRING("10.0.1.100", decoded.assigned_ip);
    TEST_ASSERT_EQUAL_UINT32(3600, decoded.session_ttl);
    TEST_ASSERT_EQUAL_STRING("vpn.example.com", decoded.default_domain);
    TEST_ASSERT_EQUAL_UINT32(2, decoded.route_count);
    TEST_ASSERT_EQUAL_STRING("10.0.0.0/8", decoded.routes[0]);
    TEST_ASSERT_EQUAL_STRING("172.16.0.0/12", decoded.routes[1]);

    iog_ipc_free_auth_response(&decoded);
}

void test_pack_unpack_worker_status(void)
{
    iog_ipc_worker_status_t status = {
        .active_connections = 42,
        .bytes_rx = 1000000,
        .bytes_tx = 2000000,
        .pid = 12345,
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_worker_status(&status, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_worker_status_t decoded;
    int ret = iog_ipc_unpack_worker_status(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(42, decoded.active_connections);
    TEST_ASSERT_EQUAL_HEX64(1000000, decoded.bytes_rx);
    TEST_ASSERT_EQUAL_HEX64(2000000, decoded.bytes_tx);
}

void test_pack_unpack_session_validate(void)
{
    uint8_t test_cookie[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    iog_ipc_session_validate_t req = {
        .cookie = test_cookie,
        .cookie_len = sizeof(test_cookie),
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_session_validate(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_session_validate_t decoded;
    int ret = iog_ipc_unpack_session_validate(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_size_t(sizeof(test_cookie), decoded.cookie_len);
    TEST_ASSERT_EQUAL_MEMORY(test_cookie, decoded.cookie, sizeof(test_cookie));

    iog_ipc_free_session_validate(&decoded);
    TEST_ASSERT_NULL(decoded.cookie);
}

void test_pack_unpack_auth_response_requires_totp(void)
{
    iog_ipc_auth_response_t resp = {
        .success = false,
        .error_msg = "TOTP required",
        .requires_totp = true,
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_response(&resp, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_auth_response_t decoded;
    int ret = iog_ipc_unpack_auth_response(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_FALSE(decoded.success);
    TEST_ASSERT_TRUE(decoded.requires_totp);
    TEST_ASSERT_EQUAL_STRING("TOTP required", decoded.error_msg);

    iog_ipc_free_auth_response(&decoded);
}

void test_pack_unpack_auth_response_no_totp(void)
{
    iog_ipc_auth_response_t resp = {
        .success = true,
        .assigned_ip = "10.0.1.50",
        .session_ttl = 1800,
        .requires_totp = false,
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_response(&resp, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_auth_response_t decoded;
    int ret = iog_ipc_unpack_auth_response(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(decoded.success);
    TEST_ASSERT_FALSE(decoded.requires_totp);

    iog_ipc_free_auth_response(&decoded);
}

void test_unpack_truncated_data_fails(void)
{
    uint8_t garbage[] = {0xFF, 0x00};
    iog_ipc_auth_request_t decoded;
    int ret = iog_ipc_unpack_auth_request(garbage, sizeof(garbage), &decoded);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pack_unpack_auth_request);
    RUN_TEST(test_pack_unpack_auth_response);
    RUN_TEST(test_pack_unpack_auth_response_requires_totp);
    RUN_TEST(test_pack_unpack_auth_response_no_totp);
    RUN_TEST(test_pack_unpack_worker_status);
    RUN_TEST(test_pack_unpack_session_validate);
    RUN_TEST(test_unpack_truncated_data_fails);
    return UNITY_END();
}
