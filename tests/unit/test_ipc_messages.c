#include <unity/unity.h>
#include <string.h>
#include "ipc/messages.h"

#define WG_IPC_MAX_MSG_SIZE 4096

void setUp(void) {}
void tearDown(void) {}

void test_pack_unpack_auth_request(void)
{
    wg_ipc_msg_t msg;
    wg_ipc_msg_init(&msg, WG_IPC_MSG_AUTH_REQUEST);

    wg_ipc_auth_request_t req = {
        .username = "testuser",
        .group = "vpn-users",
        .source_ip = "10.0.0.1",
    };

    uint8_t buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    wg_ipc_auth_request_t decoded;
    int ret = wg_ipc_unpack_auth_request(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("testuser", decoded.username);
    TEST_ASSERT_EQUAL_STRING("vpn-users", decoded.group);
    TEST_ASSERT_EQUAL_STRING("10.0.0.1", decoded.source_ip);

    wg_ipc_free_auth_request(&decoded);
}

void test_pack_unpack_auth_response(void)
{
    wg_ipc_auth_response_t resp = {
        .success = true,
        .assigned_ip = "10.0.1.100",
        .dns_server = "10.0.0.53",
        .session_ttl = 3600,
    };

    uint8_t buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_auth_response(&resp, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    wg_ipc_auth_response_t decoded;
    int ret = wg_ipc_unpack_auth_response(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(decoded.success);
    TEST_ASSERT_EQUAL_STRING("10.0.1.100", decoded.assigned_ip);
    TEST_ASSERT_EQUAL_UINT32(3600, decoded.session_ttl);

    wg_ipc_free_auth_response(&decoded);
}

void test_pack_unpack_worker_status(void)
{
    wg_ipc_worker_status_t status = {
        .active_connections = 42,
        .bytes_rx = 1000000,
        .bytes_tx = 2000000,
        .pid = 12345,
    };

    uint8_t buf[WG_IPC_MAX_MSG_SIZE];
    ssize_t packed = wg_ipc_pack_worker_status(&status, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    wg_ipc_worker_status_t decoded;
    int ret = wg_ipc_unpack_worker_status(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(42, decoded.active_connections);
    TEST_ASSERT_EQUAL_HEX64(1000000, decoded.bytes_rx);
    TEST_ASSERT_EQUAL_HEX64(2000000, decoded.bytes_tx);
}

void test_unpack_truncated_data_fails(void)
{
    uint8_t garbage[] = {0xFF, 0x00};
    wg_ipc_auth_request_t decoded;
    int ret = wg_ipc_unpack_auth_request(garbage, sizeof(garbage), &decoded);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pack_unpack_auth_request);
    RUN_TEST(test_pack_unpack_auth_response);
    RUN_TEST(test_pack_unpack_worker_status);
    RUN_TEST(test_unpack_truncated_data_fails);
    return UNITY_END();
}
