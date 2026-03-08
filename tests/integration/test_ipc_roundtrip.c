#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unity/unity.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <string.h>
#include "ipc/transport.h"
#include "ipc/messages.h"

void setUp(void) {}
void tearDown(void) {}

void test_ipc_roundtrip_auth(void)
{
    rw_ipc_channel_t ch;
    int ret = rw_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    pid_t pid = fork();
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, pid);

    if (pid == 0) {
        /* Child: sec-mod simulator */
        close(ch.parent_fd);

        uint8_t buf[RW_IPC_MAX_MSG_SIZE];
        ssize_t n = rw_ipc_recv(ch.child_fd, buf, sizeof(buf));
        if (n <= 0) { _exit(1); }

        rw_ipc_auth_request_t req;
        if (rw_ipc_unpack_auth_request(buf, (size_t)n, &req) != 0) { _exit(2); }

        rw_ipc_auth_response_t resp = {
            .success = true,
            .assigned_ip = "10.10.0.100",
            .dns_server = "10.0.0.53",
            .session_ttl = 3600,
        };

        uint8_t resp_buf[RW_IPC_MAX_MSG_SIZE];
        ssize_t packed = rw_ipc_pack_auth_response(&resp, resp_buf, sizeof(resp_buf));
        if (packed <= 0) { _exit(3); }

        if (rw_ipc_send(ch.child_fd, resp_buf, (size_t)packed) != 0) { _exit(4); }
        rw_ipc_free_auth_request(&req);
        close(ch.child_fd);
        _exit(0);
    }

    /* Parent: worker simulator */
    close(ch.child_fd);

    rw_ipc_auth_request_t req = {
        .username = "admin",
        .group = "vpn-users",
        .source_ip = "192.168.1.100",
    };

    uint8_t buf[RW_IPC_MAX_MSG_SIZE];
    ssize_t packed = rw_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    ret = rw_ipc_send(ch.parent_fd, buf, (size_t)packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ssize_t n = rw_ipc_recv(ch.parent_fd, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    rw_ipc_auth_response_t resp;
    ret = rw_ipc_unpack_auth_response(buf, (size_t)n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(resp.success);
    TEST_ASSERT_EQUAL_STRING("10.10.0.100", resp.assigned_ip);
    TEST_ASSERT_EQUAL_STRING("10.0.0.53", resp.dns_server);
    TEST_ASSERT_EQUAL_UINT32(3600, resp.session_ttl);

    rw_ipc_free_auth_response(&resp);
    close(ch.parent_fd);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ipc_roundtrip_auth);
    return UNITY_END();
}
