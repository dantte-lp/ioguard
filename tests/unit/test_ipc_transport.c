#include <unity/unity.h>
#include <string.h>
#include <unistd.h>
#include "ipc/transport.h"

void setUp(void) {}
void tearDown(void) {}

void test_wg_ipc_create_socketpair(void)
{
    wg_ipc_channel_t ch;
    int ret = wg_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ch.parent_fd);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ch.child_fd);
    wg_ipc_close(&ch);
}

void test_wg_ipc_send_recv_message(void)
{
    wg_ipc_channel_t ch;
    int ret = wg_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const uint8_t msg[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    ret = wg_ipc_send(ch.parent_fd, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t buf[256];
    ssize_t n = wg_ipc_recv(ch.child_fd, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(5, n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg, buf, 5);

    wg_ipc_close(&ch);
}

void test_wg_ipc_preserves_message_boundaries(void)
{
    wg_ipc_channel_t ch;
    int ret = wg_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const uint8_t msg1[] = {0xAA, 0xBB};
    const uint8_t msg2[] = {0xCC, 0xDD, 0xEE};
    ret = wg_ipc_send(ch.parent_fd, msg1, sizeof(msg1));
    TEST_ASSERT_EQUAL_INT(0, ret);
    ret = wg_ipc_send(ch.parent_fd, msg2, sizeof(msg2));
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t buf[256];
    ssize_t n1 = wg_ipc_recv(ch.child_fd, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(2, n1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg1, buf, 2);

    ssize_t n2 = wg_ipc_recv(ch.child_fd, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(3, n2);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg2, buf, 3);

    wg_ipc_close(&ch);
}

void test_wg_ipc_send_fd(void)
{
    wg_ipc_channel_t ch;
    int ret = wg_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int pipefd[2];
    ret = pipe(pipefd);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = wg_ipc_send_fd(ch.parent_fd, pipefd[1]);
    TEST_ASSERT_EQUAL_INT(0, ret);
    close(pipefd[1]);

    int received_fd = wg_ipc_recv_fd(ch.child_fd);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, received_fd);

    write(received_fd, "ok", 2);
    char buf[8] = {0};
    read(pipefd[0], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("ok", buf);

    close(received_fd);
    close(pipefd[0]);
    wg_ipc_close(&ch);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_wg_ipc_create_socketpair);
    RUN_TEST(test_wg_ipc_send_recv_message);
    RUN_TEST(test_wg_ipc_preserves_message_boundaries);
    RUN_TEST(test_wg_ipc_send_fd);
    return UNITY_END();
}
