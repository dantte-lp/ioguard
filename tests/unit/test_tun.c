#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <unity/unity.h>
#include "network/tun.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_tun_config_init_defaults(void)
{
    rw_tun_config_t cfg;
    rw_tun_config_init(&cfg);

    TEST_ASSERT_EQUAL_UINT32(RW_TUN_DEFAULT_MTU, cfg.mtu);
    TEST_ASSERT_EQUAL_UINT32(1406, cfg.mtu);
    TEST_ASSERT_TRUE(cfg.set_nonblock);
    TEST_ASSERT_EQUAL_CHAR('\0', cfg.dev_name[0]);
}

void test_tun_config_validate_valid(void)
{
    rw_tun_config_t cfg;
    rw_tun_config_init(&cfg);

    int ret = rw_tun_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_tun_config_validate_zero_mtu(void)
{
    rw_tun_config_t cfg;
    rw_tun_config_init(&cfg);
    cfg.mtu = 0;

    int ret = rw_tun_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_tun_config_validate_mtu_too_large(void)
{
    rw_tun_config_t cfg;
    rw_tun_config_init(&cfg);
    cfg.mtu = 70000;

    int ret = rw_tun_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_tun_config_validate_mtu_too_small(void)
{
    rw_tun_config_t cfg;
    rw_tun_config_init(&cfg);
    cfg.mtu = 10;

    int ret = rw_tun_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_tun_mtu_calculation(void)
{
    /* 1500 - 81 (IP+TCP+TLS+CSTP) = 1419 */
    TEST_ASSERT_EQUAL_UINT32(1419, rw_tun_calc_mtu(1500));

    /* 100 - 81 = 19, but clamped to RW_TUN_MIN_MTU (68) */
    TEST_ASSERT_EQUAL_UINT32(RW_TUN_MIN_MTU, rw_tun_calc_mtu(100));
}

void test_tun_alloc_not_root(void)
{
    if (geteuid() != 0) {
        TEST_IGNORE_MESSAGE("requires CAP_NET_ADMIN");
        return;
    }

    /* Also skip if /dev/net/tun is unavailable (e.g., in containers) */
    if (access("/dev/net/tun", F_OK) != 0) {
        TEST_IGNORE_MESSAGE("requires /dev/net/tun (not available in container)");
        return;
    }

    rw_tun_config_t cfg;
    rw_tun_config_init(&cfg);

    rw_tun_t tun;
    int ret = rw_tun_alloc(&cfg, &tun);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(tun.fd >= 0);
    TEST_ASSERT_EQUAL_UINT32(RW_TUN_DEFAULT_MTU, tun.mtu);
    TEST_ASSERT_TRUE(tun.dev_name[0] != '\0');

    rw_tun_close(&tun);
    TEST_ASSERT_EQUAL_INT(-1, tun.fd);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_tun_config_init_defaults);
    RUN_TEST(test_tun_config_validate_valid);
    RUN_TEST(test_tun_config_validate_zero_mtu);
    RUN_TEST(test_tun_config_validate_mtu_too_large);
    RUN_TEST(test_tun_config_validate_mtu_too_small);
    RUN_TEST(test_tun_mtu_calculation);
    RUN_TEST(test_tun_alloc_not_root);
    return UNITY_END();
}
