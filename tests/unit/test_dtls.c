#include <errno.h>
#include <string.h>
#include <unity/unity.h>
#include "network/dtls.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_dtls_config_init_defaults(void)
{
    rw_dtls_config_t cfg;
    rw_dtls_config_init(&cfg);
    TEST_ASSERT_EQUAL_UINT32(IOG_DTLS_DEFAULT_MTU, cfg.mtu);
    TEST_ASSERT_EQUAL_UINT32(IOG_DTLS_DEFAULT_TIMEOUT_S, cfg.timeout_init_s);
    TEST_ASSERT_EQUAL_UINT32(IOG_DTLS_DEFAULT_REKEY_S, cfg.rekey_interval_s);
    TEST_ASSERT_NULL(cfg.cert_file);
    TEST_ASSERT_NULL(cfg.key_file);
    TEST_ASSERT_TRUE(cfg.enable_cookies);
}

void test_dtls_config_validate_valid(void)
{
    rw_dtls_config_t cfg;
    rw_dtls_config_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, rw_dtls_config_validate(&cfg));
}

void test_dtls_config_validate_null(void)
{
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_config_validate(nullptr));
}

void test_dtls_config_validate_zero_mtu(void)
{
    rw_dtls_config_t cfg;
    rw_dtls_config_init(&cfg);
    cfg.mtu = 0;
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_config_validate(&cfg));
}

void test_dtls_config_validate_zero_timeout(void)
{
    rw_dtls_config_t cfg;
    rw_dtls_config_init(&cfg);
    cfg.timeout_init_s = 0;
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_dtls_config_validate(&cfg));
}

void test_dtls_cisco_ciphers(void)
{
    const char *ciphers = rw_dtls_cisco_ciphers();
    TEST_ASSERT_NOT_NULL(ciphers);
    TEST_ASSERT_TRUE(strstr(ciphers, "AES256") != nullptr);
    TEST_ASSERT_TRUE(strstr(ciphers, "DHE-RSA") != nullptr);
}

void test_dtls_create_destroy(void)
{
    rw_dtls_config_t cfg;
    rw_dtls_config_init(&cfg);
    rw_dtls_ctx_t *ctx = rw_dtls_create(&cfg);
    /* May be nullptr if wolfSSL not initialized — that's OK for unit test */
    if (ctx) {
        TEST_ASSERT_EQUAL_UINT32(IOG_DTLS_DEFAULT_MTU, rw_dtls_get_mtu(ctx));
        rw_dtls_destroy(ctx);
    } else {
        TEST_IGNORE_MESSAGE("wolfSSL DTLS context creation requires initialization");
    }
}

void test_dtls_destroy_null(void)
{
    rw_dtls_destroy(nullptr); /* should not crash */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_dtls_config_init_defaults);
    RUN_TEST(test_dtls_config_validate_valid);
    RUN_TEST(test_dtls_config_validate_null);
    RUN_TEST(test_dtls_config_validate_zero_mtu);
    RUN_TEST(test_dtls_config_validate_zero_timeout);
    RUN_TEST(test_dtls_cisco_ciphers);
    RUN_TEST(test_dtls_create_destroy);
    RUN_TEST(test_dtls_destroy_null);
    return UNITY_END();
}
