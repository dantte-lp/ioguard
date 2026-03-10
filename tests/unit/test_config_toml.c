#include <unity/unity.h>
#include "config/config.h"

#ifndef TEST_FIXTURES_DIR
#    define TEST_FIXTURES_DIR "."
#endif
static const char *TEST_CONFIG = TEST_FIXTURES_DIR "/ioguard.toml";

void setUp(void)
{
}
void tearDown(void)
{
}

void test_config_load_valid_file(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    rw_config_free(&cfg);
}

void test_config_load_nonexistent_file(void)
{
    rw_config_t cfg;
    int ret = rw_config_load("/nonexistent.toml", &cfg);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_config_server_values(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("0.0.0.0", cfg.server.listen_address);
    TEST_ASSERT_EQUAL_UINT16(443, cfg.server.listen_port);
    TEST_ASSERT_EQUAL_UINT16(443, cfg.server.dtls_port);
    TEST_ASSERT_EQUAL_UINT32(1024, cfg.server.max_clients);
    TEST_ASSERT_EQUAL_UINT32(4, cfg.server.worker_count);

    rw_config_free(&cfg);
}

void test_config_auth_values(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("pam", cfg.auth.method);
    TEST_ASSERT_EQUAL_UINT32(300, cfg.auth.cookie_timeout);

    rw_config_free(&cfg);
}

void test_config_network_values(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("10.10.0.0/16", cfg.network.ipv4_pools[0]);
    TEST_ASSERT_EQUAL_UINT32(1400, cfg.network.mtu);
    TEST_ASSERT_EQUAL_STRING("corp.example.com", cfg.network.default_domain);

    rw_config_free(&cfg);
}

void test_config_tls_values(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("/etc/ioguard/server.pem", cfg.tls.cert_file);
    TEST_ASSERT_EQUAL_STRING("/etc/ioguard/server.key", cfg.tls.key_file);

    rw_config_free(&cfg);
}

void test_config_auth_totp_values(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("ioguard-test", cfg.auth.totp_issuer);
    TEST_ASSERT_EQUAL_UINT32(6, cfg.auth.totp_digits);
    TEST_ASSERT_EQUAL_UINT32(2, cfg.auth.totp_window);

    rw_config_free(&cfg);
}

void test_config_storage_values(void)
{
    rw_config_t cfg;
    int ret = rw_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("/etc/ioguard/vault.key", cfg.storage.vault_key_path);

    rw_config_free(&cfg);
}

void test_config_totp_defaults(void)
{
    rw_config_t cfg;
    rw_config_set_defaults(&cfg);

    TEST_ASSERT_EQUAL_STRING("ioguard", cfg.auth.totp_issuer);
    TEST_ASSERT_EQUAL_UINT32(6, cfg.auth.totp_digits);
    TEST_ASSERT_EQUAL_UINT32(1, cfg.auth.totp_window);

    rw_config_free(&cfg);
}

void test_config_defaults_when_missing(void)
{
    rw_config_t cfg;
    rw_config_set_defaults(&cfg);

    TEST_ASSERT_EQUAL_UINT16(443, cfg.server.listen_port);
    TEST_ASSERT_EQUAL_UINT32(0, cfg.server.worker_count);
    TEST_ASSERT_EQUAL_UINT32(1400, cfg.network.mtu);

    rw_config_free(&cfg);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_config_load_valid_file);
    RUN_TEST(test_config_load_nonexistent_file);
    RUN_TEST(test_config_server_values);
    RUN_TEST(test_config_auth_values);
    RUN_TEST(test_config_network_values);
    RUN_TEST(test_config_tls_values);
    RUN_TEST(test_config_auth_totp_values);
    RUN_TEST(test_config_storage_values);
    RUN_TEST(test_config_totp_defaults);
    RUN_TEST(test_config_defaults_when_missing);
    return UNITY_END();
}
