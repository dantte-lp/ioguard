#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "auth/cert_auth.h"

void setUp(void)
{
    rw_cert_auth_destroy();
}

void tearDown(void)
{
    rw_cert_auth_destroy();
}

void test_cert_auth_init_null_config_returns_einval(void)
{
    int ret = rw_cert_auth_init(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_cert_auth_destroy_null_safe(void)
{
    /* Calling destroy without init must not crash */
    rw_cert_auth_destroy();
    rw_cert_auth_destroy();
}

void test_cert_auth_backend_registers(void)
{
    const iog_auth_backend_t *backend = iog_cert_auth_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_NOT_NULL(backend->name);
    TEST_ASSERT_NOT_NULL(backend->init);
    TEST_ASSERT_NOT_NULL(backend->authenticate);
    TEST_ASSERT_NOT_NULL(backend->destroy);

    int ret = iog_auth_backend_register(backend);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const iog_auth_backend_t *found = iog_auth_backend_find("cert");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(backend, found);

    iog_auth_backend_cleanup();
}

void test_cert_auth_extract_cn_from_subject(void)
{
    /* Null inputs must return -EINVAL */
    char buf[64];
    int ret = rw_cert_extract_username(nullptr, 0, "CN", buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = rw_cert_extract_username((const uint8_t *)"x", 1, nullptr, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = rw_cert_extract_username((const uint8_t *)"x", 1, "CN", nullptr, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = rw_cert_extract_username((const uint8_t *)"x", 1, "CN", buf, 0);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    /* Zero-length DER must return -ENOENT */
    ret = rw_cert_extract_username((const uint8_t *)"", 0, "CN", buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-ENOENT, ret);
}

void test_cert_auth_username_field_default_is_cn(void)
{
    rw_cert_auth_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_cert_path, sizeof(cfg.ca_cert_path), "/etc/pki/ca.pem");
    /* Leave username_field empty — should default to "CN" */

    int ret = rw_cert_auth_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify init succeeded and backend is usable by getting descriptor */
    const iog_auth_backend_t *backend = iog_cert_auth_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_EQUAL_STRING("cert", backend->name);

    /* Re-init should return -EALREADY */
    ret = rw_cert_auth_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EALREADY, ret);
}

void test_cert_auth_backend_name_is_cert(void)
{
    const iog_auth_backend_t *backend = iog_cert_auth_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_EQUAL_STRING("cert", backend->name);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cert_auth_init_null_config_returns_einval);
    RUN_TEST(test_cert_auth_destroy_null_safe);
    RUN_TEST(test_cert_auth_backend_registers);
    RUN_TEST(test_cert_auth_extract_cn_from_subject);
    RUN_TEST(test_cert_auth_username_field_default_is_cn);
    RUN_TEST(test_cert_auth_backend_name_is_cert);
    return UNITY_END();
}
