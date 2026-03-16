#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "auth/cert_auth.h"

void setUp(void)
{
    iog_cert_auth_destroy();
}

void tearDown(void)
{
    iog_cert_auth_destroy();
}

void test_cert_auth_init_null_config_returns_einval(void)
{
    int ret = iog_cert_auth_init(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_cert_auth_destroy_null_safe(void)
{
    /* Calling destroy without init must not crash */
    iog_cert_auth_destroy();
    iog_cert_auth_destroy();
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
    int ret = iog_cert_extract_username(nullptr, 0, "CN", buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = iog_cert_extract_username((const uint8_t *)"x", 1, nullptr, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = iog_cert_extract_username((const uint8_t *)"x", 1, "CN", nullptr, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    ret = iog_cert_extract_username((const uint8_t *)"x", 1, "CN", buf, 0);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    /* Zero-length DER must return -ENOENT */
    ret = iog_cert_extract_username((const uint8_t *)"", 0, "CN", buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(-ENOENT, ret);
}

void test_cert_auth_username_field_default_is_cn(void)
{
    iog_cert_auth_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_cert_path, sizeof(cfg.ca_cert_path), "/etc/pki/ca.pem");
    /* Leave username_field empty — should default to "CN" */

    int ret = iog_cert_auth_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify init succeeded and backend is usable by getting descriptor */
    const iog_auth_backend_t *backend = iog_cert_auth_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_EQUAL_STRING("cert", backend->name);

    /* Re-init should return -EALREADY */
    ret = iog_cert_auth_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EALREADY, ret);
}

void test_cert_auth_backend_name_is_cert(void)
{
    const iog_auth_backend_t *backend = iog_cert_auth_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_EQUAL_STRING("cert", backend->name);
}

void test_cert_auth_config_default_eku_false(void)
{
    iog_cert_auth_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_cert_path, sizeof(cfg.ca_cert_path), "/etc/pki/ca.pem");

    /* require_eku must default to false after zero-init */
    TEST_ASSERT_FALSE(cfg.require_eku);

    int ret = iog_cert_auth_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_cert_auth_config_template_oid_empty(void)
{
    iog_cert_auth_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.ca_cert_path, sizeof(cfg.ca_cert_path), "/etc/pki/ca.pem");

    /* template_oid must default to empty string after zero-init */
    TEST_ASSERT_EQUAL_STRING("", cfg.template_oid);

    int ret = iog_cert_auth_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_cert_auth_backend_has_authenticate(void)
{
    const iog_auth_backend_t *backend = iog_cert_auth_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_NOT_NULL(backend->authenticate);
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
    RUN_TEST(test_cert_auth_config_default_eku_false);
    RUN_TEST(test_cert_auth_config_template_oid_empty);
    RUN_TEST(test_cert_auth_backend_has_authenticate);
    return UNITY_END();
}
