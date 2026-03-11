#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "auth/auth_backend.h"
#include "auth/ldap_auth.h"

void setUp(void)
{
    iog_auth_backend_cleanup();
}

void tearDown(void)
{
    rw_ldap_destroy();
    iog_auth_backend_cleanup();
}

void test_ldap_init_null_config_returns_einval(void)
{
    int ret = rw_ldap_init(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_ldap_init_missing_uri_returns_einval(void)
{
    rw_ldap_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* uri is empty */

    int ret = rw_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_ldap_destroy_null_safe(void)
{
    /* Calling destroy without prior init must not crash */
    rw_ldap_destroy();
    rw_ldap_destroy();
}

void test_ldap_backend_registers(void)
{
    const iog_auth_backend_t *backend = iog_ldap_backend();
    TEST_ASSERT_NOT_NULL(backend);

    int ret = iog_auth_backend_register(backend);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const iog_auth_backend_t *found = iog_auth_backend_find("ldap");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(backend, found);
}

void test_ldap_build_bind_dn_with_template(void)
{
    const char *tmpl = "uid=%s,ou=people,dc=example,dc=com";
    char buf[256];

    ssize_t len = rw_ldap_build_bind_dn(tmpl, "jdoe", buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING("uid=jdoe,ou=people,dc=example,dc=com", buf);
    TEST_ASSERT_EQUAL_INT(
        (int)strlen("uid=jdoe,ou=people,dc=example,dc=com"), (int)len);
}

void test_ldap_build_search_filter(void)
{
    char buf[256];

    ssize_t len = rw_ldap_build_group_filter(
        "memberOf", "uid=jdoe,ou=people,dc=example,dc=com",
        buf, sizeof(buf));

    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING(
        "(memberOf=uid=jdoe,ou=people,dc=example,dc=com)", buf);
}

void test_ldap_config_validates_uri_scheme(void)
{
    rw_ldap_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* HTTP scheme must be rejected */
    snprintf(cfg.uri, sizeof(cfg.uri), "http://ldap.example.com:389");
    snprintf(cfg.bind_dn_template, sizeof(cfg.bind_dn_template),
             "uid=%%s,dc=example,dc=com");

    int ret = rw_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    /* ldap:// must be accepted */
    snprintf(cfg.uri, sizeof(cfg.uri), "ldap://ldap.example.com:389");
    ret = rw_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    rw_ldap_destroy();

    /* ldaps:// must be accepted */
    snprintf(cfg.uri, sizeof(cfg.uri), "ldaps://ldap.example.com:636");
    ret = rw_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    rw_ldap_destroy();
}

void test_ldap_backend_name_is_ldap(void)
{
    const iog_auth_backend_t *backend = iog_ldap_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_EQUAL_STRING("ldap", backend->name);
    TEST_ASSERT_NOT_NULL(backend->init);
    TEST_ASSERT_NOT_NULL(backend->authenticate);
    TEST_ASSERT_NOT_NULL(backend->destroy);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ldap_init_null_config_returns_einval);
    RUN_TEST(test_ldap_init_missing_uri_returns_einval);
    RUN_TEST(test_ldap_destroy_null_safe);
    RUN_TEST(test_ldap_backend_registers);
    RUN_TEST(test_ldap_build_bind_dn_with_template);
    RUN_TEST(test_ldap_build_search_filter);
    RUN_TEST(test_ldap_config_validates_uri_scheme);
    RUN_TEST(test_ldap_backend_name_is_ldap);
    return UNITY_END();
}
