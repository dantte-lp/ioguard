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
    iog_ldap_destroy();
    iog_auth_backend_cleanup();
}

void test_ldap_init_null_config_returns_einval(void)
{
    int ret = iog_ldap_init(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_ldap_init_missing_uri_returns_einval(void)
{
    iog_ldap_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* uri is empty */

    int ret = iog_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_ldap_destroy_null_safe(void)
{
    /* Calling destroy without prior init must not crash */
    iog_ldap_destroy();
    iog_ldap_destroy();
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

    ssize_t len = iog_ldap_build_bind_dn(tmpl, "jdoe", buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING("uid=jdoe,ou=people,dc=example,dc=com", buf);
    TEST_ASSERT_EQUAL_INT((int)strlen("uid=jdoe,ou=people,dc=example,dc=com"), (int)len);
}

void test_ldap_build_search_filter(void)
{
    char buf[256];

    ssize_t len = iog_ldap_build_group_filter("memberOf", "uid=jdoe,ou=people,dc=example,dc=com",
                                              buf, sizeof(buf));

    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_EQUAL_STRING("(memberOf=uid=jdoe,ou=people,dc=example,dc=com)", buf);
}

void test_ldap_config_validates_uri_scheme(void)
{
    iog_ldap_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* HTTP scheme must be rejected */
    snprintf(cfg.uri, sizeof(cfg.uri), "http://ldap.example.com:389");
    snprintf(cfg.bind_dn_template, sizeof(cfg.bind_dn_template), "uid=%%s,dc=example,dc=com");

    int ret = iog_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);

    /* ldap:// must be accepted */
    snprintf(cfg.uri, sizeof(cfg.uri), "ldap://ldap.example.com:389");
    ret = iog_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    iog_ldap_destroy();

    /* ldaps:// must be accepted */
    snprintf(cfg.uri, sizeof(cfg.uri), "ldaps://ldap.example.com:636");
    ret = iog_ldap_init(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    iog_ldap_destroy();
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

/* ── RFC 4515 LDAP filter escaping tests ────────────────────────── */

void test_ldap_escape_special_chars(void)
{
    char out[256];
    ssize_t n = iog_ldap_escape_filter_value("admin)(|(uid=*", out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, n);
    TEST_ASSERT_EQUAL_STRING("admin\\29\\28|\\28uid=\\2a", out);
}

void test_ldap_escape_backslash(void)
{
    char out[256];
    ssize_t n = iog_ldap_escape_filter_value("user\\name", out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, n);
    TEST_ASSERT_EQUAL_STRING("user\\5cname", out);
}

void test_ldap_escape_clean_input(void)
{
    char out[256];
    ssize_t n = iog_ldap_escape_filter_value("normaluser", out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, n);
    TEST_ASSERT_EQUAL_STRING("normaluser", out);
}

void test_ldap_escape_null_returns_einval(void)
{
    char out[64];
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ldap_escape_filter_value(nullptr, out, sizeof(out)));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ldap_escape_filter_value("x", nullptr, 64));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_ldap_escape_filter_value("x", out, 0));
}

void test_ldap_escape_buffer_too_small(void)
{
    char out[4];
    ssize_t n = iog_ldap_escape_filter_value("a(b", out, sizeof(out));
    /* "a" + "\\28" + "b" = 6 chars, buffer is 4 — must fail */
    TEST_ASSERT_EQUAL_INT(-ENOSPC, n);
}

void test_ldap_build_dn_escapes_user(void)
{
    char out[256];
    ssize_t n = iog_ldap_build_bind_dn("uid=%s,dc=example", "evil)(cn=*", out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, n);
    /* Must NOT contain unescaped parens from user input */
    TEST_ASSERT_NULL(strstr(out, ")("));
    TEST_ASSERT_NOT_NULL(strstr(out, "\\29\\28"));
}

void test_ldap_build_filter_escapes_user(void)
{
    char out[256];
    ssize_t n = iog_ldap_build_group_filter("memberOf", "cn=evil*,dc=x", out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, n);
    /* Wildcard must be escaped */
    TEST_ASSERT_NULL(strstr(out, "evil*"));
    TEST_ASSERT_NOT_NULL(strstr(out, "evil\\2a"));
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
    /* RFC 4515 escaping (CRIT-2 fix) */
    RUN_TEST(test_ldap_escape_special_chars);
    RUN_TEST(test_ldap_escape_backslash);
    RUN_TEST(test_ldap_escape_clean_input);
    RUN_TEST(test_ldap_escape_null_returns_einval);
    RUN_TEST(test_ldap_escape_buffer_too_small);
    RUN_TEST(test_ldap_build_dn_escapes_user);
    RUN_TEST(test_ldap_build_filter_escapes_user);
    return UNITY_END();
}
