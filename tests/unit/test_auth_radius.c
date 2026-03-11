#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "auth/auth_backend.h"
#include "auth/radius.h"

void setUp(void)
{
    iog_auth_backend_cleanup();
}

void tearDown(void)
{
    rw_radius_destroy();
    iog_auth_backend_cleanup();
}

/* -----------------------------------------------------------------------
 * Test: rw_radius_init with null config returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_init_null_config_returns_einval(void)
{
    int ret = rw_radius_init(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: rw_radius_init with missing server returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_init_missing_server_returns_einval(void)
{
    rw_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* secret set but server empty */
    snprintf(cfg.secret, sizeof(cfg.secret), "testing123");

    int ret = rw_radius_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: rw_radius_destroy when not initialized does not crash
 * ----------------------------------------------------------------------- */
void test_radius_destroy_null_safe(void)
{
    /* Should be a no-op, not crash */
    rw_radius_destroy();
    rw_radius_destroy();
}

/* -----------------------------------------------------------------------
 * Test: iog_radius_backend returns valid backend, can register
 * ----------------------------------------------------------------------- */
void test_radius_backend_registers(void)
{
    const iog_auth_backend_t *backend = iog_radius_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_NOT_NULL(backend->name);
    TEST_ASSERT_NOT_NULL(backend->init);
    TEST_ASSERT_NOT_NULL(backend->authenticate);
    TEST_ASSERT_NOT_NULL(backend->destroy);

    int ret = iog_auth_backend_register(backend);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const iog_auth_backend_t *found = iog_auth_backend_find("radius");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_PTR(backend, found);
}

/* -----------------------------------------------------------------------
 * Test: rw_radius_config_defaults fills timeout and retries
 * ----------------------------------------------------------------------- */
void test_radius_config_defaults(void)
{
    rw_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    int ret = rw_radius_config_defaults(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(RW_RADIUS_DEFAULT_TIMEOUT_MS, cfg.timeout_ms);
    TEST_ASSERT_EQUAL_UINT32(RW_RADIUS_DEFAULT_RETRIES, cfg.retries);
}

/* -----------------------------------------------------------------------
 * Test: config_defaults preserves non-zero values
 * ----------------------------------------------------------------------- */
void test_radius_config_defaults_preserves_nonzero(void)
{
    rw_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.timeout_ms = 10000;
    cfg.retries = 5;

    int ret = rw_radius_config_defaults(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(10000, cfg.timeout_ms);
    TEST_ASSERT_EQUAL_UINT32(5, cfg.retries);
}

/* -----------------------------------------------------------------------
 * Test: config_defaults with null returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_config_defaults_null_returns_einval(void)
{
    int ret = rw_radius_config_defaults(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: config_validate rejects missing secret
 * ----------------------------------------------------------------------- */
void test_radius_config_validate_missing_secret(void)
{
    rw_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.server, sizeof(cfg.server), "127.0.0.1:1812");
    /* secret is empty */

    int ret = rw_radius_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: config_validate accepts valid config
 * ----------------------------------------------------------------------- */
void test_radius_config_validate_valid(void)
{
    rw_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.server, sizeof(cfg.server), "127.0.0.1:1812");
    snprintf(cfg.secret, sizeof(cfg.secret), "testing123");

    int ret = rw_radius_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

/* -----------------------------------------------------------------------
 * Test: iog_radius_backend()->name is "radius"
 * ----------------------------------------------------------------------- */
void test_radius_backend_name_is_radius(void)
{
    const iog_auth_backend_t *backend = iog_radius_backend();
    TEST_ASSERT_NOT_NULL(backend);
    TEST_ASSERT_EQUAL_STRING("radius", backend->name);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_radius_init_null_config_returns_einval);
    RUN_TEST(test_radius_init_missing_server_returns_einval);
    RUN_TEST(test_radius_destroy_null_safe);
    RUN_TEST(test_radius_backend_registers);
    RUN_TEST(test_radius_config_defaults);
    RUN_TEST(test_radius_config_defaults_preserves_nonzero);
    RUN_TEST(test_radius_config_defaults_null_returns_einval);
    RUN_TEST(test_radius_config_validate_missing_secret);
    RUN_TEST(test_radius_config_validate_valid);
    RUN_TEST(test_radius_backend_name_is_radius);
    return UNITY_END();
}
