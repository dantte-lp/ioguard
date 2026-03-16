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
    iog_radius_destroy();
    iog_auth_backend_cleanup();
}

/* -----------------------------------------------------------------------
 * Test: iog_radius_init with null config returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_init_null_config_returns_einval(void)
{
    int ret = iog_radius_init(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: iog_radius_init with missing server returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_init_missing_server_returns_einval(void)
{
    iog_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* secret set but server empty */
    snprintf(cfg.secret, sizeof(cfg.secret), "testing123");

    int ret = iog_radius_init(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: iog_radius_destroy when not initialized does not crash
 * ----------------------------------------------------------------------- */
void test_radius_destroy_null_safe(void)
{
    /* Should be a no-op, not crash */
    iog_radius_destroy();
    iog_radius_destroy();
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
 * Test: iog_radius_config_defaults fills timeout and retries
 * ----------------------------------------------------------------------- */
void test_radius_config_defaults(void)
{
    iog_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    int ret = iog_radius_config_defaults(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(IOG_RADIUS_DEFAULT_TIMEOUT_MS, cfg.timeout_ms);
    TEST_ASSERT_EQUAL_UINT32(IOG_RADIUS_DEFAULT_RETRIES, cfg.retries);
}

/* -----------------------------------------------------------------------
 * Test: config_defaults preserves non-zero values
 * ----------------------------------------------------------------------- */
void test_radius_config_defaults_preserves_nonzero(void)
{
    iog_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.timeout_ms = 10000;
    cfg.retries = 5;

    int ret = iog_radius_config_defaults(&cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(10000, cfg.timeout_ms);
    TEST_ASSERT_EQUAL_UINT32(5, cfg.retries);
}

/* -----------------------------------------------------------------------
 * Test: config_defaults with null returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_config_defaults_null_returns_einval(void)
{
    int ret = iog_radius_config_defaults(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: config_validate rejects missing secret
 * ----------------------------------------------------------------------- */
void test_radius_config_validate_missing_secret(void)
{
    iog_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.server, sizeof(cfg.server), "127.0.0.1:1812");
    /* secret is empty */

    int ret = iog_radius_config_validate(&cfg);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: config_validate accepts valid config
 * ----------------------------------------------------------------------- */
void test_radius_config_validate_valid(void)
{
    iog_radius_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.server, sizeof(cfg.server), "127.0.0.1:1812");
    snprintf(cfg.secret, sizeof(cfg.secret), "testing123");

    int ret = iog_radius_config_validate(&cfg);
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

/* -----------------------------------------------------------------------
 * Test: extract_cisco_group with valid "group=VPN-Users" VSA
 * ----------------------------------------------------------------------- */
void test_radius_extract_cisco_group_valid(void)
{
    /* Cisco VSA: vendor 9, type 1, value "group=VPN-Users" */
    const char *value = "group=VPN-Users";
    size_t value_len = strlen(value);
    uint8_t attr_len = (uint8_t)(value_len + 2); /* type + length + value */

    /* Build raw VSA: 4 bytes vendor + 1 type + 1 length + value */
    uint8_t vsa[64];
    vsa[0] = 0x00; /* vendor ID 9 in big-endian */
    vsa[1] = 0x00;
    vsa[2] = 0x00;
    vsa[3] = 0x09;
    vsa[4] = 0x01; /* type = cisco-avpair */
    vsa[5] = attr_len;
    memcpy(&vsa[6], value, value_len);

    char out[64];
    ssize_t ret = iog_radius_extract_cisco_group(vsa, 6 + value_len, out, sizeof(out));

    TEST_ASSERT_EQUAL_INT(9, ret); /* strlen("VPN-Users") */
    TEST_ASSERT_EQUAL_STRING("VPN-Users", out);
}

/* -----------------------------------------------------------------------
 * Test: extract_cisco_group with bare group name (no "group=" prefix)
 * ----------------------------------------------------------------------- */
void test_radius_extract_cisco_group_bare_name(void)
{
    const char *value = "Admins";
    size_t value_len = strlen(value);
    uint8_t attr_len = (uint8_t)(value_len + 2);

    uint8_t vsa[64];
    vsa[0] = 0x00;
    vsa[1] = 0x00;
    vsa[2] = 0x00;
    vsa[3] = 0x09;
    vsa[4] = 0x01;
    vsa[5] = attr_len;
    memcpy(&vsa[6], value, value_len);

    char out[64];
    ssize_t ret = iog_radius_extract_cisco_group(vsa, 6 + value_len, out, sizeof(out));

    TEST_ASSERT_EQUAL_INT(6, ret);
    TEST_ASSERT_EQUAL_STRING("Admins", out);
}

/* -----------------------------------------------------------------------
 * Test: extract_cisco_group with null params returns -EINVAL
 * ----------------------------------------------------------------------- */
void test_radius_extract_cisco_group_null_returns_einval(void)
{
    uint8_t vsa[16] = {0};
    char out[32];

    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_radius_extract_cisco_group(nullptr, 10, out, sizeof(out)));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_radius_extract_cisco_group(vsa, 10, nullptr, sizeof(out)));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_radius_extract_cisco_group(vsa, 10, out, 0));
}

/* -----------------------------------------------------------------------
 * Test: extract_cisco_group with buffer too small returns -ENOSPC
 * ----------------------------------------------------------------------- */
void test_radius_extract_cisco_group_buffer_too_small(void)
{
    const char *value = "group=VPN-Users";
    size_t value_len = strlen(value);
    uint8_t attr_len = (uint8_t)(value_len + 2);

    uint8_t vsa[64];
    vsa[0] = 0x00;
    vsa[1] = 0x00;
    vsa[2] = 0x00;
    vsa[3] = 0x09;
    vsa[4] = 0x01;
    vsa[5] = attr_len;
    memcpy(&vsa[6], value, value_len);

    /* Buffer too small for "VPN-Users" (9 chars + NUL = 10 needed) */
    char out[5];
    ssize_t ret = iog_radius_extract_cisco_group(vsa, 6 + value_len, out, sizeof(out));

    TEST_ASSERT_EQUAL_INT(-ENOSPC, ret);
}

/* -----------------------------------------------------------------------
 * Test: extract_cisco_group rejects wrong vendor ID
 * ----------------------------------------------------------------------- */
void test_radius_extract_cisco_group_wrong_vendor(void)
{
    const char *value = "group=Test";
    size_t value_len = strlen(value);
    uint8_t attr_len = (uint8_t)(value_len + 2);

    uint8_t vsa[64];
    vsa[0] = 0x00;
    vsa[1] = 0x00;
    vsa[2] = 0x00;
    vsa[3] = 0x0A; /* vendor 10, not Cisco */
    vsa[4] = 0x01;
    vsa[5] = attr_len;
    memcpy(&vsa[6], value, value_len);

    char out[64];
    ssize_t ret = iog_radius_extract_cisco_group(vsa, 6 + value_len, out, sizeof(out));

    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

/* -----------------------------------------------------------------------
 * Test: extract_cisco_group rejects truncated VSA data
 * ----------------------------------------------------------------------- */
void test_radius_extract_cisco_group_truncated(void)
{
    uint8_t vsa[4] = {0x00, 0x00, 0x00, 0x09};
    char out[64];

    ssize_t ret = iog_radius_extract_cisco_group(vsa, sizeof(vsa), out, sizeof(out));
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
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
    RUN_TEST(test_radius_extract_cisco_group_valid);
    RUN_TEST(test_radius_extract_cisco_group_bare_name);
    RUN_TEST(test_radius_extract_cisco_group_null_returns_einval);
    RUN_TEST(test_radius_extract_cisco_group_buffer_too_small);
    RUN_TEST(test_radius_extract_cisco_group_wrong_vendor);
    RUN_TEST(test_radius_extract_cisco_group_truncated);
    return UNITY_END();
}
