#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <unity/unity.h>

#include "core/security_hooks.h"
#include "security/firewall.h"
#include "security/landlock.h"
#include "security/sandbox.h"

void setUp(void)
{
}
void tearDown(void)
{
}

/* ============================================================================
 * Tests
 * ============================================================================ */

void test_hooks_sandbox_profile_selection(void)
{
    /* Worker gets most restrictive profile */
    TEST_ASSERT_EQUAL_INT(IOG_SANDBOX_WORKER, rw_security_select_sandbox(true));

    /* Auth-mod gets slightly less restrictive */
    TEST_ASSERT_EQUAL_INT(IOG_SANDBOX_AUTHMOD, rw_security_select_sandbox(false));
}

void test_hooks_landlock_profile_selection(void)
{
    TEST_ASSERT_EQUAL_INT(IOG_LANDLOCK_WORKER, rw_security_select_landlock(true));
    TEST_ASSERT_EQUAL_INT(IOG_LANDLOCK_AUTHMOD, rw_security_select_landlock(false));
}

void test_hooks_apply_process_null_config(void)
{
    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_security_apply_process(true, nullptr));
}

void test_hooks_apply_process_disabled(void)
{
    /* With both seccomp and landlock disabled, should succeed without doing anything */
    iog_config_t config;
    iog_config_set_defaults(&config);
    config.security.seccomp = false;
    config.security.landlock = false;

    int ret = rw_security_apply_process(true, &config);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_hooks_build_fw_session(void)
{
    iog_fw_session_t session;
    uint32_t ip = htonl(0x0A000164); /* 10.0.1.100 */

    int ret = iog_security_build_fw_session(&session, "testuser", AF_INET, ip);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(AF_INET, session.af);
    TEST_ASSERT_EQUAL_UINT(ip, session.assigned_ipv4);
    TEST_ASSERT_EQUAL_STRING("testuser", session.username);
    /* Chain name should be non-empty */
    TEST_ASSERT_GREATER_THAN(0, (int)strlen(session.chain_name));
}

void test_hooks_build_fw_session_null_params(void)
{
    iog_fw_session_t session;
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_security_build_fw_session(nullptr, "user", AF_INET, 0));
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_security_build_fw_session(&session, nullptr, AF_INET, 0));
}

void test_hooks_build_fw_session_invalid_af(void)
{
    iog_fw_session_t session;
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_security_build_fw_session(&session, "user", AF_UNIX, 0));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hooks_sandbox_profile_selection);
    RUN_TEST(test_hooks_landlock_profile_selection);
    RUN_TEST(test_hooks_apply_process_null_config);
    RUN_TEST(test_hooks_apply_process_disabled);
    RUN_TEST(test_hooks_build_fw_session);
    RUN_TEST(test_hooks_build_fw_session_null_params);
    RUN_TEST(test_hooks_build_fw_session_invalid_af);
    return UNITY_END();
}
