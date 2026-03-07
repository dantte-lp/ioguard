#include <unity/unity.h>
#include <string.h>
#include "auth/pam.h"

void setUp(void) {}
void tearDown(void) {}

void test_pam_init_default(void)
{
    wg_pam_config_t cfg;
    int ret = wg_pam_init(&cfg, nullptr);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("wolfguard", cfg.service);
}

void test_pam_init_custom(void)
{
    wg_pam_config_t cfg;
    int ret = wg_pam_init(&cfg, "sshd");
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("sshd", cfg.service);
}

void test_pam_authenticate_invalid_user(void)
{
    wg_pam_config_t cfg;
    int ret = wg_pam_init(&cfg, "other");
    TEST_ASSERT_EQUAL_INT(0, ret);

    wg_auth_result_t result = wg_pam_authenticate(&cfg,
                                                   "wg_test_nonexistent_user_12345",
                                                   "wrong");
    /* The "other" service typically denies all; expect failure or error */
    TEST_ASSERT_TRUE(result == WG_AUTH_FAILURE || result == WG_AUTH_ERROR);
}

void test_pam_authenticate_null_params(void)
{
    wg_pam_config_t cfg;
    int ret = wg_pam_init(&cfg, "other");
    TEST_ASSERT_EQUAL_INT(0, ret);

    wg_auth_result_t result;

    result = wg_pam_authenticate(&cfg, nullptr, "password");
    TEST_ASSERT_EQUAL_INT(WG_AUTH_ERROR, result);

    result = wg_pam_authenticate(&cfg, "user", nullptr);
    TEST_ASSERT_EQUAL_INT(WG_AUTH_ERROR, result);

    result = wg_pam_authenticate(nullptr, "user", "password");
    TEST_ASSERT_EQUAL_INT(WG_AUTH_ERROR, result);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pam_init_default);
    RUN_TEST(test_pam_init_custom);
    RUN_TEST(test_pam_authenticate_invalid_user);
    RUN_TEST(test_pam_authenticate_null_params);
    return UNITY_END();
}
