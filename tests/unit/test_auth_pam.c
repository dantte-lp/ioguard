#include <string.h>
#include <unity/unity.h>
#include "auth/pam.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_pam_init_default(void)
{
    rw_pam_config_t cfg;
    int ret = rw_pam_init(&cfg, nullptr);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("ioguard", cfg.service);
}

void test_pam_init_custom(void)
{
    rw_pam_config_t cfg;
    int ret = rw_pam_init(&cfg, "sshd");
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("sshd", cfg.service);
}

void test_pam_authenticate_invalid_user(void)
{
    rw_pam_config_t cfg;
    int ret = rw_pam_init(&cfg, "other");
    TEST_ASSERT_EQUAL_INT(0, ret);

    rw_auth_result_t result = rw_pam_authenticate(&cfg, "rw_test_nonexistent_user_12345", "wrong");
    /* The "other" service typically denies all; expect failure or error */
    TEST_ASSERT_TRUE(result == RW_AUTH_FAILURE || result == RW_AUTH_ERROR);
}

void test_pam_authenticate_null_params(void)
{
    rw_pam_config_t cfg;
    int ret = rw_pam_init(&cfg, "other");
    TEST_ASSERT_EQUAL_INT(0, ret);

    rw_auth_result_t result;

    result = rw_pam_authenticate(&cfg, nullptr, "password");
    TEST_ASSERT_EQUAL_INT(RW_AUTH_ERROR, result);

    result = rw_pam_authenticate(&cfg, "user", nullptr);
    TEST_ASSERT_EQUAL_INT(RW_AUTH_ERROR, result);

    result = rw_pam_authenticate(nullptr, "user", "password");
    TEST_ASSERT_EQUAL_INT(RW_AUTH_ERROR, result);
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
