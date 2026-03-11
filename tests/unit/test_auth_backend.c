#include <errno.h>
#include <string.h>
#include <unity/unity.h>

#include "auth/auth_backend.h"

static int mock_init(const void *config)
{
    (void)config;
    return 0;
}

static iog_auth_status_t mock_authenticate(const iog_auth_request_t *req,
                                           iog_auth_response_t *resp)
{
    (void)req;
    resp->status = IOG_AUTH_STATUS_SUCCESS;
    return IOG_AUTH_STATUS_SUCCESS;
}

static void mock_destroy(void)
{
}

static const iog_auth_backend_t mock_backend = {
    .name = "mock",
    .init = mock_init,
    .authenticate = mock_authenticate,
    .destroy = mock_destroy,
};

static const iog_auth_backend_t mock_backend2 = {
    .name = "mock2",
    .init = mock_init,
    .authenticate = mock_authenticate,
    .destroy = mock_destroy,
};

void setUp(void)
{
    iog_auth_backend_cleanup();
}

void tearDown(void)
{
    iog_auth_backend_cleanup();
}

void test_auth_backend_register_returns_zero(void)
{
    int ret = iog_auth_backend_register(&mock_backend);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_auth_backend_find_by_name(void)
{
    int ret = iog_auth_backend_register(&mock_backend);
    TEST_ASSERT_EQUAL_INT(0, ret);
    const iog_auth_backend_t *found = iog_auth_backend_find("mock");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("mock", found->name);
    TEST_ASSERT_EQUAL_PTR(&mock_backend, found);
}

void test_auth_backend_find_unknown_returns_null(void)
{
    const iog_auth_backend_t *found = iog_auth_backend_find("nonexistent");
    TEST_ASSERT_NULL(found);
}

void test_auth_backend_register_null_returns_einval(void)
{
    int ret = iog_auth_backend_register(nullptr);
    TEST_ASSERT_EQUAL_INT(-EINVAL, ret);
}

void test_auth_backend_register_duplicate_returns_eexist(void)
{
    int ret = iog_auth_backend_register(&mock_backend);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_auth_backend_register(&mock_backend);
    TEST_ASSERT_EQUAL_INT(-EEXIST, ret);
}

void test_auth_backend_list_returns_registered(void)
{
    int ret = iog_auth_backend_register(&mock_backend);
    TEST_ASSERT_EQUAL_INT(0, ret);
    ret = iog_auth_backend_register(&mock_backend2);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int count = 0;
    const iog_auth_backend_t *const *list = iog_auth_backend_list(&count);
    TEST_ASSERT_EQUAL_INT(2, count);
    TEST_ASSERT_NOT_NULL(list);
    TEST_ASSERT_EQUAL_PTR(&mock_backend, list[0]);
    TEST_ASSERT_EQUAL_PTR(&mock_backend2, list[1]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_auth_backend_register_returns_zero);
    RUN_TEST(test_auth_backend_find_by_name);
    RUN_TEST(test_auth_backend_find_unknown_returns_null);
    RUN_TEST(test_auth_backend_register_null_returns_einval);
    RUN_TEST(test_auth_backend_register_duplicate_returns_eexist);
    RUN_TEST(test_auth_backend_list_returns_registered);
    return UNITY_END();
}
