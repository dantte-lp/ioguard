#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <unity/unity.h>
#include "core/session.h"

static iog_session_store_t *store;

void setUp(void)
{
    store = iog_session_store_create(8);
    TEST_ASSERT_NOT_NULL(store);
}

void tearDown(void)
{
    iog_session_store_destroy(store);
    store = nullptr;
}

void test_session_store_create_destroy(void)
{
    iog_session_store_t *s = iog_session_store_create(16);

    TEST_ASSERT_NOT_NULL(s);
    iog_session_store_destroy(s);

    /* nullptr destroy must not crash */
    iog_session_store_destroy(nullptr);
}

void test_session_create_basic(void)
{
    iog_session_t *session = nullptr;
    int ret = iog_session_create(store, "alice", "vpn-users", 3600, &session);

    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(session);
    TEST_ASSERT_EQUAL_STRING("alice", session->username);
    TEST_ASSERT_EQUAL_STRING("vpn-users", session->group);
    TEST_ASSERT_TRUE(session->active);
    TEST_ASSERT_EQUAL_UINT32(3600, session->ttl_seconds);

    /* Cookie must not be all zeros */
    uint8_t zeros[IOG_SESSION_COOKIE_SIZE] = {0};
    int all_zero = 1;

    for (size_t i = 0; i < IOG_SESSION_COOKIE_SIZE; i++) {
        if (session->cookie[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT_FALSE(all_zero);
    (void)zeros;
}

void test_session_validate_success(void)
{
    iog_session_t *created = nullptr;
    int ret = iog_session_create(store, "bob", "admins", 3600, &created);

    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Save cookie for validation */
    uint8_t cookie[IOG_SESSION_COOKIE_SIZE];

    memcpy(cookie, created->cookie, IOG_SESSION_COOKIE_SIZE);

    iog_session_t *validated = nullptr;

    ret = iog_session_validate(store, cookie, IOG_SESSION_COOKIE_SIZE, &validated);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(validated);
    TEST_ASSERT_EQUAL_PTR(created, validated);
    TEST_ASSERT_EQUAL_STRING("bob", validated->username);
}

void test_session_validate_invalid(void)
{
    /* Create a session first so store is not empty */
    iog_session_t *session = nullptr;

    (void)iog_session_create(store, "charlie", nullptr, 3600, &session);

    /* Try validating with a bogus cookie */
    uint8_t bogus[IOG_SESSION_COOKIE_SIZE];

    memset(bogus, 0xAA, IOG_SESSION_COOKIE_SIZE);

    iog_session_t *out = nullptr;
    int ret = iog_session_validate(store, bogus, IOG_SESSION_COOKIE_SIZE, &out);

    TEST_ASSERT_EQUAL_INT(-ENOENT, ret);
    TEST_ASSERT_NULL(out);
}

void test_session_delete(void)
{
    iog_session_t *session = nullptr;
    int ret = iog_session_create(store, "dave", "users", 3600, &session);

    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t cookie[IOG_SESSION_COOKIE_SIZE];

    memcpy(cookie, session->cookie, IOG_SESSION_COOKIE_SIZE);

    ret = iog_session_delete(store, cookie, IOG_SESSION_COOKIE_SIZE);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Subsequent validate must fail */
    iog_session_t *out = nullptr;

    ret = iog_session_validate(store, cookie, IOG_SESSION_COOKIE_SIZE, &out);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_session_expiry(void)
{
    iog_session_t *session = nullptr;
    int ret = iog_session_create(store, "eve", nullptr, 1, &session);

    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(1, iog_session_count(store));

    /* Wait for expiry */
    sleep(2);

    uint32_t cleaned = iog_session_cleanup_expired(store);

    TEST_ASSERT_EQUAL_UINT32(1, cleaned);
    TEST_ASSERT_EQUAL_UINT32(0, iog_session_count(store));
}

void test_session_max_capacity(void)
{
    /* Store was created with max_sessions=8 */
    for (uint32_t i = 0; i < 8; i++) {
        iog_session_t *session = nullptr;
        int ret = iog_session_create(store, "user", nullptr, 3600, &session);

        TEST_ASSERT_EQUAL_INT(0, ret);
    }

    /* Next create must fail */
    iog_session_t *overflow = nullptr;
    int ret = iog_session_create(store, "overflow", nullptr, 3600, &overflow);

    TEST_ASSERT_EQUAL_INT(-EAGAIN, ret);
    TEST_ASSERT_NULL(overflow);
}

void test_session_count(void)
{
    TEST_ASSERT_EQUAL_UINT32(0, iog_session_count(store));

    iog_session_t *s1 = nullptr;
    iog_session_t *s2 = nullptr;

    (void)iog_session_create(store, "user1", nullptr, 3600, &s1);
    TEST_ASSERT_EQUAL_UINT32(1, iog_session_count(store));

    (void)iog_session_create(store, "user2", nullptr, 3600, &s2);
    TEST_ASSERT_EQUAL_UINT32(2, iog_session_count(store));

    uint8_t cookie[IOG_SESSION_COOKIE_SIZE];
    int ret;

    memcpy(cookie, s1->cookie, IOG_SESSION_COOKIE_SIZE);
    ret = iog_session_delete(store, cookie, IOG_SESSION_COOKIE_SIZE);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(1, iog_session_count(store));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_session_store_create_destroy);
    RUN_TEST(test_session_create_basic);
    RUN_TEST(test_session_validate_success);
    RUN_TEST(test_session_validate_invalid);
    RUN_TEST(test_session_delete);
    RUN_TEST(test_session_expiry);
    RUN_TEST(test_session_max_capacity);
    RUN_TEST(test_session_count);
    return UNITY_END();
}
