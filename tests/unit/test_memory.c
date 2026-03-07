#include <unity/unity.h>
#include <string.h>
#include "utils/memory.h"

void setUp(void) {}
void tearDown(void) {}

void test_wg_mem_init_returns_zero(void)
{
    int ret = wg_mem_init();
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_wg_mem_alloc_returns_nonnull(void)
{
    void *ptr = wg_mem_alloc(128);
    TEST_ASSERT_NOT_NULL(ptr);
    wg_mem_free(ptr);
}

void test_wg_mem_calloc_returns_zeroed(void)
{
    uint8_t *ptr = wg_mem_calloc(1, 64);
    TEST_ASSERT_NOT_NULL(ptr);
    for (int i = 0; i < 64; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, ptr[i]);
    }
    wg_mem_free(ptr);
}

void test_wg_mem_alloc_zero_returns_null(void)
{
    void *ptr = wg_mem_alloc(0);
    TEST_ASSERT_NULL(ptr);
}

void test_wg_mem_free_null_is_safe(void)
{
    wg_mem_free(nullptr); /* must not crash */
}

void test_wg_mem_secure_zero(void)
{
    uint8_t buf[32];
    memset(buf, 0xAA, sizeof(buf));
    wg_mem_secure_zero(buf, sizeof(buf));
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buf[i]);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_wg_mem_init_returns_zero);
    RUN_TEST(test_wg_mem_alloc_returns_nonnull);
    RUN_TEST(test_wg_mem_calloc_returns_zeroed);
    RUN_TEST(test_wg_mem_alloc_zero_returns_null);
    RUN_TEST(test_wg_mem_free_null_is_safe);
    RUN_TEST(test_wg_mem_secure_zero);
    return UNITY_END();
}
