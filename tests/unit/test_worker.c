#include <errno.h>
#include <unity/unity.h>
#include "core/worker.h"

void setUp(void)
{
}
void tearDown(void)
{
}

void test_worker_config_init_defaults(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);

    TEST_ASSERT_EQUAL_UINT32(256, cfg.max_connections);
    TEST_ASSERT_EQUAL_UINT32(256, cfg.queue_depth);
    TEST_ASSERT_EQUAL_UINT32(30, cfg.dpd_interval_s);
    TEST_ASSERT_EQUAL_UINT32(3, cfg.dpd_max_retries);
    TEST_ASSERT_EQUAL_UINT32(1406, cfg.tun_mtu);
}

void test_worker_config_validate_valid(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);

    TEST_ASSERT_EQUAL_INT(0, iog_worker_config_validate(&cfg));
}

void test_worker_config_validate_zero_conns(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 0;

    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_worker_config_validate(&cfg));
}

void test_worker_create_destroy(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    iog_worker_destroy(w);
}

void test_worker_state_initial(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    TEST_ASSERT_EQUAL_INT(IOG_WORKER_NEW, iog_worker_state(w));

    iog_worker_destroy(w);
}

void test_worker_add_connection(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id = iog_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);
    TEST_ASSERT_EQUAL_UINT32(1, iog_worker_connection_count(w));

    iog_worker_destroy(w);
}

void test_worker_remove_connection(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id = iog_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);

    int ret = iog_worker_remove_connection(w, (uint64_t)id);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(0, iog_worker_connection_count(w));

    iog_worker_destroy(w);
}

void test_worker_connection_limit(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 2;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id1 = iog_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id1);

    int64_t id2 = iog_worker_add_connection(w, 12, 13);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id2);

    int64_t id3 = iog_worker_add_connection(w, 14, 15);
    TEST_ASSERT_EQUAL_INT64(-ENOSPC, id3);

    iog_worker_destroy(w);
}

void test_worker_find_connection(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id = iog_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);

    iog_connection_t *c = iog_worker_find_connection(w, (uint64_t)id);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_INT(10, c->tls_fd);
    TEST_ASSERT_EQUAL_INT(11, c->tun_fd);
    TEST_ASSERT_TRUE(c->active);

    iog_worker_destroy(w);
}

void test_worker_find_missing(void)
{
    iog_worker_config_t cfg;
    iog_worker_config_init(&cfg);
    cfg.max_connections = 4;

    iog_worker_t *w = iog_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    iog_connection_t *c = iog_worker_find_connection(w, 999);
    TEST_ASSERT_NULL(c);

    iog_worker_destroy(w);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_worker_config_init_defaults);
    RUN_TEST(test_worker_config_validate_valid);
    RUN_TEST(test_worker_config_validate_zero_conns);
    RUN_TEST(test_worker_create_destroy);
    RUN_TEST(test_worker_state_initial);
    RUN_TEST(test_worker_add_connection);
    RUN_TEST(test_worker_remove_connection);
    RUN_TEST(test_worker_connection_limit);
    RUN_TEST(test_worker_find_connection);
    RUN_TEST(test_worker_find_missing);
    return UNITY_END();
}
