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
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);

    TEST_ASSERT_EQUAL_UINT32(256, cfg.max_connections);
    TEST_ASSERT_EQUAL_UINT32(256, cfg.queue_depth);
    TEST_ASSERT_EQUAL_UINT32(30, cfg.dpd_interval_s);
    TEST_ASSERT_EQUAL_UINT32(3, cfg.dpd_max_retries);
    TEST_ASSERT_EQUAL_UINT32(1406, cfg.tun_mtu);
}

void test_worker_config_validate_valid(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);

    TEST_ASSERT_EQUAL_INT(0, rw_worker_config_validate(&cfg));
}

void test_worker_config_validate_zero_conns(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 0;

    TEST_ASSERT_EQUAL_INT(-EINVAL, rw_worker_config_validate(&cfg));
}

void test_worker_create_destroy(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 4;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    rw_worker_destroy(w);
}

void test_worker_state_initial(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 4;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    TEST_ASSERT_EQUAL_INT(RW_WORKER_NEW, rw_worker_state(w));

    rw_worker_destroy(w);
}

void test_worker_add_connection(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 4;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id = rw_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);
    TEST_ASSERT_EQUAL_UINT32(1, rw_worker_connection_count(w));

    rw_worker_destroy(w);
}

void test_worker_remove_connection(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 4;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id = rw_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);

    int ret = rw_worker_remove_connection(w, (uint64_t)id);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(0, rw_worker_connection_count(w));

    rw_worker_destroy(w);
}

void test_worker_connection_limit(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 2;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id1 = rw_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id1);

    int64_t id2 = rw_worker_add_connection(w, 12, 13);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id2);

    int64_t id3 = rw_worker_add_connection(w, 14, 15);
    TEST_ASSERT_EQUAL_INT64(-ENOSPC, id3);

    rw_worker_destroy(w);
}

void test_worker_find_connection(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 4;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    int64_t id = rw_worker_add_connection(w, 10, 11);
    TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);

    rw_connection_t *c = rw_worker_find_connection(w, (uint64_t)id);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_INT(10, c->tls_fd);
    TEST_ASSERT_EQUAL_INT(11, c->tun_fd);
    TEST_ASSERT_TRUE(c->active);

    rw_worker_destroy(w);
}

void test_worker_find_missing(void)
{
    rw_worker_config_t cfg;
    rw_worker_config_init(&cfg);
    cfg.max_connections = 4;

    rw_worker_t *w = rw_worker_create(&cfg);
    TEST_ASSERT_NOT_NULL(w);

    rw_connection_t *c = rw_worker_find_connection(w, 999);
    TEST_ASSERT_NULL(c);

    rw_worker_destroy(w);
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
