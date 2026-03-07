#include <unity/unity.h>
#include "core/worker.h"
#include <errno.h>

void setUp(void) {}
void tearDown(void) {}

void test_worker_config_init_defaults(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);

	TEST_ASSERT_EQUAL_UINT32(256, cfg.max_connections);
	TEST_ASSERT_EQUAL_UINT32(256, cfg.queue_depth);
	TEST_ASSERT_EQUAL_UINT32(30, cfg.dpd_interval_s);
	TEST_ASSERT_EQUAL_UINT32(3, cfg.dpd_max_retries);
	TEST_ASSERT_EQUAL_UINT32(1406, cfg.tun_mtu);
}

void test_worker_config_validate_valid(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);

	TEST_ASSERT_EQUAL_INT(0, wg_worker_config_validate(&cfg));
}

void test_worker_config_validate_zero_conns(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 0;

	TEST_ASSERT_EQUAL_INT(-EINVAL, wg_worker_config_validate(&cfg));
}

void test_worker_create_destroy(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	wg_worker_destroy(w);
}

void test_worker_state_initial(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	TEST_ASSERT_EQUAL_INT(WG_WORKER_NEW, wg_worker_state(w));

	wg_worker_destroy(w);
}

void test_worker_add_connection(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	int64_t id = wg_worker_add_connection(w, 10, 11);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);
	TEST_ASSERT_EQUAL_UINT32(1, wg_worker_connection_count(w));

	wg_worker_destroy(w);
}

void test_worker_remove_connection(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	int64_t id = wg_worker_add_connection(w, 10, 11);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);

	int ret = wg_worker_remove_connection(w, (uint64_t)id);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_UINT32(0, wg_worker_connection_count(w));

	wg_worker_destroy(w);
}

void test_worker_connection_limit(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 2;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	int64_t id1 = wg_worker_add_connection(w, 10, 11);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id1);

	int64_t id2 = wg_worker_add_connection(w, 12, 13);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id2);

	int64_t id3 = wg_worker_add_connection(w, 14, 15);
	TEST_ASSERT_EQUAL_INT64(-ENOSPC, id3);

	wg_worker_destroy(w);
}

void test_worker_find_connection(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	int64_t id = wg_worker_add_connection(w, 10, 11);
	TEST_ASSERT_GREATER_OR_EQUAL_INT64(1, id);

	wg_connection_t *c = wg_worker_find_connection(w, (uint64_t)id);
	TEST_ASSERT_NOT_NULL(c);
	TEST_ASSERT_EQUAL_INT(10, c->tls_fd);
	TEST_ASSERT_EQUAL_INT(11, c->tun_fd);
	TEST_ASSERT_TRUE(c->active);

	wg_worker_destroy(w);
}

void test_worker_find_missing(void)
{
	wg_worker_config_t cfg;
	wg_worker_config_init(&cfg);
	cfg.max_connections = 4;

	wg_worker_t *w = wg_worker_create(&cfg);
	TEST_ASSERT_NOT_NULL(w);

	wg_connection_t *c = wg_worker_find_connection(w, 999);
	TEST_ASSERT_NULL(c);

	wg_worker_destroy(w);
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
