#include <stdatomic.h>
#include <string.h>
#include <unity/unity.h>

#include "metrics/prometheus.h"

static rw_prom_registry_t *registry;

void setUp(void)
{
    registry = nullptr;
}

void tearDown(void)
{
    rw_prom_registry_destroy(registry);
    registry = nullptr;
}

void test_prom_registry_create_destroy(void)
{
    int ret = rw_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(registry);

    /* destroy is called in tearDown */
}

void test_prom_counter_inc(void)
{
    rw_prom_counter_t counter = {
        .value = 0,
        .name = "rw_test_total",
        .help = "Test counter",
    };

    rw_prom_counter_inc(&counter);
    TEST_ASSERT_EQUAL_UINT64(1, atomic_load(&counter.value));
}

void test_prom_counter_add(void)
{
    rw_prom_counter_t counter = {
        .value = 0,
        .name = "rw_requests_total",
        .help = "Total requests",
    };

    rw_prom_counter_add(&counter, 42);
    TEST_ASSERT_EQUAL_UINT64(42, atomic_load(&counter.value));
}

void test_prom_gauge_set(void)
{
    rw_prom_gauge_t gauge = {
        .value = 0,
        .name = "rw_active_sessions",
        .help = "Currently active VPN sessions",
    };

    rw_prom_gauge_set(&gauge, 7);
    TEST_ASSERT_EQUAL_INT64(7, atomic_load(&gauge.value));
}

void test_prom_gauge_inc_dec(void)
{
    rw_prom_gauge_t gauge = {
        .value = 0,
        .name = "rw_active_sessions",
        .help = "Currently active VPN sessions",
    };

    rw_prom_gauge_inc(&gauge);
    TEST_ASSERT_EQUAL_INT64(1, atomic_load(&gauge.value));

    rw_prom_gauge_dec(&gauge);
    TEST_ASSERT_EQUAL_INT64(0, atomic_load(&gauge.value));
}

void test_prom_histogram_observe(void)
{
    rw_prom_histogram_t hist = {
        .name = "rw_tls_handshake_seconds",
        .help = "TLS handshake duration",
        .boundaries = { 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0 },
    };
    memset((void *)hist.bucket_counts, 0, sizeof(hist.bucket_counts));
    atomic_store(&hist.sum_us, 0);
    atomic_store(&hist.count, 0);

    /* Observe values in different buckets */
    rw_prom_histogram_observe(&hist, 0.0005); /* <= 0.001 bucket */
    rw_prom_histogram_observe(&hist, 0.003);  /* <= 0.005 bucket */
    rw_prom_histogram_observe(&hist, 0.003);  /* <= 0.005 bucket */
    rw_prom_histogram_observe(&hist, 0.02);   /* <= 0.05 bucket */

    /* Verify individual bucket counts (non-cumulative internal storage) */
    TEST_ASSERT_EQUAL_UINT64(1, atomic_load(&hist.bucket_counts[0])); /* le=0.001 */
    TEST_ASSERT_EQUAL_UINT64(2, atomic_load(&hist.bucket_counts[1])); /* le=0.005 */
    TEST_ASSERT_EQUAL_UINT64(1, atomic_load(&hist.bucket_counts[3])); /* le=0.05 */

    /* +Inf always equals total count */
    TEST_ASSERT_EQUAL_UINT64(4, atomic_load(&hist.bucket_counts[RW_PROM_HISTOGRAM_BUCKETS]));
    TEST_ASSERT_EQUAL_UINT64(4, atomic_load(&hist.count));
}

void test_prom_format_text_exposition(void)
{
    int ret = rw_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    rw_prom_counter_t counter = {
        .value = 0,
        .name = "rw_connections_total",
        .help = "Total VPN connections accepted",
    };
    rw_prom_counter_add(&counter, 42);

    rw_prom_gauge_t gauge = {
        .value = 0,
        .name = "rw_active_sessions",
        .help = "Currently active VPN sessions",
    };
    rw_prom_gauge_set(&gauge, 7);

    ret = rw_prom_register_counter(registry, &counter);
    TEST_ASSERT_EQUAL_INT(0, ret);
    ret = rw_prom_register_gauge(registry, &gauge);
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t len = rw_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Verify counter value appears in output */
    TEST_ASSERT_NOT_NULL(strstr(buf, "rw_connections_total 42"));

    /* Verify gauge value appears in output */
    TEST_ASSERT_NOT_NULL(strstr(buf, "rw_active_sessions 7"));
}

void test_prom_format_includes_help_type(void)
{
    int ret = rw_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    rw_prom_counter_t counter = {
        .value = 0,
        .name = "rw_connections_total",
        .help = "Total VPN connections accepted",
    };

    ret = rw_prom_register_counter(registry, &counter);
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t len = rw_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Verify HELP comment */
    TEST_ASSERT_NOT_NULL(
        strstr(buf, "# HELP rw_connections_total Total VPN connections accepted"));

    /* Verify TYPE comment */
    TEST_ASSERT_NOT_NULL(strstr(buf, "# TYPE rw_connections_total counter"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_prom_registry_create_destroy);
    RUN_TEST(test_prom_counter_inc);
    RUN_TEST(test_prom_counter_add);
    RUN_TEST(test_prom_gauge_set);
    RUN_TEST(test_prom_gauge_inc_dec);
    RUN_TEST(test_prom_histogram_observe);
    RUN_TEST(test_prom_format_text_exposition);
    RUN_TEST(test_prom_format_includes_help_type);
    return UNITY_END();
}
