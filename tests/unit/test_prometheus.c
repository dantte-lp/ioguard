#include <stdatomic.h>
#include <string.h>
#include <unity/unity.h>

#include "metrics/iog_metrics.h"
#include "metrics/prometheus.h"

static iog_prom_registry_t *registry;

void setUp(void)
{
    registry = nullptr;
}

void tearDown(void)
{
    iog_prom_registry_destroy(registry);
    registry = nullptr;
}

void test_prom_registry_create_destroy(void)
{
    int ret = iog_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_NULL(registry);

    /* destroy is called in tearDown */
}

void test_prom_counter_inc(void)
{
    iog_prom_counter_t counter = {
        .value = 0,
        .name = "iog_test_total",
        .help = "Test counter",
    };

    iog_prom_counter_inc(&counter);
    TEST_ASSERT_EQUAL_UINT64(1, atomic_load(&counter.value));
}

void test_prom_counter_add(void)
{
    iog_prom_counter_t counter = {
        .value = 0,
        .name = "iog_requests_total",
        .help = "Total requests",
    };

    iog_prom_counter_add(&counter, 42);
    TEST_ASSERT_EQUAL_UINT64(42, atomic_load(&counter.value));
}

void test_prom_gauge_set(void)
{
    iog_prom_gauge_t gauge = {
        .value = 0,
        .name = "iog_active_sessions",
        .help = "Currently active VPN sessions",
    };

    iog_prom_gauge_set(&gauge, 7);
    TEST_ASSERT_EQUAL_INT64(7, atomic_load(&gauge.value));
}

void test_prom_gauge_inc_dec(void)
{
    iog_prom_gauge_t gauge = {
        .value = 0,
        .name = "iog_active_sessions",
        .help = "Currently active VPN sessions",
    };

    iog_prom_gauge_inc(&gauge);
    TEST_ASSERT_EQUAL_INT64(1, atomic_load(&gauge.value));

    iog_prom_gauge_dec(&gauge);
    TEST_ASSERT_EQUAL_INT64(0, atomic_load(&gauge.value));
}

void test_prom_histogram_observe(void)
{
    iog_prom_histogram_t hist = {
        .name = "iog_tls_handshake_seconds",
        .help = "TLS handshake duration",
        .boundaries = {0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0},
    };
    memset((void *)hist.bucket_counts, 0, sizeof(hist.bucket_counts));
    atomic_store(&hist.sum_us, 0);
    atomic_store(&hist.count, 0);

    /* Observe values in different buckets */
    iog_prom_histogram_observe(&hist, 0.0005); /* <= 0.001 bucket */
    iog_prom_histogram_observe(&hist, 0.003);  /* <= 0.005 bucket */
    iog_prom_histogram_observe(&hist, 0.003);  /* <= 0.005 bucket */
    iog_prom_histogram_observe(&hist, 0.02);   /* <= 0.05 bucket */

    /* Verify individual bucket counts (non-cumulative internal storage) */
    TEST_ASSERT_EQUAL_UINT64(1, atomic_load(&hist.bucket_counts[0])); /* le=0.001 */
    TEST_ASSERT_EQUAL_UINT64(2, atomic_load(&hist.bucket_counts[1])); /* le=0.005 */
    TEST_ASSERT_EQUAL_UINT64(1, atomic_load(&hist.bucket_counts[3])); /* le=0.05 */

    /* +Inf always equals total count */
    TEST_ASSERT_EQUAL_UINT64(4, atomic_load(&hist.bucket_counts[IOG_PROM_HISTOGRAM_BUCKETS]));
    TEST_ASSERT_EQUAL_UINT64(4, atomic_load(&hist.count));
}

void test_prom_format_text_exposition(void)
{
    int ret = iog_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    iog_prom_counter_t counter = {
        .value = 0,
        .name = "iog_connections_total",
        .help = "Total VPN connections accepted",
    };
    iog_prom_counter_add(&counter, 42);

    iog_prom_gauge_t gauge = {
        .value = 0,
        .name = "iog_active_sessions",
        .help = "Currently active VPN sessions",
    };
    iog_prom_gauge_set(&gauge, 7);

    ret = iog_prom_register_counter(registry, &counter);
    TEST_ASSERT_EQUAL_INT(0, ret);
    ret = iog_prom_register_gauge(registry, &gauge);
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t len = iog_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Verify counter value appears in output */
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_connections_total 42"));

    /* Verify gauge value appears in output */
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_active_sessions 7"));
}

void test_prom_format_includes_help_type(void)
{
    int ret = iog_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    iog_prom_counter_t counter = {
        .value = 0,
        .name = "iog_connections_total",
        .help = "Total VPN connections accepted",
    };

    ret = iog_prom_register_counter(registry, &counter);
    TEST_ASSERT_EQUAL_INT(0, ret);

    char buf[4096];
    ssize_t len = iog_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    /* Verify HELP comment */
    TEST_ASSERT_NOT_NULL(
        strstr(buf, "# HELP iog_connections_total Total VPN connections accepted"));

    /* Verify TYPE comment */
    TEST_ASSERT_NOT_NULL(strstr(buf, "# TYPE iog_connections_total counter"));
}

void test_metrics_init_registers_all(void)
{
    int ret = iog_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_metrics_init(registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Verify all 6 metrics are registered by formatting and checking names */
    char buf[8192];
    ssize_t len = iog_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_connections_total"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_auth_attempts_total"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_auth_failures_total"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_bytes_rx_total"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_bytes_tx_total"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_active_sessions"));
}

void test_metrics_inc_connections(void)
{
    int ret = iog_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_metrics_init(registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    iog_metrics_inc_connections();
    iog_metrics_inc_connections();
    iog_metrics_inc_connections();

    /* Verify counter value via formatted output */
    char buf[8192];
    ssize_t len = iog_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_connections_total 3"));
}

void test_metrics_set_active_sessions(void)
{
    int ret = iog_prom_registry_create(&registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_metrics_init(registry);
    TEST_ASSERT_EQUAL_INT(0, ret);

    iog_metrics_set_active_sessions(42);

    /* Verify gauge value via formatted output */
    char buf[8192];
    ssize_t len = iog_prom_format(registry, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    TEST_ASSERT_NOT_NULL(strstr(buf, "iog_active_sessions 42"));
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
    RUN_TEST(test_metrics_init_registers_all);
    RUN_TEST(test_metrics_inc_connections);
    RUN_TEST(test_metrics_set_active_sessions);
    return UNITY_END();
}
