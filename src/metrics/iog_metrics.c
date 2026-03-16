/**
 * @file iog_metrics.c
 * @brief Standard ioguard VPN metrics — registers counters and gauges.
 */

#include "metrics/iog_metrics.h"

#include <errno.h>

/* Static metric instances owned by this module. */

static iog_prom_counter_t s_connections_total = {
    .value = 0,
    .name = "iog_connections_total",
    .help = "Total VPN connections accepted",
};

static iog_prom_counter_t s_auth_attempts_total = {
    .value = 0,
    .name = "iog_auth_attempts_total",
    .help = "Total authentication attempts",
};

static iog_prom_counter_t s_auth_failures_total = {
    .value = 0,
    .name = "iog_auth_failures_total",
    .help = "Total authentication failures",
};

static iog_prom_counter_t s_bytes_rx_total = {
    .value = 0,
    .name = "iog_bytes_rx_total",
    .help = "Total bytes received from VPN clients",
};

static iog_prom_counter_t s_bytes_tx_total = {
    .value = 0,
    .name = "iog_bytes_tx_total",
    .help = "Total bytes transmitted to VPN clients",
};

static iog_prom_gauge_t s_active_sessions = {
    .value = 0,
    .name = "iog_active_sessions",
    .help = "Currently active VPN sessions",
};

int iog_metrics_init(iog_prom_registry_t *registry)
{
    if (registry == nullptr) {
        return -EINVAL;
    }

    int ret = iog_prom_register_counter(registry, &s_connections_total);
    if (ret != 0) {
        return ret;
    }

    ret = iog_prom_register_counter(registry, &s_auth_attempts_total);
    if (ret != 0) {
        return ret;
    }

    ret = iog_prom_register_counter(registry, &s_auth_failures_total);
    if (ret != 0) {
        return ret;
    }

    ret = iog_prom_register_counter(registry, &s_bytes_rx_total);
    if (ret != 0) {
        return ret;
    }

    ret = iog_prom_register_counter(registry, &s_bytes_tx_total);
    if (ret != 0) {
        return ret;
    }

    ret = iog_prom_register_gauge(registry, &s_active_sessions);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

void iog_metrics_inc_connections(void)
{
    iog_prom_counter_inc(&s_connections_total);
}

void iog_metrics_inc_auth_attempts(void)
{
    iog_prom_counter_inc(&s_auth_attempts_total);
}

void iog_metrics_inc_auth_failures(void)
{
    iog_prom_counter_inc(&s_auth_failures_total);
}

void iog_metrics_add_bytes_rx(uint64_t bytes)
{
    iog_prom_counter_add(&s_bytes_rx_total, bytes);
}

void iog_metrics_add_bytes_tx(uint64_t bytes)
{
    iog_prom_counter_add(&s_bytes_tx_total, bytes);
}

void iog_metrics_set_active_sessions(int64_t count)
{
    iog_prom_gauge_set(&s_active_sessions, count);
}
