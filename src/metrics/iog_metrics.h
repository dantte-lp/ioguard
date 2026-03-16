/**
 * @file iog_metrics.h
 * @brief Standard ioguard VPN metrics — convenience wrappers over prometheus API.
 */

#ifndef IOGUARD_METRICS_IOG_METRICS_H
#define IOGUARD_METRICS_IOG_METRICS_H

#include "metrics/prometheus.h"

/**
 * @brief Initialize and register all standard ioguard metrics.
 * @param registry  Prometheus registry to register metrics with.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int iog_metrics_init(iog_prom_registry_t *registry);

/** @brief Increment total VPN connections counter by 1. */
void iog_metrics_inc_connections(void);

/** @brief Increment total authentication attempts counter by 1. */
void iog_metrics_inc_auth_attempts(void);

/** @brief Increment total authentication failures counter by 1. */
void iog_metrics_inc_auth_failures(void);

/**
 * @brief Add received bytes to the rx counter.
 * @param bytes  Number of bytes received.
 */
void iog_metrics_add_bytes_rx(uint64_t bytes);

/**
 * @brief Add transmitted bytes to the tx counter.
 * @param bytes  Number of bytes transmitted.
 */
void iog_metrics_add_bytes_tx(uint64_t bytes);

/**
 * @brief Set the active sessions gauge to an absolute value.
 * @param count  Current number of active sessions.
 */
void iog_metrics_set_active_sessions(int64_t count);

#endif /* IOGUARD_METRICS_IOG_METRICS_H */
