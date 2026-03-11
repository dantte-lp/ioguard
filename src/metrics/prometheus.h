/**
 * @file prometheus.h
 * @brief Custom Prometheus metrics with text exposition format.
 *
 * Lock-free counters, gauges, and histograms using C11 atomics.
 * No external dependencies — pure C implementation.
 */

#ifndef IOGUARD_METRICS_PROMETHEUS_H
#define IOGUARD_METRICS_PROMETHEUS_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/** Maximum number of histogram buckets (excluding +Inf). */
constexpr size_t IOG_PROM_HISTOGRAM_BUCKETS = 12;

/** Maximum number of metrics per type in a registry. */
constexpr size_t IOG_PROM_MAX_METRICS = 64;

/** Monotonically increasing counter (uint64, atomic). */
typedef struct {
    _Atomic uint64_t value;
    const char *name;
    const char *help;
} iog_prom_counter_t;

/** Gauge that can go up and down (int64, atomic). */
typedef struct {
    _Atomic int64_t value;
    const char *name;
    const char *help;
} iog_prom_gauge_t;

/** Histogram with fixed bucket boundaries. */
typedef struct {
    const char *name;
    const char *help;
    double boundaries[IOG_PROM_HISTOGRAM_BUCKETS];
    _Atomic uint64_t bucket_counts[IOG_PROM_HISTOGRAM_BUCKETS + 1]; /* +1 for +Inf */
    _Atomic uint64_t sum_us; /* sum in microseconds */
    _Atomic uint64_t count;
} iog_prom_histogram_t;

/** Opaque registry owning references to all registered metrics. */
typedef struct iog_prom_registry iog_prom_registry_t;

/**
 * @brief Create a new Prometheus metrics registry.
 * @param out  Pointer to store the allocated registry.
 * @return 0 on success, -EINVAL if out is nullptr, -ENOMEM on allocation failure.
 */
[[nodiscard]] int iog_prom_registry_create(iog_prom_registry_t **out);

/**
 * @brief Destroy a registry and free its memory.
 * @param reg  Registry to destroy (nullptr is safe).
 */
void iog_prom_registry_destroy(iog_prom_registry_t *reg);

/**
 * @brief Register a counter with the registry.
 * @param reg     Registry to register with.
 * @param counter Counter to register (caller retains ownership).
 * @return 0 on success, -EINVAL if arguments are nullptr, -ENOSPC if full.
 */
[[nodiscard]] int iog_prom_register_counter(iog_prom_registry_t *reg,
                                           iog_prom_counter_t *counter);

/**
 * @brief Register a gauge with the registry.
 * @param reg   Registry to register with.
 * @param gauge Gauge to register (caller retains ownership).
 * @return 0 on success, -EINVAL if arguments are nullptr, -ENOSPC if full.
 */
[[nodiscard]] int iog_prom_register_gauge(iog_prom_registry_t *reg,
                                         iog_prom_gauge_t *gauge);

/**
 * @brief Register a histogram with the registry.
 * @param reg  Registry to register with.
 * @param hist Histogram to register (caller retains ownership).
 * @return 0 on success, -EINVAL if arguments are nullptr, -ENOSPC if full.
 */
[[nodiscard]] int iog_prom_register_histogram(iog_prom_registry_t *reg,
                                             iog_prom_histogram_t *hist);

/**
 * @brief Increment a counter by 1.
 * @param counter Counter to increment.
 */
void iog_prom_counter_inc(iog_prom_counter_t *counter);

/**
 * @brief Add a value to a counter.
 * @param counter Counter to add to.
 * @param n       Value to add.
 */
void iog_prom_counter_add(iog_prom_counter_t *counter, uint64_t n);

/**
 * @brief Set a gauge to an absolute value.
 * @param gauge Gauge to set.
 * @param val   Value to set.
 */
void iog_prom_gauge_set(iog_prom_gauge_t *gauge, int64_t val);

/**
 * @brief Increment a gauge by 1.
 * @param gauge Gauge to increment.
 */
void iog_prom_gauge_inc(iog_prom_gauge_t *gauge);

/**
 * @brief Decrement a gauge by 1.
 * @param gauge Gauge to decrement.
 */
void iog_prom_gauge_dec(iog_prom_gauge_t *gauge);

/**
 * @brief Observe a value in a histogram.
 * @param hist  Histogram to observe into.
 * @param value Observed value (same unit as boundaries).
 */
void iog_prom_histogram_observe(iog_prom_histogram_t *hist, double value);

/**
 * @brief Format all registered metrics in Prometheus text exposition format.
 * @param reg      Registry containing metrics.
 * @param buf      Output buffer for the formatted text.
 * @param buf_size Size of the output buffer in bytes.
 * @return Number of bytes written (excluding NUL) on success,
 *         -EINVAL if arguments are invalid, -ENOSPC if buffer is too small.
 */
[[nodiscard]] ssize_t iog_prom_format(const iog_prom_registry_t *reg, char *buf,
                                     size_t buf_size);

#endif /* IOGUARD_METRICS_PROMETHEUS_H */
