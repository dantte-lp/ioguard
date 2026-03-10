/**
 * @file prometheus.c
 * @brief Custom Prometheus metrics — lock-free counters, gauges, histograms.
 */

#include "metrics/prometheus.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rw_prom_registry {
    rw_prom_counter_t *counters[IOG_PROM_MAX_METRICS];
    size_t counter_count;
    rw_prom_gauge_t *gauges[IOG_PROM_MAX_METRICS];
    size_t gauge_count;
    rw_prom_histogram_t *histograms[IOG_PROM_MAX_METRICS];
    size_t histogram_count;
};

int rw_prom_registry_create(rw_prom_registry_t **out)
{
    if (out == nullptr)
        return -EINVAL;

    rw_prom_registry_t *reg = calloc(1, sizeof(*reg));
    if (reg == nullptr)
        return -ENOMEM;

    *out = reg;
    return 0;
}

void rw_prom_registry_destroy(rw_prom_registry_t *reg)
{
    free(reg);
}

int rw_prom_register_counter(rw_prom_registry_t *reg, rw_prom_counter_t *counter)
{
    if (reg == nullptr || counter == nullptr)
        return -EINVAL;
    if (reg->counter_count >= IOG_PROM_MAX_METRICS)
        return -ENOSPC;

    reg->counters[reg->counter_count++] = counter;
    return 0;
}

int rw_prom_register_gauge(rw_prom_registry_t *reg, rw_prom_gauge_t *gauge)
{
    if (reg == nullptr || gauge == nullptr)
        return -EINVAL;
    if (reg->gauge_count >= IOG_PROM_MAX_METRICS)
        return -ENOSPC;

    reg->gauges[reg->gauge_count++] = gauge;
    return 0;
}

int rw_prom_register_histogram(rw_prom_registry_t *reg, rw_prom_histogram_t *hist)
{
    if (reg == nullptr || hist == nullptr)
        return -EINVAL;
    if (reg->histogram_count >= IOG_PROM_MAX_METRICS)
        return -ENOSPC;

    reg->histograms[reg->histogram_count++] = hist;
    return 0;
}

void rw_prom_counter_inc(rw_prom_counter_t *counter)
{
    if (counter == nullptr)
        return;
    atomic_fetch_add(&counter->value, 1);
}

void rw_prom_counter_add(rw_prom_counter_t *counter, uint64_t n)
{
    if (counter == nullptr)
        return;
    atomic_fetch_add(&counter->value, n);
}

void rw_prom_gauge_set(rw_prom_gauge_t *gauge, int64_t val)
{
    if (gauge == nullptr)
        return;
    atomic_store(&gauge->value, val);
}

void rw_prom_gauge_inc(rw_prom_gauge_t *gauge)
{
    if (gauge == nullptr)
        return;
    atomic_fetch_add(&gauge->value, 1);
}

void rw_prom_gauge_dec(rw_prom_gauge_t *gauge)
{
    if (gauge == nullptr)
        return;
    atomic_fetch_sub(&gauge->value, 1);
}

void rw_prom_histogram_observe(rw_prom_histogram_t *hist, double value)
{
    if (hist == nullptr)
        return;

    /* Find the first bucket whose boundary >= value and increment it.
     * Also always increment the +Inf bucket (last slot). */
    for (size_t i = 0; i < IOG_PROM_HISTOGRAM_BUCKETS; i++) {
        if (value <= hist->boundaries[i]) {
            atomic_fetch_add(&hist->bucket_counts[i], 1);
            break;
        }
    }

    /* +Inf bucket always gets incremented */
    atomic_fetch_add(&hist->bucket_counts[IOG_PROM_HISTOGRAM_BUCKETS], 1);

    /* Track sum in microseconds (value is in seconds) */
    uint64_t us = (uint64_t)(value * 1000000.0);
    atomic_fetch_add(&hist->sum_us, us);
    atomic_fetch_add(&hist->count, 1);
}

/**
 * Append formatted text to the buffer, tracking position and remaining space.
 * Returns the number of characters that would have been written (like snprintf).
 */
static int prom_append(char *buf, size_t buf_size, size_t *offset, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static int prom_append(char *buf, size_t buf_size, size_t *offset, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    size_t remaining = 0;
    char *dest = nullptr;

    if (*offset < buf_size) {
        remaining = buf_size - *offset;
        dest = buf + *offset;
    }

    int written = vsnprintf(dest, remaining, fmt, ap);
    va_end(ap);

    if (written < 0)
        return written;

    *offset += (size_t)written;
    return written;
}

ssize_t rw_prom_format(const rw_prom_registry_t *reg, char *buf, size_t buf_size)
{
    if (reg == nullptr || buf == nullptr || buf_size == 0)
        return -EINVAL;

    size_t offset = 0;

    /* Format counters */
    for (size_t i = 0; i < reg->counter_count; i++) {
        const rw_prom_counter_t *c = reg->counters[i];
        uint64_t val = atomic_load(&c->value);

        if (c->help != nullptr)
            prom_append(buf, buf_size, &offset, "# HELP %s %s\n", c->name, c->help);
        prom_append(buf, buf_size, &offset, "# TYPE %s counter\n", c->name);
        prom_append(buf, buf_size, &offset, "%s %" PRIu64 "\n\n", c->name, val);
    }

    /* Format gauges */
    for (size_t i = 0; i < reg->gauge_count; i++) {
        const rw_prom_gauge_t *g = reg->gauges[i];
        int64_t val = atomic_load(&g->value);

        if (g->help != nullptr)
            prom_append(buf, buf_size, &offset, "# HELP %s %s\n", g->name, g->help);
        prom_append(buf, buf_size, &offset, "# TYPE %s gauge\n", g->name);
        prom_append(buf, buf_size, &offset, "%s %" PRId64 "\n\n", g->name, val);
    }

    /* Format histograms */
    for (size_t i = 0; i < reg->histogram_count; i++) {
        const rw_prom_histogram_t *h = reg->histograms[i];

        if (h->help != nullptr)
            prom_append(buf, buf_size, &offset, "# HELP %s %s\n", h->name, h->help);
        prom_append(buf, buf_size, &offset, "# TYPE %s histogram\n", h->name);

        /* Cumulative bucket counts for Prometheus exposition */
        uint64_t cumulative = 0;
        for (size_t b = 0; b < IOG_PROM_HISTOGRAM_BUCKETS; b++) {
            uint64_t cnt = atomic_load(&h->bucket_counts[b]);
            if (h->boundaries[b] == 0.0 && b > 0)
                break; /* unused bucket slot */
            cumulative += cnt;
            prom_append(buf, buf_size, &offset,
                        "%s_bucket{le=\"%.3g\"} %" PRIu64 "\n",
                        h->name, h->boundaries[b], cumulative);
        }

        /* +Inf bucket */
        uint64_t total = atomic_load(&h->count);
        prom_append(buf, buf_size, &offset,
                    "%s_bucket{le=\"+Inf\"} %" PRIu64 "\n", h->name, total);

        /* Sum and count */
        uint64_t sum_us = atomic_load(&h->sum_us);
        double sum_sec = (double)sum_us / 1000000.0;
        prom_append(buf, buf_size, &offset, "%s_sum %.6f\n", h->name, sum_sec);
        prom_append(buf, buf_size, &offset, "%s_count %" PRIu64 "\n\n", h->name, total);
    }

    if (offset >= buf_size)
        return -ENOSPC;

    return (ssize_t)offset;
}
