#ifndef IOGUARD_BENCH_COMMON_H
#define IOGUARD_BENCH_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>

/**
 * Benchmark timing harness — measures wall-clock time via CLOCK_MONOTONIC.
 * Returns nanoseconds per iteration.
 */
static inline double bench_ns_per_iter(void (*fn)(void *), void *arg, int iterations)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        fn(arg);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_ns =
        (double)(end.tv_sec - start.tv_sec) * 1e9 + (double)(end.tv_nsec - start.tv_nsec);
    return elapsed_ns / (double)iterations;
}

/** Print benchmark result in TSV-compatible format */
static inline void bench_report(const char *name, double ns_per_iter, int iterations)
{
    double us = ns_per_iter / 1000.0;
    double ops_per_sec = 1e9 / ns_per_iter;
    printf("%-40s %10.1f ns  %10.1f us  %12.0f ops/s  (%d iters)\n", name, ns_per_iter, us,
           ops_per_sec, iterations);
}

#endif /* IOGUARD_BENCH_COMMON_H */
