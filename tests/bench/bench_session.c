/**
 * @file bench_session.c
 * @brief Session create/validate/delete cycle benchmark.
 */
#include "bench_common.h"

#include <string.h>

#include "core/session.h"

constexpr int BENCH_ITERS = 10000;

static iog_session_store_t *store;

static void bench_create_validate_delete(void *arg)
{
    (void)arg;
    iog_session_t *session = nullptr;
    int ret = iog_session_create(store, "benchuser", "vpn", 300, &session);
    if (ret != 0) {
        return;
    }

    iog_session_t *found = nullptr;
    (void)iog_session_validate(store, session->cookie, IOG_SESSION_COOKIE_SIZE, &found);

    (void)iog_session_delete(store, session->cookie, IOG_SESSION_COOKIE_SIZE);
}

int main(void)
{
    store = iog_session_store_create(1024);
    if (store == nullptr) {
        fprintf(stderr, "Failed to create session store\n");
        return 1;
    }

    printf("=== Session Benchmark (%d iterations) ===\n", BENCH_ITERS);

    double ns = bench_ns_per_iter(bench_create_validate_delete, nullptr, BENCH_ITERS);
    bench_report("session create+validate+delete", ns, BENCH_ITERS);

    iog_session_store_destroy(store);
    return 0;
}
