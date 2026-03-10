/**
 * @file worker.h
 * @brief Worker process context and connection tracking.
 *
 * Manages per-worker state: configuration, connection pool (flat array),
 * and lifecycle states. No event loop — pure context management.
 */

#ifndef RINGWALL_CORE_WORKER_H
#define RINGWALL_CORE_WORKER_H

#include <stdbool.h>
#include <stdint.h>

#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

constexpr uint32_t RW_WORKER_DEFAULT_MAX_CONNS = 256;
constexpr uint32_t RW_WORKER_DEFAULT_QUEUE_DEPTH = 256;
constexpr uint32_t RW_WORKER_DEFAULT_TUN_MTU = 1406;

typedef enum : uint8_t {
    RW_WORKER_NEW,
    RW_WORKER_READY,
    RW_WORKER_RUNNING,
    RW_WORKER_STOPPING,
    RW_WORKER_STOPPED,
} rw_worker_state_t;

typedef struct {
    uint32_t max_connections;
    uint32_t queue_depth;
    uint32_t dpd_interval_s;
    uint32_t dpd_max_retries;
    uint32_t tun_mtu;
} rw_worker_config_t;

typedef struct {
    uint64_t conn_id;
    int tls_fd;
    int tun_fd;
    rw_dpd_ctx_t dpd;
    rw_compress_ctx_t compress;
    bool active;
    uint8_t recv_buf[RW_CSTP_HEADER_SIZE + RW_CSTP_MAX_PAYLOAD];
    size_t recv_len;
} rw_connection_t;

typedef struct rw_worker rw_worker_t;

/** Initialize worker config with defaults. */
void rw_worker_config_init(rw_worker_config_t *cfg);

/** Validate worker config. */
[[nodiscard]] int rw_worker_config_validate(const rw_worker_config_t *cfg);

/** Create a worker context. Returns nullptr on failure. */
[[nodiscard]] rw_worker_t *rw_worker_create(const rw_worker_config_t *cfg);

/** Destroy worker context and free resources. */
void rw_worker_destroy(rw_worker_t *w);

/** Get current worker state. */
[[nodiscard]] rw_worker_state_t rw_worker_state(const rw_worker_t *w);

/** Add a connection. Returns conn_id (>= 0) on success, negative errno on error. */
[[nodiscard]] int64_t rw_worker_add_connection(rw_worker_t *w, int tls_fd, int tun_fd);

/** Remove a connection by ID. Returns 0 on success, -ENOENT if not found. */
[[nodiscard]] int rw_worker_remove_connection(rw_worker_t *w, uint64_t conn_id);

/** Find a connection by ID. Returns nullptr if not found. */
[[nodiscard]] rw_connection_t *rw_worker_find_connection(rw_worker_t *w, uint64_t conn_id);

/** Get current number of active connections. */
[[nodiscard]] uint32_t rw_worker_connection_count(const rw_worker_t *w);

/** Get maximum connection slots (for iteration). */
[[nodiscard]] uint32_t rw_worker_max_connections(const rw_worker_t *w);

/**
 * @brief Get connection at slot index (for iteration over all slots).
 * @param w    Worker context.
 * @param idx  Slot index (0..max_connections-1).
 * @return Pointer to connection if active, nullptr if slot is empty.
 */
[[nodiscard]] rw_connection_t *rw_worker_connection_at(rw_worker_t *w, uint32_t idx);

/** Get human-readable worker state name. */
[[nodiscard]] const char *rw_worker_state_name(rw_worker_state_t state);

#endif /* RINGWALL_CORE_WORKER_H */
