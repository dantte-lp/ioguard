/**
 * @file worker.h
 * @brief Worker process context and connection tracking.
 *
 * Manages per-worker state: configuration, connection pool (flat array),
 * and lifecycle states. No event loop — pure context management.
 */

#ifndef RINGWALL_CORE_WORKER_H
#define RINGWALL_CORE_WORKER_H

#include <stdint.h>

#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

constexpr uint32_t IOG_WORKER_DEFAULT_MAX_CONNS = 256;
constexpr uint32_t IOG_WORKER_DEFAULT_QUEUE_DEPTH = 256;
constexpr uint32_t IOG_WORKER_DEFAULT_TUN_MTU = 1406;

typedef enum : uint8_t {
    IOG_WORKER_NEW,
    IOG_WORKER_READY,
    IOG_WORKER_RUNNING,
    IOG_WORKER_STOPPING,
    IOG_WORKER_STOPPED,
} iog_worker_state_t;

typedef struct {
    uint32_t max_connections;
    uint32_t queue_depth;
    uint32_t dpd_interval_s;
    uint32_t dpd_max_retries;
    uint32_t tun_mtu;
} iog_worker_config_t;

typedef struct {
    uint64_t conn_id;
    int tls_fd;
    int tun_fd;
    rw_dpd_ctx_t dpd;
    rw_compress_ctx_t compress;
    bool active;
    uint8_t recv_buf[IOG_CSTP_HEADER_SIZE + IOG_CSTP_MAX_PAYLOAD];
    size_t recv_len;
} iog_connection_t;

typedef struct rw_worker iog_worker_t;

/** Initialize worker config with defaults. */
void iog_worker_config_init(iog_worker_config_t *cfg);

/** Validate worker config. */
[[nodiscard]] int iog_worker_config_validate(const iog_worker_config_t *cfg);

/** Create a worker context. Returns nullptr on failure. */
[[nodiscard]] iog_worker_t *iog_worker_create(const iog_worker_config_t *cfg);

/** Destroy worker context and free resources. */
void iog_worker_destroy(iog_worker_t *w);

/** Get current worker state. */
[[nodiscard]] iog_worker_state_t iog_worker_state(const iog_worker_t *w);

/** Add a connection. Returns conn_id (>= 0) on success, negative errno on error. */
[[nodiscard]] int64_t iog_worker_add_connection(iog_worker_t *w, int tls_fd, int tun_fd);

/** Remove a connection by ID. Returns 0 on success, -ENOENT if not found. */
[[nodiscard]] int iog_worker_remove_connection(iog_worker_t *w, uint64_t conn_id);

/** Find a connection by ID. Returns nullptr if not found. */
[[nodiscard]] iog_connection_t *iog_worker_find_connection(iog_worker_t *w, uint64_t conn_id);

/** Get current number of active connections. */
[[nodiscard]] uint32_t iog_worker_connection_count(const iog_worker_t *w);

/** Get maximum connection slots (for iteration). */
[[nodiscard]] uint32_t iog_worker_max_connections(const iog_worker_t *w);

/**
 * @brief Get connection at slot index (for iteration over all slots).
 * @param w    Worker context.
 * @param idx  Slot index (0..max_connections-1).
 * @return Pointer to connection if active, nullptr if slot is empty.
 */
[[nodiscard]] iog_connection_t *iog_worker_connection_at(iog_worker_t *w, uint32_t idx);

/** Get human-readable worker state name. */
[[nodiscard]] const char *iog_worker_state_name(iog_worker_state_t state);

#endif /* RINGWALL_CORE_WORKER_H */
