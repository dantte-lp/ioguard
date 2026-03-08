/**
 * @file worker.h
 * @brief Worker process context and connection tracking.
 *
 * Manages per-worker state: configuration, connection pool (flat array),
 * and lifecycle states. No event loop — pure context management.
 */

#ifndef WOLFGUARD_CORE_WORKER_H
#define WOLFGUARD_CORE_WORKER_H

#include <stdbool.h>
#include <stdint.h>

#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

constexpr uint32_t WG_WORKER_DEFAULT_MAX_CONNS = 256;
constexpr uint32_t WG_WORKER_DEFAULT_QUEUE_DEPTH = 256;
constexpr uint32_t WG_WORKER_DEFAULT_TUN_MTU = 1406;

typedef enum : uint8_t {
	WG_WORKER_NEW,
	WG_WORKER_READY,
	WG_WORKER_RUNNING,
	WG_WORKER_STOPPING,
	WG_WORKER_STOPPED,
} wg_worker_state_t;

typedef struct {
	uint32_t max_connections;
	uint32_t queue_depth;
	uint32_t dpd_interval_s;
	uint32_t dpd_max_retries;
	uint32_t tun_mtu;
} wg_worker_config_t;

typedef struct {
	uint64_t conn_id;
	int tls_fd;
	int tun_fd;
	wg_dpd_ctx_t dpd;
	wg_compress_ctx_t compress;
	bool active;
	uint8_t recv_buf[WG_CSTP_HEADER_SIZE + WG_CSTP_MAX_PAYLOAD];
	size_t recv_len;
} wg_connection_t;

typedef struct wg_worker wg_worker_t;

/** Initialize worker config with defaults. */
void wg_worker_config_init(wg_worker_config_t *cfg);

/** Validate worker config. */
[[nodiscard]] int wg_worker_config_validate(const wg_worker_config_t *cfg);

/** Create a worker context. Returns nullptr on failure. */
[[nodiscard]] wg_worker_t *wg_worker_create(const wg_worker_config_t *cfg);

/** Destroy worker context and free resources. */
void wg_worker_destroy(wg_worker_t *w);

/** Get current worker state. */
[[nodiscard]] wg_worker_state_t wg_worker_state(const wg_worker_t *w);

/** Add a connection. Returns conn_id (>= 0) on success, negative errno on error. */
[[nodiscard]] int64_t wg_worker_add_connection(wg_worker_t *w, int tls_fd, int tun_fd);

/** Remove a connection by ID. Returns 0 on success, -ENOENT if not found. */
[[nodiscard]] int wg_worker_remove_connection(wg_worker_t *w, uint64_t conn_id);

/** Find a connection by ID. Returns nullptr if not found. */
[[nodiscard]] wg_connection_t *wg_worker_find_connection(wg_worker_t *w, uint64_t conn_id);

/** Get current number of active connections. */
[[nodiscard]] uint32_t wg_worker_connection_count(const wg_worker_t *w);

/** Get human-readable worker state name. */
[[nodiscard]] const char *wg_worker_state_name(wg_worker_state_t state);

#endif /* WOLFGUARD_CORE_WORKER_H */
