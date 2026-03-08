#include "core/worker.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct wg_worker {
	wg_worker_config_t config;
	wg_worker_state_t state;
	wg_connection_t *conns;
	uint32_t conn_count;
	uint64_t next_conn_id;
};

void wg_worker_config_init(wg_worker_config_t *cfg)
{
	*cfg = (wg_worker_config_t){
		.max_connections = WG_WORKER_DEFAULT_MAX_CONNS,
		.queue_depth = WG_WORKER_DEFAULT_QUEUE_DEPTH,
		.dpd_interval_s = WG_DPD_DEFAULT_INTERVAL_S,
		.dpd_max_retries = WG_DPD_DEFAULT_MAX_RETRIES,
		.tun_mtu = WG_WORKER_DEFAULT_TUN_MTU,
	};
}

int wg_worker_config_validate(const wg_worker_config_t *cfg)
{
	if (cfg->max_connections == 0)
		return -EINVAL;
	if (cfg->queue_depth == 0)
		return -EINVAL;
	if (cfg->tun_mtu == 0)
		return -EINVAL;
	return 0;
}

wg_worker_t *wg_worker_create(const wg_worker_config_t *cfg)
{
	if (wg_worker_config_validate(cfg) != 0)
		return nullptr;

	wg_worker_t *w = calloc(1, sizeof(*w));
	if (!w)
		return nullptr;

	w->conns = calloc(cfg->max_connections, sizeof(*w->conns));
	if (!w->conns) {
		free(w);
		return nullptr;
	}

	w->config = *cfg;
	w->state = WG_WORKER_NEW;
	w->conn_count = 0;
	w->next_conn_id = 1;

	return w;
}

void wg_worker_destroy(wg_worker_t *w)
{
	if (!w)
		return;
	for (uint32_t i = 0; i < w->config.max_connections; i++) {
		if (w->conns[i].active)
			wg_compress_destroy(&w->conns[i].compress);
	}
	explicit_bzero(w->conns, w->config.max_connections * sizeof(*w->conns));
	free(w->conns);
	explicit_bzero(w, sizeof(*w));
	free(w);
}

wg_worker_state_t wg_worker_state(const wg_worker_t *w)
{
	return w->state;
}

int64_t wg_worker_add_connection(wg_worker_t *w, int tls_fd, int tun_fd)
{
	if (w->conn_count >= w->config.max_connections)
		return -ENOSPC;

	/* Find first inactive slot */
	for (uint32_t i = 0; i < w->config.max_connections; i++) {
		if (!w->conns[i].active) {
			wg_connection_t *c = &w->conns[i];
			memset(c, 0, sizeof(*c));
			c->conn_id = w->next_conn_id++;
			c->tls_fd = tls_fd;
			c->tun_fd = tun_fd;
			c->active = true;
			c->recv_len = 0;
			wg_dpd_init(&c->dpd, w->config.dpd_interval_s,
			            w->config.dpd_max_retries);
			(void)wg_compress_init(&c->compress, WG_COMPRESS_NONE);
			w->conn_count++;
			return (int64_t)c->conn_id;
		}
	}

	return -ENOSPC;
}

int wg_worker_remove_connection(wg_worker_t *w, uint64_t conn_id)
{
	for (uint32_t i = 0; i < w->config.max_connections; i++) {
		if (w->conns[i].active && w->conns[i].conn_id == conn_id) {
			wg_compress_destroy(&w->conns[i].compress);
			explicit_bzero(&w->conns[i], sizeof(w->conns[i]));
			w->conn_count--;
			return 0;
		}
	}
	return -ENOENT;
}

wg_connection_t *wg_worker_find_connection(wg_worker_t *w, uint64_t conn_id)
{
	for (uint32_t i = 0; i < w->config.max_connections; i++) {
		if (w->conns[i].active && w->conns[i].conn_id == conn_id)
			return &w->conns[i];
	}
	return nullptr;
}

uint32_t wg_worker_connection_count(const wg_worker_t *w)
{
	return w->conn_count;
}

const char *wg_worker_state_name(wg_worker_state_t state)
{
	switch (state) {
	case WG_WORKER_NEW:      return "NEW";
	case WG_WORKER_READY:    return "READY";
	case WG_WORKER_RUNNING:  return "RUNNING";
	case WG_WORKER_STOPPING: return "STOPPING";
	case WG_WORKER_STOPPED:  return "STOPPED";
	}
	return "UNKNOWN";
}
