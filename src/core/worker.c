#include "core/worker.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct rw_worker {
    rw_worker_config_t config;
    rw_worker_state_t state;
    rw_connection_t *conns;
    uint32_t conn_count;
    uint64_t next_conn_id;
};

void rw_worker_config_init(rw_worker_config_t *cfg)
{
    *cfg = (rw_worker_config_t){
        .max_connections = RW_WORKER_DEFAULT_MAX_CONNS,
        .queue_depth = RW_WORKER_DEFAULT_QUEUE_DEPTH,
        .dpd_interval_s = RW_DPD_DEFAULT_INTERVAL_S,
        .dpd_max_retries = RW_DPD_DEFAULT_MAX_RETRIES,
        .tun_mtu = RW_WORKER_DEFAULT_TUN_MTU,
    };
}

int rw_worker_config_validate(const rw_worker_config_t *cfg)
{
    if (cfg->max_connections == 0) {
        return -EINVAL;
    }
    if (cfg->queue_depth == 0) {
        return -EINVAL;
    }
    if (cfg->tun_mtu == 0) {
        return -EINVAL;
    }
    return 0;
}

rw_worker_t *rw_worker_create(const rw_worker_config_t *cfg)
{
    if (rw_worker_config_validate(cfg) != 0) {
        return nullptr;
    }

    rw_worker_t *w = calloc(1, sizeof(*w));
    if (!w) {
        return nullptr;
    }

    w->conns = calloc(cfg->max_connections, sizeof(*w->conns));
    if (!w->conns) {
        free(w);
        return nullptr;
    }

    w->config = *cfg;
    w->state = RW_WORKER_NEW;
    w->conn_count = 0;
    w->next_conn_id = 1;

    return w;
}

void rw_worker_destroy(rw_worker_t *w)
{
    if (!w) {
        return;
    }
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (w->conns[i].active) {
            rw_compress_destroy(&w->conns[i].compress);
        }
    }
    explicit_bzero(w->conns, w->config.max_connections * sizeof(*w->conns));
    free(w->conns);
    explicit_bzero(w, sizeof(*w));
    free(w);
}

rw_worker_state_t rw_worker_state(const rw_worker_t *w)
{
    return w->state;
}

int64_t rw_worker_add_connection(rw_worker_t *w, int tls_fd, int tun_fd)
{
    if (w->conn_count >= w->config.max_connections) {
        return -ENOSPC;
    }

    /* Find first inactive slot */
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (!w->conns[i].active) {
            rw_connection_t *c = &w->conns[i];
            memset(c, 0, sizeof(*c));
            c->conn_id = w->next_conn_id++;
            c->tls_fd = tls_fd;
            c->tun_fd = tun_fd;
            c->active = true;
            c->recv_len = 0;
            rw_dpd_init(&c->dpd, w->config.dpd_interval_s, w->config.dpd_max_retries);
            (void)rw_compress_init(&c->compress, RW_COMPRESS_NONE);
            w->conn_count++;
            return (int64_t)c->conn_id;
        }
    }

    return -ENOSPC;
}

int rw_worker_remove_connection(rw_worker_t *w, uint64_t conn_id)
{
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (w->conns[i].active && w->conns[i].conn_id == conn_id) {
            rw_compress_destroy(&w->conns[i].compress);
            explicit_bzero(&w->conns[i], sizeof(w->conns[i]));
            w->conn_count--;
            return 0;
        }
    }
    return -ENOENT;
}

rw_connection_t *rw_worker_find_connection(rw_worker_t *w, uint64_t conn_id)
{
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (w->conns[i].active && w->conns[i].conn_id == conn_id) {
            return &w->conns[i];
        }
    }
    return nullptr;
}

uint32_t rw_worker_connection_count(const rw_worker_t *w)
{
    return w->conn_count;
}

uint32_t rw_worker_max_connections(const rw_worker_t *w)
{
    return w->config.max_connections;
}

rw_connection_t *rw_worker_connection_at(rw_worker_t *w, uint32_t idx)
{
    if (idx >= w->config.max_connections) {
        return nullptr;
    }
    if (!w->conns[idx].active) {
        return nullptr;
    }
    return &w->conns[idx];
}

const char *rw_worker_state_name(rw_worker_state_t state)
{
    switch (state) {
    case RW_WORKER_NEW:
        return "NEW";
    case RW_WORKER_READY:
        return "READY";
    case RW_WORKER_RUNNING:
        return "RUNNING";
    case RW_WORKER_STOPPING:
        return "STOPPING";
    case RW_WORKER_STOPPED:
        return "STOPPED";
    }
    return "UNKNOWN";
}
