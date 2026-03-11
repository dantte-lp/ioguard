#include "core/worker.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct iog_worker {
    iog_worker_config_t config;
    iog_worker_state_t state;
    iog_connection_t *conns;
    uint32_t conn_count;
    uint64_t next_conn_id;
};

void iog_worker_config_init(iog_worker_config_t *cfg)
{
    *cfg = (iog_worker_config_t){
        .max_connections = IOG_WORKER_DEFAULT_MAX_CONNS,
        .queue_depth = IOG_WORKER_DEFAULT_QUEUE_DEPTH,
        .dpd_interval_s = IOG_DPD_DEFAULT_INTERVAL_S,
        .dpd_max_retries = IOG_DPD_DEFAULT_MAX_RETRIES,
        .tun_mtu = IOG_WORKER_DEFAULT_TUN_MTU,
    };
}

int iog_worker_config_validate(const iog_worker_config_t *cfg)
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

iog_worker_t *iog_worker_create(const iog_worker_config_t *cfg)
{
    if (iog_worker_config_validate(cfg) != 0) {
        return nullptr;
    }

    iog_worker_t *w = calloc(1, sizeof(*w));
    if (!w) {
        return nullptr;
    }

    w->conns = calloc(cfg->max_connections, sizeof(*w->conns));
    if (!w->conns) {
        free(w);
        return nullptr;
    }

    w->config = *cfg;
    w->state = IOG_WORKER_NEW;
    w->conn_count = 0;
    w->next_conn_id = 1;

    return w;
}

void iog_worker_destroy(iog_worker_t *w)
{
    if (!w) {
        return;
    }
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (w->conns[i].active) {
            iog_compress_destroy(&w->conns[i].compress);
        }
    }
    explicit_bzero(w->conns, w->config.max_connections * sizeof(*w->conns));
    free(w->conns);
    explicit_bzero(w, sizeof(*w));
    free(w);
}

iog_worker_state_t iog_worker_state(const iog_worker_t *w)
{
    return w->state;
}

int64_t iog_worker_add_connection(iog_worker_t *w, int tls_fd, int tun_fd)
{
    if (w->conn_count >= w->config.max_connections) {
        return -ENOSPC;
    }

    /* Find first inactive slot */
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (!w->conns[i].active) {
            iog_connection_t *c = &w->conns[i];
            memset(c, 0, sizeof(*c));
            c->conn_id = w->next_conn_id++;
            c->tls_fd = tls_fd;
            c->tun_fd = tun_fd;
            c->active = true;
            c->recv_len = 0;
            iog_dpd_init(&c->dpd, w->config.dpd_interval_s, w->config.dpd_max_retries);
            (void)iog_compress_init(&c->compress, IOG_COMPRESS_NONE);
            w->conn_count++;
            return (int64_t)c->conn_id;
        }
    }

    return -ENOSPC;
}

int iog_worker_remove_connection(iog_worker_t *w, uint64_t conn_id)
{
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (w->conns[i].active && w->conns[i].conn_id == conn_id) {
            iog_compress_destroy(&w->conns[i].compress);
            explicit_bzero(&w->conns[i], sizeof(w->conns[i]));
            w->conn_count--;
            return 0;
        }
    }
    return -ENOENT;
}

iog_connection_t *iog_worker_find_connection(iog_worker_t *w, uint64_t conn_id)
{
    for (uint32_t i = 0; i < w->config.max_connections; i++) {
        if (w->conns[i].active && w->conns[i].conn_id == conn_id) {
            return &w->conns[i];
        }
    }
    return nullptr;
}

uint32_t iog_worker_connection_count(const iog_worker_t *w)
{
    return w->conn_count;
}

uint32_t iog_worker_max_connections(const iog_worker_t *w)
{
    return w->config.max_connections;
}

iog_connection_t *iog_worker_connection_at(iog_worker_t *w, uint32_t idx)
{
    if (idx >= w->config.max_connections) {
        return nullptr;
    }
    if (!w->conns[idx].active) {
        return nullptr;
    }
    return &w->conns[idx];
}

const char *iog_worker_state_name(iog_worker_state_t state)
{
    switch (state) {
    case IOG_WORKER_NEW:
        return "NEW";
    case IOG_WORKER_READY:
        return "READY";
    case IOG_WORKER_RUNNING:
        return "RUNNING";
    case IOG_WORKER_STOPPING:
        return "STOPPING";
    case IOG_WORKER_STOPPED:
        return "STOPPED";
    }
    return "UNKNOWN";
}
