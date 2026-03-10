#ifndef RINGWALL_CORE_SESSION_H
#define RINGWALL_CORE_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

constexpr size_t RW_SESSION_COOKIE_SIZE = 32;
constexpr uint32_t RW_SESSION_MAX_SESSIONS = 1024;

typedef struct {
    uint8_t cookie[RW_SESSION_COOKIE_SIZE];
    char username[256];
    char group[256];
    char assigned_ip[46]; /* INET6_ADDRSTRLEN */
    char dns_server[46];
    time_t created;
    time_t last_activity;
    uint32_t ttl_seconds;
    bool active;
} rw_session_t;

typedef struct rw_session_store rw_session_store_t; /* opaque */

[[nodiscard]] rw_session_store_t *rw_session_store_create(uint32_t max_sessions);
void rw_session_store_destroy(rw_session_store_t *store);

[[nodiscard]] int rw_session_create(rw_session_store_t *store, const char *username,
                                    const char *group, uint32_t ttl_seconds, rw_session_t **out);

[[nodiscard]] int rw_session_validate(rw_session_store_t *store, const uint8_t *cookie,
                                      size_t cookie_len, rw_session_t **out);

[[nodiscard]] int rw_session_delete(rw_session_store_t *store, const uint8_t *cookie,
                                    size_t cookie_len);

uint32_t rw_session_cleanup_expired(rw_session_store_t *store);

uint32_t rw_session_count(const rw_session_store_t *store);

#endif /* RINGWALL_CORE_SESSION_H */
