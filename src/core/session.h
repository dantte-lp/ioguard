#ifndef WOLFGUARD_CORE_SESSION_H
#define WOLFGUARD_CORE_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

constexpr size_t WG_SESSION_COOKIE_SIZE = 32;
constexpr uint32_t WG_SESSION_MAX_SESSIONS = 1024;

typedef struct {
    uint8_t cookie[WG_SESSION_COOKIE_SIZE];
    char username[256];
    char group[256];
    char assigned_ip[46];     /* INET6_ADDRSTRLEN */
    char dns_server[46];
    time_t created;
    time_t last_activity;
    uint32_t ttl_seconds;
    bool active;
} wg_session_t;

typedef struct wg_session_store wg_session_store_t;  /* opaque */

[[nodiscard]] wg_session_store_t *wg_session_store_create(uint32_t max_sessions);
void wg_session_store_destroy(wg_session_store_t *store);

[[nodiscard]] int wg_session_create(wg_session_store_t *store,
                                     const char *username,
                                     const char *group,
                                     uint32_t ttl_seconds,
                                     wg_session_t **out);

[[nodiscard]] int wg_session_validate(wg_session_store_t *store,
                                       const uint8_t *cookie, size_t cookie_len,
                                       wg_session_t **out);

int wg_session_delete(wg_session_store_t *store,
                       const uint8_t *cookie, size_t cookie_len);

uint32_t wg_session_cleanup_expired(wg_session_store_t *store);

uint32_t wg_session_count(const wg_session_store_t *store);

#endif /* WOLFGUARD_CORE_SESSION_H */
