#ifndef IOGUARD_CORE_SESSION_H
#define IOGUARD_CORE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

constexpr size_t IOG_SESSION_COOKIE_SIZE = 32;
constexpr uint32_t IOG_SESSION_MAX_SESSIONS = 1024;

typedef struct {
    uint8_t cookie[IOG_SESSION_COOKIE_SIZE];
    char username[256];
    char group[256];
    char assigned_ip[46]; /* INET6_ADDRSTRLEN */
    char dns_server[46];
    time_t created;
    time_t last_activity;
    uint32_t ttl_seconds;
    bool active;
} iog_session_t;

typedef struct iog_session_store iog_session_store_t; /* opaque */

[[nodiscard]] iog_session_store_t *iog_session_store_create(uint32_t max_sessions);
void iog_session_store_destroy(iog_session_store_t *store);

[[nodiscard]] int iog_session_create(iog_session_store_t *store, const char *username,
                                    const char *group, uint32_t ttl_seconds, iog_session_t **out);

[[nodiscard]] int iog_session_validate(iog_session_store_t *store, const uint8_t *cookie,
                                      size_t cookie_len, iog_session_t **out);

[[nodiscard]] int iog_session_delete(iog_session_store_t *store, const uint8_t *cookie,
                                    size_t cookie_len);

uint32_t iog_session_cleanup_expired(iog_session_store_t *store);

uint32_t iog_session_count(const iog_session_store_t *store);

#endif /* IOGUARD_CORE_SESSION_H */
