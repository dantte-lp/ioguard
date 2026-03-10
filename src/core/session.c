#include "core/session.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_WOLFSSL
#    include <wolfssl/options.h>
#    include <wolfssl/wolfcrypt/random.h>
#else
#    include <fcntl.h>
#    include <unistd.h>
#endif

struct iog_session_store {
    iog_session_t *sessions;
    uint32_t max_sessions;
    uint32_t count;
#ifdef USE_WOLFSSL
    WC_RNG rng;
#endif
};

static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t result = 0;

    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 0 : -1;
}

#ifndef USE_WOLFSSL
static int fill_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
        return -errno;
    }

    ssize_t n = read(fd, buf, len);

    close(fd);
    return (n == (ssize_t)len) ? 0 : -EIO;
}
#endif

static int generate_cookie(iog_session_store_t *store, uint8_t *buf, size_t len)
{
#ifdef USE_WOLFSSL
    int ret = wc_RNG_GenerateBlock(&store->rng, buf, (word32)len);

    return (ret == 0) ? 0 : -EIO;
#else
    (void)store;
    return fill_random(buf, len);
#endif
}

iog_session_store_t *iog_session_store_create(uint32_t max_sessions)
{
    if (max_sessions == 0) {
        return nullptr;
    }

    iog_session_store_t *store = calloc(1, sizeof(*store));

    if (store == nullptr) {
        return nullptr;
    }

    store->sessions = calloc(max_sessions, sizeof(*store->sessions));
    if (store->sessions == nullptr) {
        free(store);
        return nullptr;
    }

    store->max_sessions = max_sessions;
    store->count = 0;

#ifdef USE_WOLFSSL
    if (wc_InitRng(&store->rng) != 0) {
        free(store->sessions);
        free(store);
        return nullptr;
    }
#endif

    return store;
}

void iog_session_store_destroy(iog_session_store_t *store)
{
    if (store == nullptr) {
        return;
    }

    if (store->sessions != nullptr) {
        for (uint32_t i = 0; i < store->max_sessions; i++) {
            if (store->sessions[i].active) {
                explicit_bzero(&store->sessions[i], sizeof(store->sessions[i]));
            }
        }
        free(store->sessions);
    }

#ifdef USE_WOLFSSL
    wc_FreeRng(&store->rng);
#endif

    free(store);
}

int iog_session_create(iog_session_store_t *store, const char *username, const char *group,
                      uint32_t ttl_seconds, iog_session_t **out)
{
    if (store == nullptr || username == nullptr || out == nullptr) {
        return -EINVAL;
    }

    if (store->count >= store->max_sessions) {
        return -EAGAIN;
    }

    /* Find an inactive slot */
    iog_session_t *slot = nullptr;

    for (uint32_t i = 0; i < store->max_sessions; i++) {
        if (!store->sessions[i].active) {
            slot = &store->sessions[i];
            break;
        }
    }

    if (slot == nullptr) {
        return -EAGAIN;
    }

    /* Generate random cookie */
    int ret = generate_cookie(store, slot->cookie, IOG_SESSION_COOKIE_SIZE);

    if (ret != 0) {
        return ret;
    }

    /* Copy username */
    size_t ulen = strnlen(username, sizeof(slot->username) - 1);

    memcpy(slot->username, username, ulen);
    slot->username[ulen] = '\0';

    /* Copy group (may be null) */
    if (group != nullptr) {
        size_t glen = strnlen(group, sizeof(slot->group) - 1);

        memcpy(slot->group, group, glen);
        slot->group[glen] = '\0';
    } else {
        slot->group[0] = '\0';
    }

    slot->assigned_ip[0] = '\0';
    slot->dns_server[0] = '\0';
    slot->created = time(nullptr);
    slot->last_activity = slot->created;
    slot->ttl_seconds = ttl_seconds;
    slot->active = true;

    store->count++;
    *out = slot;
    return 0;
}

int iog_session_validate(iog_session_store_t *store, const uint8_t *cookie, size_t cookie_len,
                        iog_session_t **out)
{
    if (store == nullptr || cookie == nullptr || out == nullptr) {
        return -EINVAL;
    }

    if (cookie_len != IOG_SESSION_COOKIE_SIZE) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < store->max_sessions; i++) {
        if (!store->sessions[i].active) {
            continue;
        }

        if (constant_time_compare(store->sessions[i].cookie, cookie, IOG_SESSION_COOKIE_SIZE) == 0) {
            /* Check expiry */
            time_t now = time(nullptr);

            if ((uint32_t)(now - store->sessions[i].created) > store->sessions[i].ttl_seconds) {
                /* Session expired — clean it up */
                explicit_bzero(store->sessions[i].cookie, IOG_SESSION_COOKIE_SIZE);
                explicit_bzero(&store->sessions[i], sizeof(store->sessions[i]));
                store->count--;
                return -ETIMEDOUT;
            }

            store->sessions[i].last_activity = now;
            *out = &store->sessions[i];
            return 0;
        }
    }

    return -ENOENT;
}

int iog_session_delete(iog_session_store_t *store, const uint8_t *cookie, size_t cookie_len)
{
    if (store == nullptr || cookie == nullptr) {
        return -EINVAL;
    }

    if (cookie_len != IOG_SESSION_COOKIE_SIZE) {
        return -EINVAL;
    }

    for (uint32_t i = 0; i < store->max_sessions; i++) {
        if (!store->sessions[i].active) {
            continue;
        }

        if (constant_time_compare(store->sessions[i].cookie, cookie, IOG_SESSION_COOKIE_SIZE) == 0) {
            explicit_bzero(store->sessions[i].cookie, IOG_SESSION_COOKIE_SIZE);
            explicit_bzero(&store->sessions[i], sizeof(store->sessions[i]));
            store->count--;
            return 0;
        }
    }

    return -ENOENT;
}

uint32_t iog_session_cleanup_expired(iog_session_store_t *store)
{
    if (store == nullptr) {
        return 0;
    }

    uint32_t cleaned = 0;
    time_t now = time(nullptr);

    for (uint32_t i = 0; i < store->max_sessions; i++) {
        if (!store->sessions[i].active) {
            continue;
        }

        if ((uint32_t)(now - store->sessions[i].created) > store->sessions[i].ttl_seconds) {
            explicit_bzero(store->sessions[i].cookie, IOG_SESSION_COOKIE_SIZE);
            explicit_bzero(&store->sessions[i], sizeof(store->sessions[i]));
            store->count--;
            cleaned++;
        }
    }

    return cleaned;
}

uint32_t iog_session_count(const iog_session_store_t *store)
{
    if (store == nullptr) {
        return 0;
    }

    return store->count;
}
