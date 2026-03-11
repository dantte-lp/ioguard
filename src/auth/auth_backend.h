#ifndef RINGWALL_AUTH_BACKEND_H
#define RINGWALL_AUTH_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Maximum number of registered authentication backends. */
constexpr int RW_AUTH_BACKEND_MAX = 16;

/** Authentication status codes returned by backends. */
typedef enum {
    IOG_AUTH_STATUS_SUCCESS = 0,
    IOG_AUTH_STATUS_FAILURE = -1,
    IOG_AUTH_STATUS_ERROR = -2,
    IOG_AUTH_STATUS_ACCOUNT_EXPIRED = -3,
    IOG_AUTH_STATUS_PASSWORD_EXPIRED = -4,
} iog_auth_status_t;

/** Authentication request passed to a backend. */
typedef struct {
    const char *username;
    const char *password;        /* nullptr for cert auth */
    const char *otp;             /* nullptr if no MFA */
    const uint8_t *client_cert;  /* DER-encoded cert, nullptr if N/A */
    size_t client_cert_len;
    const char *source_ip;
    uint16_t source_port;
} iog_auth_request_t;

/** Authentication response populated by a backend. */
typedef struct {
    iog_auth_status_t status;
    char groups[256];            /* comma-separated group list */
    uint32_t framed_ip;          /* RADIUS Framed-IP-Address, 0 if N/A */
    uint8_t framed_ipv6[16];    /* RADIUS Framed-IPv6-Address */
    bool has_framed_ipv6;
} iog_auth_response_t;

/** Pluggable authentication backend interface. */
typedef struct iog_auth_backend {
    const char *name;
    int (*init)(const void *config);
    iog_auth_status_t (*authenticate)(const iog_auth_request_t *req,
                                     iog_auth_response_t *resp);
    void (*destroy)(void);
} iog_auth_backend_t;

/**
 * Register an authentication backend.
 *
 * @param backend  Pointer to the backend descriptor (must remain valid).
 * @return 0 on success, -EINVAL if backend or backend->name is null,
 *         -EEXIST if a backend with the same name is already registered,
 *         -ENOSPC if the registry is full.
 */
[[nodiscard]] int iog_auth_backend_register(const iog_auth_backend_t *backend);

/**
 * Find a registered backend by name.
 *
 * @param name  Backend name to search for.
 * @return Pointer to the backend, or nullptr if not found.
 */
const iog_auth_backend_t *iog_auth_backend_find(const char *name);

/**
 * List all registered backends.
 *
 * @param count  Output: number of registered backends.
 * @return Pointer to the internal array of backend pointers.
 */
const iog_auth_backend_t *const *iog_auth_backend_list(int *count);

/**
 * Destroy all registered backends and clear the registry.
 *
 * Calls destroy() on each backend that has a non-null destroy callback.
 */
void iog_auth_backend_cleanup(void);

#endif /* RINGWALL_AUTH_BACKEND_H */
