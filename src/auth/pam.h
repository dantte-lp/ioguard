#ifndef RINGWALL_AUTH_PAM_H
#define RINGWALL_AUTH_PAM_H

#include <stdbool.h>
#include <stddef.h>

constexpr size_t RW_PAM_MAX_SERVICE = 64;

typedef enum {
    RW_AUTH_SUCCESS = 0,
    RW_AUTH_FAILURE = -1,
    RW_AUTH_ERROR = -2,
    RW_AUTH_ACCOUNT_EXPIRED = -3,
    RW_AUTH_PASSWORD_EXPIRED = -4,
} rw_auth_result_t;

typedef struct {
    char service[RW_PAM_MAX_SERVICE];
} rw_pam_config_t;

[[nodiscard]] int rw_pam_init(rw_pam_config_t *cfg, const char *service);

[[nodiscard]] rw_auth_result_t rw_pam_authenticate(const rw_pam_config_t *cfg,
                                                    const char *username,
                                                    const char *password);

#endif /* RINGWALL_AUTH_PAM_H */
