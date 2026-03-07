#ifndef WOLFGUARD_AUTH_PAM_H
#define WOLFGUARD_AUTH_PAM_H

#include <stdbool.h>
#include <stddef.h>

constexpr size_t WG_PAM_MAX_SERVICE = 64;

typedef enum {
    WG_AUTH_SUCCESS = 0,
    WG_AUTH_FAILURE = -1,
    WG_AUTH_ERROR = -2,
    WG_AUTH_ACCOUNT_EXPIRED = -3,
    WG_AUTH_PASSWORD_EXPIRED = -4,
} wg_auth_result_t;

typedef struct {
    char service[WG_PAM_MAX_SERVICE];
} wg_pam_config_t;

[[nodiscard]] int wg_pam_init(wg_pam_config_t *cfg, const char *service);

[[nodiscard]] wg_auth_result_t wg_pam_authenticate(const wg_pam_config_t *cfg,
                                                    const char *username,
                                                    const char *password);

#endif /* WOLFGUARD_AUTH_PAM_H */
