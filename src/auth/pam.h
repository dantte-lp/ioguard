#ifndef IOGUARD_AUTH_PAM_H
#define IOGUARD_AUTH_PAM_H

#include <stddef.h>

constexpr size_t IOG_PAM_MAX_SERVICE = 64;

typedef enum {
    IOG_AUTH_SUCCESS = 0,
    IOG_AUTH_FAILURE = -1,
    IOG_AUTH_ERROR = -2,
    IOG_AUTH_ACCOUNT_EXPIRED = -3,
    IOG_AUTH_PASSWORD_EXPIRED = -4,
} iog_auth_result_t;

typedef struct {
    char service[IOG_PAM_MAX_SERVICE];
} iog_pam_config_t;

[[nodiscard]] int iog_pam_init(iog_pam_config_t *cfg, const char *service);

[[nodiscard]] iog_auth_result_t iog_pam_authenticate(const iog_pam_config_t *cfg, const char *username,
                                                   const char *password);

#endif /* IOGUARD_AUTH_PAM_H */
