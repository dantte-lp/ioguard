#include "auth/pam.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <security/pam_appl.h>

/**
 * PAM conversation callback. Only handles PAM_PROMPT_ECHO_OFF (password).
 */
static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr)
{
    if (num_msg <= 0 || msg == nullptr || resp == nullptr) {
        return PAM_CONV_ERR;
    }

    struct pam_response *reply = calloc((size_t)num_msg, sizeof(*reply));
    if (reply == nullptr) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            reply[i].resp = strdup((const char *)appdata_ptr);
            if (reply[i].resp == nullptr) {
                /* Clean up already-allocated responses */
                for (int j = 0; j < i; j++) {
                    free(reply[j].resp);
                }
                free(reply);
                return PAM_BUF_ERR;
            }
            reply[i].resp_retcode = 0;
        } else {
            /* We only handle password prompts */
            for (int j = 0; j <= i; j++) {
                free(reply[j].resp);
            }
            free(reply);
            return PAM_CONV_ERR;
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

int wg_pam_init(wg_pam_config_t *cfg, const char *service)
{
    if (cfg == nullptr) {
        return -EINVAL;
    }

    memset(cfg, 0, sizeof(*cfg));

    const char *svc = (service != nullptr) ? service : "wolfguard";
    int ret = snprintf(cfg->service, sizeof(cfg->service), "%s", svc);
    if (ret < 0 || (size_t)ret >= sizeof(cfg->service)) {
        return -ENAMETOOLONG;
    }

    return 0;
}

wg_auth_result_t wg_pam_authenticate(const wg_pam_config_t *cfg,
                                     const char *username,
                                     const char *password)
{
    if (cfg == nullptr || username == nullptr || password == nullptr) {
        return WG_AUTH_ERROR;
    }

    /* Make a mutable copy of the password for the conversation function */
    char *pw_copy = strdup(password);
    if (pw_copy == nullptr) {
        return WG_AUTH_ERROR;
    }

    struct pam_conv conv = {
        .conv = pam_conversation,
        .appdata_ptr = pw_copy,
    };

    pam_handle_t *pamh = nullptr;
    int ret = pam_start(cfg->service, username, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        explicit_bzero(pw_copy, strlen(pw_copy));
        free(pw_copy);
        return WG_AUTH_ERROR;
    }

    ret = pam_authenticate(pamh, 0);

    wg_auth_result_t result;
    if (ret == PAM_SUCCESS) {
        /* Authentication passed; check account status */
        ret = pam_acct_mgmt(pamh, 0);
    }

    /* Map PAM return codes to our result type */
    switch (ret) {
    case PAM_SUCCESS:
        result = WG_AUTH_SUCCESS;
        break;
    case PAM_AUTH_ERR:
    case PAM_USER_UNKNOWN:
    case PAM_MAXTRIES:
        result = WG_AUTH_FAILURE;
        break;
    case PAM_ACCT_EXPIRED:
        result = WG_AUTH_ACCOUNT_EXPIRED;
        break;
    case PAM_NEW_AUTHTOK_REQD:
        result = WG_AUTH_PASSWORD_EXPIRED;
        break;
    default:
        result = WG_AUTH_ERROR;
        break;
    }

    pam_end(pamh, ret);

    /* Zero password copy before freeing */
    explicit_bzero(pw_copy, strlen(pw_copy));
    free(pw_copy);

    return result;
}
