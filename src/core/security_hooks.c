#include "core/security_hooks.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

iog_sandbox_profile_t iog_security_select_sandbox(bool is_worker)
{
    return is_worker ? IOG_SANDBOX_WORKER : IOG_SANDBOX_AUTHMOD;
}

iog_landlock_profile_t iog_security_select_landlock(bool is_worker)
{
    return is_worker ? IOG_LANDLOCK_WORKER : IOG_LANDLOCK_AUTHMOD;
}

int iog_security_apply_process(bool is_worker, const iog_config_t *config)
{
    if (config == nullptr) {
        return -EINVAL;
    }

    int ret = 0;

    /* Apply seccomp BPF sandbox if enabled */
    if (config->security.seccomp) {
        iog_sandbox_profile_t profile = iog_security_select_sandbox(is_worker);
        ret = iog_sandbox_apply(profile);
        if (ret < 0) {
            return ret;
        }
    }

    /* Apply landlock filesystem isolation if enabled and supported */
    if (config->security.landlock && iog_landlock_supported()) {
        iog_landlock_profile_t lprofile = iog_security_select_landlock(is_worker);
        ret = iog_landlock_apply(lprofile, config->storage.mdbx_path, config->storage.sqlite_path);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

int iog_security_build_fw_session(iog_fw_session_t *session, const char *username, int af,
                                  uint32_t ip)
{
    if (session == nullptr || username == nullptr) {
        return -EINVAL;
    }
    if (af != AF_INET && af != AF_INET6) {
        return -EINVAL;
    }

    memset(session, 0, sizeof(*session));
    session->af = af;
    session->assigned_ipv4 = ip;
    snprintf(session->username, sizeof(session->username), "%s", username);

    /* Build chain name from session */
    int ret = iog_fw_chain_name(session, session->chain_name, sizeof(session->chain_name));
    if (ret < 0) {
        return ret;
    }

    return 0;
}

int iog_security_session_create(const char *username, int af, uint32_t ip)
{
    iog_fw_session_t session;
    int ret = iog_security_build_fw_session(&session, username, af, ip);
    if (ret < 0) {
        return ret;
    }

    return iog_fw_session_create(&session);
}

int iog_security_session_destroy(const char *username, int af, uint32_t ip)
{
    iog_fw_session_t session;
    int ret = iog_security_build_fw_session(&session, username, af, ip);
    if (ret < 0) {
        return ret;
    }

    return iog_fw_session_destroy(&session);
}
