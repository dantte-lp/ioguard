#ifndef IOGUARD_CORE_SECURITY_HOOKS_H
#define IOGUARD_CORE_SECURITY_HOOKS_H

#include "config/config.h"
#include "security/firewall.h"
#include "security/landlock.h"
#include "security/sandbox.h"

#include <netinet/in.h>
#include <stdint.h>

/**
 * @brief Select sandbox profile for a process role.
 *
 * @param is_worker  true for worker, false for auth-mod.
 * @return Appropriate sandbox profile enum.
 */
[[nodiscard]] iog_sandbox_profile_t iog_security_select_sandbox(bool is_worker);

/**
 * @brief Select landlock profile for a process role.
 *
 * @param is_worker  true for worker, false for auth-mod.
 * @return Appropriate landlock profile enum.
 */
[[nodiscard]] iog_landlock_profile_t iog_security_select_landlock(bool is_worker);

/**
 * @brief Apply process-level security restrictions.
 *
 * Called immediately after fork(), before any I/O.
 * Applies seccomp and/or landlock based on config flags.
 *
 * @param is_worker  true for worker process, false for auth-mod.
 * @param config     Server configuration.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_security_apply_process(bool is_worker, const iog_config_t *config);

/**
 * @brief Build firewall session descriptor for per-user rules.
 *
 * @param session  Output session descriptor.
 * @param username Username string.
 * @param af       Address family (AF_INET or AF_INET6).
 * @param ip       Assigned IP (network byte order for IPv4).
 * @return 0 on success, -EINVAL on bad params.
 */
[[nodiscard]] int iog_security_build_fw_session(iog_fw_session_t *session, const char *username,
                                               int af, uint32_t ip);

/**
 * @brief Create per-session firewall rules after auth success.
 *
 * @param username  Authenticated username.
 * @param af        Address family (AF_INET or AF_INET6).
 * @param ip        Assigned IP address.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_security_session_create(const char *username, int af, uint32_t ip);

/**
 * @brief Remove per-session firewall rules on disconnect.
 *
 * @param username  Username for chain identification.
 * @param af        Address family.
 * @param ip        Previously assigned IP address.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int iog_security_session_destroy(const char *username, int af, uint32_t ip);

#endif /* IOGUARD_CORE_SECURITY_HOOKS_H */
