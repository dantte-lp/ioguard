/**
 * @file landlock.h
 * @brief Landlock filesystem isolation — worker and auth-mod profiles.
 *
 * Uses the kernel Landlock ABI (syscalls 444-446) to restrict filesystem
 * access per process.  No external library required.
 */

#ifndef RINGWALL_SECURITY_LANDLOCK_H
#define RINGWALL_SECURITY_LANDLOCK_H

#include <stdbool.h>
#include <stdint.h>

/** Landlock profile selecting which filesystem paths to allow. */
typedef enum : uint8_t {
	RW_LANDLOCK_WORKER,  /**< Read-only: mdbx file, /dev/net/tun */
	RW_LANDLOCK_AUTHMOD, /**< Read-write: mdbx + sqlite, read /dev/urandom */
} rw_landlock_profile_t;

/**
 * @brief Check whether the running kernel supports Landlock.
 * @return true if Landlock ABI v1+ is available.
 */
[[nodiscard]] bool rw_landlock_supported(void);

/**
 * @brief Build and apply a Landlock ruleset to the calling process.
 * @param profile     The Landlock profile to apply.
 * @param mdbx_path   Path to the mdbx data file (read-only for worker,
 *                     read-write for authmod).  Must not be nullptr.
 * @param sqlite_path Path to the sqlite database (authmod only, may be
 *                     nullptr for worker profile).
 * @return 0 on success, negative errno on failure (-ENOSYS if unsupported).
 *
 * After this call, filesystem access outside the allowed paths is denied
 * with EACCES.  This is irreversible for the calling process.
 */
[[nodiscard]] int rw_landlock_apply(rw_landlock_profile_t profile,
				    const char *mdbx_path,
				    const char *sqlite_path);

#endif /* RINGWALL_SECURITY_LANDLOCK_H */
