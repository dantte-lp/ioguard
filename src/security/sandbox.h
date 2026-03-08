/**
 * @file sandbox.h
 * @brief seccomp BPF sandbox — three profiles for worker, auth-mod, and main.
 *
 * Builds and applies seccomp-bpf filters using libseccomp with
 * SCMP_ACT_KILL_PROCESS as the default action.
 */

#ifndef RINGWALL_SECURITY_SANDBOX_H
#define RINGWALL_SECURITY_SANDBOX_H

#include <stdint.h>

/** Sandbox profile selecting which syscalls to allow. */
typedef enum : uint8_t {
	RW_SANDBOX_WORKER,  /**< Most restrictive: read, write, io_uring, mmap */
	RW_SANDBOX_AUTHMOD, /**< Worker + pwrite, fdatasync, flock, IPC sockets */
	RW_SANDBOX_MAIN,    /**< Authmod + socket, bind, listen, pidfd_spawn */
} rw_sandbox_profile_t;

/**
 * @brief Build a seccomp filter and return the count of allowed syscalls.
 * @param profile  The sandbox profile to build.
 * @param out_count  On success, receives the number of allowed syscalls.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_sandbox_build(rw_sandbox_profile_t profile,
				   int *out_count);

/**
 * @brief Build and apply a seccomp filter to the calling thread.
 * @param profile  The sandbox profile to apply.
 * @return 0 on success, negative errno on failure.
 *
 * After this call returns successfully the filter is active and
 * any disallowed syscall will kill the process (SCMP_ACT_KILL_PROCESS).
 */
[[nodiscard]] int rw_sandbox_apply(rw_sandbox_profile_t profile);

#endif /* RINGWALL_SECURITY_SANDBOX_H */
