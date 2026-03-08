/**
 * @file sandbox.c
 * @brief seccomp BPF sandbox implementation using libseccomp.
 */

#include "security/sandbox.h"

#include <errno.h>
#include <seccomp.h>
#include <stddef.h>

/* Syscall table for each profile tier.
 * Each higher tier is a strict superset of the previous one. */

/** Worker syscalls — most restrictive baseline. */
static const int worker_syscalls[] = {
	SCMP_SYS(read),
	SCMP_SYS(write),
	SCMP_SYS(readv),
	SCMP_SYS(writev),
	SCMP_SYS(mmap),
	SCMP_SYS(munmap),
	SCMP_SYS(madvise),
	SCMP_SYS(mprotect),
	SCMP_SYS(brk),
	SCMP_SYS(close),
	SCMP_SYS(futex),
	SCMP_SYS(io_uring_enter),
	SCMP_SYS(io_uring_setup),
	SCMP_SYS(io_uring_register),
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(epoll_wait),
	SCMP_SYS(exit_group),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(getrandom),
	SCMP_SYS(mremap),
	SCMP_SYS(msync),
	SCMP_SYS(lseek),
	SCMP_SYS(newfstatat),
	SCMP_SYS(openat),
	SCMP_SYS(fcntl),
};

/** Auth-mod extra syscalls (on top of worker). */
static const int authmod_extra_syscalls[] = {
	SCMP_SYS(flock),
	SCMP_SYS(pread64),
	SCMP_SYS(pwrite64),
	SCMP_SYS(fdatasync),
	SCMP_SYS(socket),
	SCMP_SYS(sendmsg),
	SCMP_SYS(recvmsg),
	SCMP_SYS(connect),
	SCMP_SYS(getpid),
	SCMP_SYS(gettid),
	SCMP_SYS(tgkill),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(pipe2),
};

/** Main process extra syscalls (on top of auth-mod). */
static const int main_extra_syscalls[] = {
	SCMP_SYS(bind),
	SCMP_SYS(listen),
	SCMP_SYS(accept4),
	SCMP_SYS(pidfd_open),
	SCMP_SYS(pidfd_send_signal),
	SCMP_SYS(clone3),
	SCMP_SYS(waitid),
	SCMP_SYS(signalfd4),
	SCMP_SYS(setsockopt),
	SCMP_SYS(getsockopt),
	SCMP_SYS(ioctl),
	SCMP_SYS(dup2),
	SCMP_SYS(dup3),
	SCMP_SYS(chdir),
	SCMP_SYS(umask),
};

#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((a)[0])))

/**
 * Add an array of syscalls to a seccomp context.
 * Returns 0 on success, negative errno on failure.
 */
static int add_syscalls(scmp_filter_ctx ctx, const int *syscalls, int count)
{
	for (int i = 0; i < count; i++) {
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0);
		if (rc < 0)
			return rc;
	}
	return 0;
}

/**
 * Build a seccomp filter context for the given profile.
 * Caller must release with seccomp_release().
 * On success, *out_count receives the total number of allowed syscalls.
 */
static int build_filter(rw_sandbox_profile_t profile, scmp_filter_ctx *out_ctx,
			int *out_count)
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (ctx == nullptr)
		return -ENOMEM;

	int total = 0;
	int rc;

	/* Worker base set — always included. */
	rc = add_syscalls(ctx, worker_syscalls, ARRAY_LEN(worker_syscalls));
	if (rc < 0)
		goto fail;
	total += ARRAY_LEN(worker_syscalls);

	if (profile >= RW_SANDBOX_AUTHMOD) {
		rc = add_syscalls(ctx, authmod_extra_syscalls,
				  ARRAY_LEN(authmod_extra_syscalls));
		if (rc < 0)
			goto fail;
		total += ARRAY_LEN(authmod_extra_syscalls);
	}

	if (profile >= RW_SANDBOX_MAIN) {
		rc = add_syscalls(ctx, main_extra_syscalls,
				  ARRAY_LEN(main_extra_syscalls));
		if (rc < 0)
			goto fail;
		total += ARRAY_LEN(main_extra_syscalls);
	}

	*out_ctx = ctx;
	if (out_count != nullptr)
		*out_count = total;
	return 0;

fail:
	seccomp_release(ctx);
	return rc;
}

int rw_sandbox_build(rw_sandbox_profile_t profile, int *out_count)
{
	if (out_count == nullptr)
		return -EINVAL;

	scmp_filter_ctx ctx = nullptr;
	int rc = build_filter(profile, &ctx, out_count);
	if (rc == 0)
		seccomp_release(ctx);
	return rc;
}

int rw_sandbox_apply(rw_sandbox_profile_t profile)
{
	scmp_filter_ctx ctx = nullptr;
	int rc = build_filter(profile, &ctx, nullptr);
	if (rc < 0)
		return rc;

	rc = seccomp_load(ctx);
	seccomp_release(ctx);
	return rc;
}
