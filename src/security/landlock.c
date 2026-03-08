/**
 * @file landlock.c
 * @brief Landlock filesystem isolation via raw syscalls.
 */

#include "security/landlock.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ---- Syscall wrappers ---- */

static inline int landlock_create_ruleset(
	const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags)
{
	return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int landlock_add_rule(int ruleset_fd,
				    enum landlock_rule_type rule_type,
				    const void *rule_attr, uint32_t flags)
{
	return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
			    rule_attr, flags);
}

static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
	return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* ---- Helpers ---- */

/** Access rights handled by all rulesets (ABI v1 baseline). */
static constexpr __u64 handled_fs =
	LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
	LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
	LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
	LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
	LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
	LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	LANDLOCK_ACCESS_FS_MAKE_SYM;

/**
 * Add a path-beneath rule to a Landlock ruleset.
 * Returns 0 on success, negative errno on failure.
 */
static int add_path_rule(int ruleset_fd, const char *path, __u64 access)
{
	int fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	struct landlock_path_beneath_attr rule = {
		.allowed_access = access,
		.parent_fd = fd,
	};

	int rc = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				   &rule, 0);
	int saved = errno;
	close(fd);

	if (rc < 0)
		return -saved;
	return 0;
}

/* ---- Public API ---- */

bool rw_landlock_supported(void)
{
	int abi = landlock_create_ruleset(nullptr, 0,
					  LANDLOCK_CREATE_RULESET_VERSION);
	return abi >= 1;
}

int rw_landlock_apply(rw_landlock_profile_t profile, const char *mdbx_path,
		      const char *sqlite_path)
{
	if (mdbx_path == nullptr)
		return -EINVAL;
	if (profile == RW_LANDLOCK_AUTHMOD && sqlite_path == nullptr)
		return -EINVAL;

	/* Check kernel support. */
	int abi = landlock_create_ruleset(nullptr, 0,
					  LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0)
		return -ENOSYS;

	/* Create ruleset with all FS rights handled. */
	struct landlock_ruleset_attr attr = {
		.handled_access_fs = handled_fs,
	};
	int ruleset_fd = landlock_create_ruleset(
		&attr, sizeof(attr), 0);
	if (ruleset_fd < 0)
		return -errno;

	int rc = 0;

	switch (profile) {
	case RW_LANDLOCK_WORKER:
		/* Read-only access to mdbx file. */
		rc = add_path_rule(ruleset_fd, mdbx_path,
				   LANDLOCK_ACCESS_FS_READ_FILE);
		if (rc < 0)
			goto cleanup;

		/* Read-only access to /dev/net/tun. */
		rc = add_path_rule(ruleset_fd, "/dev/net/tun",
				   LANDLOCK_ACCESS_FS_READ_FILE);
		if (rc < 0)
			goto cleanup;
		break;

	case RW_LANDLOCK_AUTHMOD:
		/* Read-write access to mdbx file. */
		rc = add_path_rule(ruleset_fd, mdbx_path,
				   LANDLOCK_ACCESS_FS_READ_FILE |
				   LANDLOCK_ACCESS_FS_WRITE_FILE);
		if (rc < 0)
			goto cleanup;

		/* Read-write access to sqlite file. */
		rc = add_path_rule(ruleset_fd, sqlite_path,
				   LANDLOCK_ACCESS_FS_READ_FILE |
				   LANDLOCK_ACCESS_FS_WRITE_FILE);
		if (rc < 0)
			goto cleanup;

		/* Read-only access to /dev/urandom. */
		rc = add_path_rule(ruleset_fd, "/dev/urandom",
				   LANDLOCK_ACCESS_FS_READ_FILE);
		if (rc < 0)
			goto cleanup;
		break;
	}

	/* Drop the ability to gain new privileges (required by Landlock). */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		rc = -errno;
		goto cleanup;
	}

	/* Enforce the ruleset on this process. */
	if (landlock_restrict_self(ruleset_fd, 0) < 0) {
		rc = -errno;
		goto cleanup;
	}

cleanup:
	close(ruleset_fd);
	return rc;
}
