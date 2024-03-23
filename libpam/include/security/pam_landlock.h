#include "_pam_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef _SECURITY_PAM_LANDLOCK_H
#define _SECURITY_PAM_LANDLOCK_H

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
		const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
		const enum landlock_rule_type rule_type,
		const void *const rule_attr,
		const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
			flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
		const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#define ACCESS_FS_ROUGHLY_WRITE ( \
		LANDLOCK_ACCESS_FS_WRITE_FILE | \
		LANDLOCK_ACCESS_FS_REMOVE_DIR | \
		LANDLOCK_ACCESS_FS_REMOVE_FILE | \
		LANDLOCK_ACCESS_FS_MAKE_CHAR | \
		LANDLOCK_ACCESS_FS_MAKE_DIR | \
		LANDLOCK_ACCESS_FS_MAKE_REG | \
		LANDLOCK_ACCESS_FS_MAKE_SOCK | \
		LANDLOCK_ACCESS_FS_MAKE_FIFO | \
		LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
		LANDLOCK_ACCESS_FS_MAKE_SYM | \
		LANDLOCK_ACCESS_FS_REFER)

#define LANDLOCK_COMPAT_ERR -1
#define LANDLOCK_FATAL_ERR 1

static int _pam_landlock_create_ruleset(int * const ruleset_fd, const __u64 ruleset) {
	int abi;

	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = ruleset,
	};

	/* Checks for Landlock ABI compatibility. */
	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0)
		return LANDLOCK_COMPAT_ERR;
	if (abi < 2)
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;

	*ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (*ruleset_fd < 0) {
		D(("Failed to create a ruleset"));
		return LANDLOCK_FATAL_ERR;
	}
	return 0;
}

static int _pam_landlock_apply_restrictions(const int ruleset_fd) {
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		D(("Failed to restrict privileges"));
		close(ruleset_fd);
		return LANDLOCK_FATAL_ERR;
	}
	if (landlock_restrict_self(ruleset_fd, 0)) {
		D(("Failed to enforce ruleset"));
		close(ruleset_fd);
		return LANDLOCK_FATAL_ERR;
	}
	close(ruleset_fd);
	return 0;
}

#endif /* _SECURITY_PAM_LANDLOCK_H */
