/*
 * Copyright (c) 2020 Dmitry V. Levin <ldv@altlinux.org>
 *
 * Handy inline functions and macros providing some convenient functionality
 * to libpam and its modules.
 */

#ifndef PAM_INLINE_H
#define PAM_INLINE_H

#include "pam_cc_compat.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>

/*
 * Evaluates to
 * - a syntax error if the argument is 0,
 * 0, otherwise.
 */
#define PAM_FAIL_BUILD_ON_ZERO(e_)	(sizeof(int[-1 + 2 * !!(e_)]) * 0)

/*
 * Evaluates to
 * 1, if the given type is known to be a non-array type
 * 0, otherwise.
 */
#define PAM_IS_NOT_ARRAY(a_)		PAM_IS_SAME_TYPE((a_), &(a_)[0])

/*
 * Evaluates to
 * - a syntax error if the argument is not an array,
 * 0, otherwise.
 */
#define PAM_MUST_BE_ARRAY(a_)		PAM_FAIL_BUILD_ON_ZERO(!PAM_IS_NOT_ARRAY(a_))

/* Evaluates to the number of elements in the specified array.  */
#define PAM_ARRAY_SIZE(a_)		(sizeof(a_) / sizeof((a_)[0]) + PAM_MUST_BE_ARRAY(a_))

/*
 * Returns NULL if STR does not start with PREFIX,
 * or a pointer to the first char in STR after PREFIX.
 * The length of PREFIX is specified by PREFIX_LEN.
 */
static inline const char *
pam_str_skip_prefix_len(const char *str, const char *prefix, size_t prefix_len)
{
	return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

#define pam_str_skip_prefix(str_, prefix_)	\
	pam_str_skip_prefix_len((str_), (prefix_), sizeof(prefix_) - 1 + PAM_MUST_BE_ARRAY(prefix_))

/*
 * Returns NULL if STR does not start with PREFIX
 * (ignoring the case of the characters),
 * or a pointer to the first char in STR after PREFIX.
 * The length of PREFIX is specified by PREFIX_LEN.
 */
static inline const char *
pam_str_skip_icase_prefix_len(const char *str, const char *prefix, size_t prefix_len)
{
	return strncasecmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

#define pam_str_skip_icase_prefix(str_, prefix_)	\
	pam_str_skip_icase_prefix_len((str_), (prefix_), sizeof(prefix_) - 1 + PAM_MUST_BE_ARRAY(prefix_))

static inline int
pam_read_passwords(int fd, int npass, char **passwords)
{
	/*
	 * The passwords array must contain npass preallocated
	 * buffers of length PAM_MAX_RESP_SIZE + 1.
	 */
	int rbytes = 0;
	int offset = 0;
	int i = 0;
	char *pptr;
	while (npass > 0) {
		rbytes = read(fd, passwords[i]+offset, PAM_MAX_RESP_SIZE+1-offset);

		if (rbytes < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		if (rbytes == 0) {
			break;
		}

		while (npass > 0 &&
		       (pptr = memchr(passwords[i] + offset, '\0', rbytes)) != NULL) {
			++pptr; /* skip the '\0' */
			rbytes -= pptr - (passwords[i] + offset);
			i++;
			offset = 0;
			npass--;
			if (rbytes > 0) {
				if (npass > 0) {
					memcpy(passwords[i], pptr, rbytes);
				}
				memset(pptr, '\0', rbytes);
			}
		}
		offset += rbytes;
	}

	/* clear up */
	if (offset > 0 && npass > 0) {
		memset(passwords[i], '\0', offset);
	}

	return i;
}

#endif /* PAM_INLINE_H */
