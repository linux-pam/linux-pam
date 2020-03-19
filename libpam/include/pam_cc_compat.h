/*
 * Copyright (c) 2020 Dmitry V. Levin <ldv@altlinux.org>
 */

#ifndef PAM_CC_COMPAT_H
#define PAM_CC_COMPAT_H

#include "config.h"
#include <security/_pam_types.h>

#if defined __clang__ && defined __clang_major__ && defined __clang_minor__
# define PAM_CLANG_PREREQ(maj, min)					\
	((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
#else
# define PAM_CLANG_PREREQ(maj, min)	0
#endif

#if PAM_GNUC_PREREQ(2, 7)
# define PAM_ATTRIBUTE_ALIGNED(arg)	__attribute__((__aligned__(arg)))
#else
# define PAM_ATTRIBUTE_ALIGNED(arg)	/* empty */
#endif

#if PAM_GNUC_PREREQ(4, 6)
# define DIAG_PUSH_IGNORE_CAST_QUAL					\
	_Pragma("GCC diagnostic push");					\
	_Pragma("GCC diagnostic ignored \"-Wcast-qual\"")
# define DIAG_POP_IGNORE_CAST_QUAL					\
	_Pragma("GCC diagnostic pop")
# define DIAG_PUSH_IGNORE_CAST_ALIGN					\
	_Pragma("GCC diagnostic push");					\
	_Pragma("GCC diagnostic ignored \"-Wcast-align\"")
# define DIAG_POP_IGNORE_CAST_ALIGN					\
	_Pragma("GCC diagnostic pop")
#elif PAM_CLANG_PREREQ(2, 6)
# define DIAG_PUSH_IGNORE_CAST_QUAL					\
	_Pragma("clang diagnostic push");				\
	_Pragma("clang diagnostic ignored \"-Wcast-qual\"")
# define DIAG_POP_IGNORE_CAST_QUAL					\
	_Pragma("clang diagnostic pop")
# define DIAG_PUSH_IGNORE_CAST_ALIGN					\
	_Pragma("clang diagnostic push");				\
	_Pragma("clang diagnostic ignored \"-Wcast-align\"")
# define DIAG_POP_IGNORE_CAST_ALIGN					\
	_Pragma("clang diagnostic pop")
#else
# define DIAG_PUSH_IGNORE_CAST_QUAL	/* empty */
# define DIAG_POP_IGNORE_CAST_QUAL	/* empty */
# define DIAG_PUSH_IGNORE_CAST_ALIGN	/* empty */
# define DIAG_POP_IGNORE_CAST_ALIGN	/* empty */
#endif

#endif /* PAM_CC_COMPAT_H */
