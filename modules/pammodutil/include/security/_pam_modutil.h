#ifndef _PAM_MODUTIL_H
#define _PAM_MODUTIL_H

/*
 * $Id$
 *
 * This file is a list of handy libc wrappers that attempt to provide some
 * thread-safe and other convenient functionality to modules in a form that
 * is common, but not dynamically linked with yet another dynamic pam
 * library extension.
 *
 * A number of these functions reserve space in a pam_[sg]et_data item.
 * In all cases, the name of the item is prefixed with "_pammodutil_*".
 *
 * On systems that simply can't support thread safe programming, these
 * functions don't support it either - sorry.
 *
 * Copyright (c) 2001-2002 Andrew Morgan <morgan@kernel.org>
 */

#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <sys/types.h>

extern struct passwd *_pammodutil_getpwnam(pam_handle_t *pamh,
					   const char *user);

extern struct passwd *_pammodutil_getpwuid(pam_handle_t *pamh,
					   uid_t uid);

extern struct group  *_pammodutil_getgrnam(pam_handle_t *pamh,
                                           const char *group);
 
extern struct group  *_pammodutil_getgrgid(pam_handle_t *pamh,
                                           gid_t gid);
 
extern struct spwd   *_pammodutil_getspnam(pam_handle_t *pamh,
                                           const char *user);

extern int _pammodutil_user_in_group_nam_nam(pam_handle_t *pamh,
                                             const char *user,
                                             const char *group);
 
extern int _pammodutil_user_in_group_nam_gid(pam_handle_t *pamh,
                                             const char *user,
                                             gid_t group);
 
extern int _pammodutil_user_in_group_uid_nam(pam_handle_t *pamh,
                                             uid_t user,
                                             const char *group);
 
extern int _pammodutil_user_in_group_uid_gid(pam_handle_t *pamh,
                                             uid_t user,
                                             gid_t group);

extern void _pammodutil_cleanup(pam_handle_t *pamh, void *data,
				int error_status);

extern const char *_pammodutil_getlogin(pam_handle_t *pamh);

extern int _pammodutil_read(int fd, char *buffer, int count);

extern int _pammodutil_write(int fd, const char *buffer, int count);

#endif /* _PAM_MODUTIL_H */
