#ifndef _SECURITY__PAM_MODUTIL_H
#define _SECURITY__PAM_MODUTIL_H

/*
 * $Id$
 *
 * This file is a list of handy libc wrappers that attempt to provide some
 * thread-safe and other convenient functionality to modules in a common form.
 *
 * A number of these functions reserve space in a pam_[sg]et_data item.
 * In all cases, the name of the item is prefixed with "_pammodutil_*".
 *
 * On systems that simply can't support thread safe programming, these
 * functions don't support it either - sorry.
 *
 * Copyright (c) 2001-2002 Andrew Morgan <morgan@kernel.org>
 */

#include <security/_pam_types.h>

extern struct passwd * PAM_NONNULL((1,2))
pam_modutil_getpwnam(pam_handle_t *pamh, const char *user);

extern struct passwd * PAM_NONNULL((1))
pam_modutil_getpwuid(pam_handle_t *pamh, uid_t uid);

extern struct group  * PAM_NONNULL((1,2))
pam_modutil_getgrnam(pam_handle_t *pamh, const char *group);
 
extern struct group  * PAM_NONNULL((1))
pam_modutil_getgrgid(pam_handle_t *pamh, gid_t gid);
 
extern struct spwd   * PAM_NONNULL((1,2))
pam_modutil_getspnam(pam_handle_t *pamh, const char *user);

extern int PAM_NONNULL((1,2,3))
pam_modutil_user_in_group_nam_nam(pam_handle_t *pamh,
                                  const char *user,
                                  const char *group);
 
extern int PAM_NONNULL((1,2))
pam_modutil_user_in_group_nam_gid(pam_handle_t *pamh,
                                  const char *user,
                                  gid_t group);
 
extern int PAM_NONNULL((1,3))
pam_modutil_user_in_group_uid_nam(pam_handle_t *pamh,
                                  uid_t user,
                                  const char *group);
 
extern int PAM_NONNULL((1))
pam_modutil_user_in_group_uid_gid(pam_handle_t *pamh,
                                  uid_t user,
                                  gid_t group);

extern const char * PAM_NONNULL((1))
pam_modutil_getlogin(pam_handle_t *pamh);

extern int
pam_modutil_read(int fd, char *buffer, int count);

extern int
pam_modutil_write(int fd, const char *buffer, int count);

#endif /* _SECURITY__PAM_MODUTIL_H */
