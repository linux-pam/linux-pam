/* pam_loginuid.c --
 * Copyright 2005 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500
 * Boston, MA 02110-1335 USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 * PAM module that sets the login uid introduced in kernel 2.6.11
 */

#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <fcntl.h>

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#include <sys/select.h>
#include <errno.h>
#endif

/*
 * This function writes the loginuid to the /proc system. It returns
 * 0 on success and 1 on failure.
 */
static int set_loginuid(pam_handle_t *pamh, uid_t uid)
{
	int fd, count, rc = 0;
	char loginuid[24];

	count = snprintf(loginuid, sizeof(loginuid), "%lu", (unsigned long)uid);
	fd = open("/proc/self/loginuid", O_NOFOLLOW|O_WRONLY|O_TRUNC);
	if (fd < 0) {
		if (errno != ENOENT) {
			rc = 1;
			pam_syslog(pamh, LOG_ERR,
				   "Cannot open /proc/self/loginuid: %m");
		}
		return rc;
	}
	if (pam_modutil_write(fd, loginuid, count) != count)
		rc = 1;
	close(fd);
	return rc;
}

#ifdef HAVE_LIBAUDIT
/*
 * This function is called only if "require_auditd" option is passed. It is
 * called after loginuid has been set. The purpose is to disallow logins
 * should the audit daemon not be running or crashed. It returns PAM_SUCCESS
 * if the audit daemon is running  and PAM_SESSION_ERR otherwise.
 */
static int check_auditd(void)
{
	int fd, retval;

	fd = audit_open();
	if (fd < 0) {
		/* This is here to let people that build their own kernel
		   and disable the audit system get in. You get these error
		   codes only when the kernel doesn't have audit
		   compiled in. */
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
		    errno == EAFNOSUPPORT)
			return PAM_SUCCESS;
		return PAM_SESSION_ERR;
	}
	retval = audit_request_status(fd);
	if (retval > 0) {
		struct audit_reply rep;
		int i;
		int timeout = 30; /* tenths of seconds */
		fd_set read_mask;

		FD_ZERO(&read_mask);
		FD_SET(fd, &read_mask);

		for (i = 0; i < timeout; i++) {
			struct timeval t;
			int rc;

			t.tv_sec  = 0;
			t.tv_usec = 100000;
			do {
				rc = select(fd+1, &read_mask, NULL, NULL, &t);
			} while (rc < 0 && errno == EINTR);

			rc = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING,0);
			if (rc > 0) {
				/* If we get done or error, break out */
				if (rep.type == NLMSG_DONE ||
						rep.type == NLMSG_ERROR)
					break;

				/* If its not status, keep looping */
				if (rep.type != AUDIT_GET)
					continue;

				/* Found it... */
				close(fd);
				if (rep.status->pid == 0)
					return PAM_SESSION_ERR;
				else
					return PAM_SUCCESS;
			}
		}
	}
	close(fd);
	if (retval == -ECONNREFUSED) {
		/* This is here to let people that build their own kernel
		   and disable the audit system get in. ECONNREFUSED is
		   issued by the kernel when there is "no on listening". */
		return PAM_SUCCESS;
	} else if (retval == -EPERM && getuid() != 0) {
		/* If we get this, then the kernel supports auditing
		 * but we don't have enough privilege to write to the
		 * socket. Therefore, we have already been authenticated
		 * and we are a common user. Just act as though auditing
		 * is not enabled. Any other error we take seriously. */
		return PAM_SUCCESS;
	}

	return PAM_SESSION_ERR;
}
#endif

/*
 * Initialize audit session for user
 */
static int
_pam_loginuid(pam_handle_t *pamh, int flags UNUSED,
#ifdef HAVE_LIBAUDIT
	      int argc, const char **argv
#else
	      int argc UNUSED, const char **argv UNUSED
#endif
)
{
        const char *user = NULL;
	struct passwd *pwd;
#ifdef HAVE_LIBAUDIT
	int require_auditd = 0;
#endif

	/* get user name */
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_ERR, "error recovering login user-name");
		return PAM_SESSION_ERR;
	}

        /* get user info */
	if ((pwd = pam_modutil_getpwnam(pamh, user)) == NULL) {
		pam_syslog(pamh, LOG_ERR,
			 "error: login user-name '%s' does not exist", user);
		return PAM_SESSION_ERR;
	}

	if (set_loginuid(pamh, pwd->pw_uid)) {
		pam_syslog(pamh, LOG_ERR, "set_loginuid failed\n");
		return PAM_SESSION_ERR;
	}

#ifdef HAVE_LIBAUDIT
	while (argc-- > 0) {
		if (strcmp(*argv, "require_auditd") == 0)
			require_auditd = 1;
		argv++;
	}

	if (require_auditd)
		return check_auditd();
	else
#endif
		return PAM_SUCCESS;
}

/*
 * PAM routines
 *
 * This is here for vsftpd which doesn't seem to run the session stack
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_loginuid(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return _pam_loginuid(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
	return PAM_SUCCESS;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_loginuid_modstruct = {
    "pam_loginuid",
    NULL,
    NULL,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    NULL
};
#endif
