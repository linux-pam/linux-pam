/*
 * This program is designed to run setuid(root) or with sufficient
 * privilege to read all of the unix password databases. It is designed
 * to provide a mechanism for the current user (defined by this
 * process' uid) to verify their own password.
 *
 * The password is read from the standard input. The exit status of
 * this program indicates whether the user is authenticated or not.
 *
 * Copyright information is located at the end of the file.
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#endif

#include <security/_pam_types.h>
#include <security/_pam_macros.h>

#include "passverify.h"

static int _check_expiry(const char *uname)
{
	struct spwd *spent;
	struct passwd *pwent;
	int retval;
	int daysleft;

	retval = get_account_info(uname, &pwent, &spent);
	if (retval != PAM_SUCCESS) {
		helper_log_err(LOG_ALERT, "could not obtain user info (%s)", uname);
		printf("-1\n");
		return retval;
	}

	if (spent == NULL) {
		printf("-1\n");
		return retval;
	}

	retval = check_shadow_expiry(spent, &daysleft);
	printf("%d\n", daysleft);
	return retval;
}

#ifdef HAVE_LIBAUDIT
static int _audit_log(int type, const char *uname, int rc)
{
	int audit_fd;

	audit_fd = audit_open();
	if (audit_fd < 0) {
		/* You get these error codes only when the kernel doesn't have
		 * audit compiled in. */
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
			errno == EAFNOSUPPORT)
			return PAM_SUCCESS;

		helper_log_err(LOG_CRIT, "audit_open() failed: %m");
		return PAM_AUTH_ERR;
	}

	rc = audit_log_acct_message(audit_fd, type, NULL, "PAM:unix_chkpwd",
		uname, -1, NULL, NULL, NULL, rc == PAM_SUCCESS);
	if (rc == -EPERM && geteuid() != 0) {
		rc = 0;
	}

	audit_close(audit_fd);

	return rc < 0 ? PAM_AUTH_ERR : PAM_SUCCESS;
}
#endif

int main(int argc, char *argv[])
{
	char pass[MAXPASS + 1];
	char *option;
	int npass, nullok;
	int blankpass = 0;
	int retval = PAM_AUTH_ERR;
	char *user;
	char *passwords[] = { pass };

	/*
	 * Catch or ignore as many signal as possible.
	 */
	setup_signals();

	/*
	 * we establish that this program is running with non-tty stdin.
	 * this is to discourage casual use. It does *NOT* prevent an
	 * intruder from repeatadly running this program to determine the
	 * password of the current user (brute force attack, but one for
	 * which the attacker must already have gained access to the user's
	 * account).
	 */

	if (isatty(STDIN_FILENO) || argc != 3 ) {
		helper_log_err(LOG_NOTICE
		      ,"inappropriate use of Unix helper binary [UID=%d]"
			 ,getuid());
#ifdef HAVE_LIBAUDIT
		_audit_log(AUDIT_ANOM_EXEC, getuidname(getuid()), PAM_SYSTEM_ERR);
#endif
		fprintf(stderr
		 ,"This binary is not designed for running in this way\n"
		      "-- the system administrator has been informed\n");
		sleep(10);	/* this should discourage/annoy the user */
		return PAM_SYSTEM_ERR;
	}

	/*
	 * Determine what the current user's name is.
	 * We must thus skip the check if the real uid is 0.
	 */
	if (getuid() == 0) {
	  user=argv[1];
	}
	else {
	  user = getuidname(getuid());
	  /* if the caller specifies the username, verify that user
	     matches it */
	  if (strcmp(user, argv[1])) {
	    user = argv[1];
	    /* no match -> permanently change to the real user and proceed */
	    if (setuid(getuid()) != 0)
		return PAM_AUTH_ERR;
	  }
	}

	option=argv[2];

	if (strcmp(option, "chkexpiry") == 0)
	  /* Check account information from the shadow file */
	  return _check_expiry(argv[1]);
	/* read the nullok/nonull option */
	else if (strcmp(option, "nullok") == 0)
	  nullok = 1;
	else if (strcmp(option, "nonull") == 0)
	  nullok = 0;
	else {
#ifdef HAVE_LIBAUDIT
	  _audit_log(AUDIT_ANOM_EXEC, getuidname(getuid()), PAM_SYSTEM_ERR);
#endif
	  return PAM_SYSTEM_ERR;
	}
	/* read the password from stdin (a pipe from the pam_unix module) */

	npass = read_passwords(STDIN_FILENO, 1, passwords);

	if (npass != 1) {	/* is it a valid password? */
		helper_log_err(LOG_DEBUG, "no password supplied");
		*pass = '\0';
	}

	if (*pass == '\0') {
		blankpass = 1;
	}

	retval = helper_verify_password(user, pass, nullok);

	memset(pass, '\0', MAXPASS);	/* clear memory of the password */

	/* return pass or fail */

	if (retval != PAM_SUCCESS) {
		if (!nullok || !blankpass) {
			/* no need to log blank pass test */
#ifdef HAVE_LIBAUDIT
			if (getuid() != 0)
				_audit_log(AUDIT_USER_AUTH, user, PAM_AUTH_ERR);
#endif
			helper_log_err(LOG_NOTICE, "password check failed for user (%s)", user);
		}
		return PAM_AUTH_ERR;
	} else {
	        if (getuid() != 0) {
#ifdef HAVE_LIBAUDIT
			return _audit_log(AUDIT_USER_AUTH, user, PAM_SUCCESS);
#else
		        return PAM_SUCCESS;
#endif
	        }
		return PAM_SUCCESS;
	}
}

/*
 * Copyright (c) Andrew G. Morgan, 1996. All rights reserved
 * Copyright (c) Red Hat, Inc., 2007,2008. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
