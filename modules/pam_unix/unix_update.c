/*
 * This program is designed to run with sufficient privilege
 * to read and write all of the unix password databases.
 * Its purpose is to allow updating the databases when
 * SELinux confinement of the caller domain prevents them to
 * do that themselves.
 *
 * The password is read from the standard input. The exit status of
 * this program indicates whether the password was updated or not.
 *
 * Copyright information is located at the end of the file.
 *
 */

#include "config.h"

#include <stdarg.h>
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
#include <sys/time.h>

#include <security/_pam_types.h>
#include <security/_pam_macros.h>

#include "passverify.h"

static int
set_password(const char *forwho, const char *shadow, const char *remember)
{
    struct passwd *pwd = NULL;
    int retval;
    char pass[MAXPASS + 1];
    char towhat[MAXPASS + 1];
    int npass = 0;
    /* we don't care about number format errors because the helper
       should be called internally only */
    int doshadow = atoi(shadow);
    int nremember = atoi(remember);
    char *passwords[] = { pass, towhat };

    /* read the password from stdin (a pipe from the pam_unix module) */

    npass = read_passwords(STDIN_FILENO, 2, passwords);

    if (npass != 2) {	/* is it a valid password? */
      if (npass == 1) {
        helper_log_err(LOG_DEBUG, "no new password supplied");
	memset(pass, '\0', MAXPASS);
      } else {
        helper_log_err(LOG_DEBUG, "no valid passwords supplied");
      }
      return PAM_AUTHTOK_ERR;
    }

    if (lock_pwdf() != PAM_SUCCESS)
	return PAM_AUTHTOK_LOCK_BUSY;

    pwd = getpwnam(forwho);

    if (pwd == NULL) {
        retval = PAM_USER_UNKNOWN;
        goto done;
    }

    /* If real caller uid is not root we must verify that
       received old pass agrees with the current one.
       We always allow change from null pass. */
    if (getuid()) {
	retval = helper_verify_password(forwho, pass, 1);
	if (retval != PAM_SUCCESS) {
	    goto done;
	}
    }

    /* first, save old password */
    if (save_old_password(forwho, pass, nremember)) {
	retval = PAM_AUTHTOK_ERR;
	goto done;
    }

    if (doshadow || is_pwd_shadowed(pwd)) {
	retval = unix_update_shadow(forwho, towhat);
	if (retval == PAM_SUCCESS)
	    if (!is_pwd_shadowed(pwd))
		retval = unix_update_passwd(forwho, "x");
    } else {
	retval = unix_update_passwd(forwho, towhat);
    }

done:
    memset(pass, '\0', MAXPASS);
    memset(towhat, '\0', MAXPASS);

    unlock_pwdf();

    if (retval == PAM_SUCCESS) {
	return PAM_SUCCESS;
    } else {
	return PAM_AUTHTOK_ERR;
    }
}

int main(int argc, char *argv[])
{
	char *option;

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

	if (isatty(STDIN_FILENO) || argc != 5 ) {
		helper_log_err(LOG_NOTICE
		      ,"inappropriate use of Unix helper binary [UID=%d]"
			 ,getuid());
		fprintf(stderr
		 ,"This binary is not designed for running in this way\n"
		      "-- the system administrator has been informed\n");
		sleep(10);	/* this should discourage/annoy the user */
		return PAM_SYSTEM_ERR;
	}

	/* We must be root to read/update shadow.
	 */
	if (geteuid() != 0) {
	    return PAM_CRED_INSUFFICIENT;
	}

	option = argv[2];

	if (strcmp(option, "update") == 0) {
	    /* Attempting to change the password */
	    return set_password(argv[1], argv[3], argv[4]);
	}

	return PAM_SYSTEM_ERR;
}

/*
 * Copyright (c) Andrew G. Morgan, 1996. All rights reserved
 * Copyright (c) Red Hat, Inc., 2007, 2008. All rights reserved
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
