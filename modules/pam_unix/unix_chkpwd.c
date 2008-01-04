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
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED (selinux_enabled!=-1 ? selinux_enabled : (selinux_enabled=is_selinux_enabled()>0))
static security_context_t prev_context=NULL;
static int selinux_enabled=-1;
#else
#define SELINUX_ENABLED 0
#endif

#define MAXPASS		200	/* the maximum length of a password */

#include <security/_pam_types.h>
#include <security/_pam_macros.h>

#include "passverify.h"

/* syslogging function for errors and other information */

static void su_sighandler(int sig)
{
#ifndef SA_RESETHAND
	/* emulate the behaviour of the SA_RESETHAND flag */
	if ( sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV )
		signal(sig, SIG_DFL);
#endif
	if (sig > 0) {
		helper_log_err(LOG_NOTICE, "caught signal %d.", sig);
		exit(sig);
	}
}

static void setup_signals(void)
{
	struct sigaction action;	/* posix signal structure */

	/*
	 * Setup signal handlers
	 */
	(void) memset((void *) &action, 0, sizeof(action));
	action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
	action.sa_flags = SA_RESETHAND;
#endif
	(void) sigaction(SIGILL, &action, NULL);
	(void) sigaction(SIGTRAP, &action, NULL);
	(void) sigaction(SIGBUS, &action, NULL);
	(void) sigaction(SIGSEGV, &action, NULL);
	action.sa_handler = SIG_IGN;
	action.sa_flags = 0;
	(void) sigaction(SIGTERM, &action, NULL);
	(void) sigaction(SIGHUP, &action, NULL);
	(void) sigaction(SIGINT, &action, NULL);
	(void) sigaction(SIGQUIT, &action, NULL);
}

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

static char *getuidname(uid_t uid)
{
	struct passwd *pw;
	static char username[32];

	pw = getpwuid(uid);
	if (pw == NULL)
		return NULL;

	strncpy(username, pw->pw_name, sizeof(username));
	username[sizeof(username) - 1] = '\0';

	return username;
}

#define SH_TMPFILE		"/etc/nshadow"
static int _update_shadow(const char *forwho)
{
    struct spwd *spwdent = NULL, *stmpent = NULL;
    FILE *pwfile, *opwfile;
    int err = 1;
    int oldmask;
    struct stat st;
    char pass[MAXPASS + 1];
    char towhat[MAXPASS + 1];
    int npass=0;

    /* read the password from stdin (a pipe from the pam_unix module) */

    npass = read(STDIN_FILENO, pass, MAXPASS);

    if (npass < 0) {	/* is it a valid password? */

      helper_log_err(LOG_DEBUG, "no password supplied");
      return PAM_AUTHTOK_ERR;

    } else if (npass >= MAXPASS) {

      helper_log_err(LOG_DEBUG, "password too long");
      return PAM_AUTHTOK_ERR;

    } else {
      /* does pass agree with the official one? */
      int retval=0;
      pass[npass] = '\0';	/* NUL terminate */
      retval = helper_verify_password(forwho, pass, 0);
      if (retval != PAM_SUCCESS) {
	return retval;
      }
    }

    /* read the password from stdin (a pipe from the pam_unix module) */

    npass = read(STDIN_FILENO, towhat, MAXPASS);

    if (npass < 0) {	/* is it a valid password? */

      helper_log_err(LOG_DEBUG, "no new password supplied");
      return PAM_AUTHTOK_ERR;

    } else if (npass >= MAXPASS) {

      helper_log_err(LOG_DEBUG, "new password too long");
      return PAM_AUTHTOK_ERR;

    }

    towhat[npass] = '\0';	/* NUL terminate */
    spwdent = getspnam(forwho);
    if (spwdent == NULL) {
	return PAM_USER_UNKNOWN;
    }
    oldmask = umask(077);

#ifdef WITH_SELINUX
    if (SELINUX_ENABLED) {
      security_context_t shadow_context=NULL;
      if (getfilecon("/etc/shadow",&shadow_context)<0) {
	return PAM_AUTHTOK_ERR;
      };
      if (getfscreatecon(&prev_context)<0) {
	freecon(shadow_context);
	return PAM_AUTHTOK_ERR;
      }
      if (setfscreatecon(shadow_context)) {
	freecon(shadow_context);
	freecon(prev_context);
	return PAM_AUTHTOK_ERR;
      }
      freecon(shadow_context);
    }
#endif
    pwfile = fopen(SH_TMPFILE, "w");
    umask(oldmask);
    if (pwfile == NULL) {
	err = 1;
	goto done;
    }

    opwfile = fopen("/etc/shadow", "r");
    if (opwfile == NULL) {
	fclose(pwfile);
	err = 1;
	goto done;
    }

    if (fstat(fileno(opwfile), &st) == -1) {
	fclose(opwfile);
	fclose(pwfile);
	err = 1;
	goto done;
    }

    if (fchown(fileno(pwfile), st.st_uid, st.st_gid) == -1) {
	fclose(opwfile);
	fclose(pwfile);
	err = 1;
	goto done;
    }
    if (fchmod(fileno(pwfile), st.st_mode) == -1) {
	fclose(opwfile);
	fclose(pwfile);
	err = 1;
	goto done;
    }

    stmpent = fgetspent(opwfile);
    while (stmpent) {

	if (!strcmp(stmpent->sp_namp, forwho)) {
	    stmpent->sp_pwdp = towhat;
	    stmpent->sp_lstchg = time(NULL) / (60 * 60 * 24);
	    err = 0;
	    D(("Set password %s for %s", stmpent->sp_pwdp, forwho));
	}

	if (putspent(stmpent, pwfile)) {
	    D(("error writing entry to shadow file: %m"));
	    err = 1;
	    break;
	}

	stmpent = fgetspent(opwfile);
    }
    fclose(opwfile);

    if (fclose(pwfile)) {
	D(("error writing entries to shadow file: %m"));
	err = 1;
    }

 done:
    if (!err) {
	if (rename(SH_TMPFILE, "/etc/shadow"))
	    err = 1;
    }

#ifdef WITH_SELINUX
    if (SELINUX_ENABLED) {
      if (setfscreatecon(prev_context)) {
	err = 1;
      }
      if (prev_context)
	freecon(prev_context);
      prev_context=NULL;
    }
#endif

    if (!err) {
	return PAM_SUCCESS;
    } else {
	unlink(SH_TMPFILE);
	return PAM_AUTHTOK_ERR;
    }
}

int main(int argc, char *argv[])
{
	char pass[MAXPASS + 1];
	char *option;
	int npass, nullok;
	int blankpass;
	int retval = PAM_AUTH_ERR;
	char *user;

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
	    return PAM_AUTH_ERR;
	  }
	}

	option=argv[2];

	if (strncmp(argv[2], "chkexpiry", 8) == 0) {
	  /* Check account information from the shadow file */
	  return _check_expiry(argv[1]);
	  
	}

	if (strncmp(option, "shadow", 8) == 0) {
	  /* Attempting to change the password */
	  return _update_shadow(argv[1]);
	}

	/* read the nullok/nonull option */
	if (strncmp(option, "nullok", 8) == 0)
	  nullok = 1;
	else
	  nullok = 0;

	/* read the password from stdin (a pipe from the pam_unix module) */

	npass = read(STDIN_FILENO, pass, MAXPASS);

	if (npass < 0) {	/* is it a valid password? */

		helper_log_err(LOG_DEBUG, "no password supplied");

	} else if (npass >= MAXPASS) {

		helper_log_err(LOG_DEBUG, "password too long");

	} else {
		if (npass == 0) {
			/* the password is NULL */
			blankpass = 1;
			retval = helper_verify_password(user, NULL, nullok);

		} else {
			/* does pass agree with the official one? */
			if (pass[0] == '\0')
				blankpass = 1;
			pass[npass] = '\0';	/* NUL terminate */
			retval = helper_verify_password(user, pass, nullok);

		}
	}

	memset(pass, '\0', MAXPASS);	/* clear memory of the password */

	/* return pass or fail */

	if (retval != PAM_SUCCESS) {
		if (!nullok || !blankpass)
			/* no need to log blank pass test */
			helper_log_err(LOG_NOTICE, "password check failed for user (%s)", user);
		return PAM_AUTH_ERR;
	} else {
		return PAM_SUCCESS;
	}
}

/*
 * Copyright (c) Andrew G. Morgan, 1996. All rights reserved
 * Copyright (c) Red Hat, Inc., 2007. All rights reserved
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
