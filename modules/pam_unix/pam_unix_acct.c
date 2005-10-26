/*
 * Copyright Elliot Lee, 1996.  All rights reserved.
 * Copyright Jan Rêkorajski, 1999.  All rights reserved.
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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>		/* for time() */
#include <errno.h>
#include <sys/wait.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED is_selinux_enabled()>0
#endif

#include <security/_pam_macros.h>

/* indicate that the following groups are defined */

#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "support.h"

#ifdef WITH_SELINUX

struct spwd spwd;

struct spwd *_unix_run_verify_binary(pam_handle_t *pamh, unsigned int ctrl, const char *user)
{
  int retval=0, child, fds[2];
  void (*sighandler)(int) = NULL;
  D(("running verify_binary"));

  /* create a pipe for the messages */
  if (pipe(fds) != 0) {
    D(("could not make pipe"));
    pam_syslog(pamh, LOG_ERR, "Could not make pipe: %m");
    return NULL;
  }
  D(("called."));

  if (off(UNIX_NOREAP, ctrl)) {
    /*
     * This code arranges that the demise of the child does not cause
     * the application to receive a signal it is not expecting - which
     * may kill the application or worse.
     *
     * The "noreap" module argument is provided so that the admin can
     * override this behavior.
     */
    sighandler = signal(SIGCHLD, SIG_DFL);
  }

  /* fork */
  child = fork();
  if (child == 0) {
    size_t i=0;
    struct rlimit rlim;
    static char *envp[] = { NULL };
    char *args[] = { NULL, NULL, NULL, NULL };

    close(0); close(1);
    /* reopen stdin as pipe */
    close(fds[0]);
    dup2(fds[1], STDOUT_FILENO);

    /* XXX - should really tidy up PAM here too */

    if (getrlimit(RLIMIT_NOFILE,&rlim)==0) {
      for (i=2; i < rlim.rlim_max; i++) {
	if ((unsigned int)fds[1] != i) {
	  close(i);
	}
      }
    }

    if (SELINUX_ENABLED && geteuid() == 0) {
      /* must set the real uid to 0 so the helper will not error
         out if pam is called from setuid binary (su, sudo...) */
      setuid(0);
    }

    /* exec binary helper */
    args[0] = x_strdup(CHKPWD_HELPER);
    args[1] = x_strdup(user);
    args[2] = x_strdup("verify");

    execve(CHKPWD_HELPER, args, envp);

    pam_syslog(pamh, LOG_ERR, "helper binary execve failed: %m");
    /* should not get here: exit with error */
    close (fds[1]);
    D(("helper binary is not available"));
    exit(PAM_AUTHINFO_UNAVAIL);
  } else {
    close(fds[1]);
    if (child > 0) {
      char buf[1024];
      int rc=0;
      rc=waitpid(child, &retval, 0);  /* wait for helper to complete */
      if (rc<0) {
	pam_syslog(pamh, LOG_ERR, "unix_chkpwd waitpid returned %d: %m", rc);
	retval = PAM_AUTH_ERR;
      } else {
	retval = WEXITSTATUS(retval);
	if (retval != PAM_AUTHINFO_UNAVAIL) {
          rc = pam_modutil_read(fds[0], buf, sizeof(buf) - 1);
	  if(rc > 0) {
	      buf[rc] = '\0';
	      if (sscanf(buf,"%ld:%ld:%ld:%ld:%ld:%ld",
		     &spwd.sp_lstchg, /* last password change */
		     &spwd.sp_min, /* days until change allowed. */
		     &spwd.sp_max, /* days before change required */
		     &spwd.sp_warn, /* days warning for expiration */
		     &spwd.sp_inact, /* days before account inactive */
		     &spwd.sp_expire) /* date when account expires */ != 6 ) retval = PAM_AUTH_ERR;
	    }
	  else {
	    pam_syslog(pamh, LOG_ERR, " ERROR %d: %m", rc); retval = PAM_AUTH_ERR;
	  }
	}
      }
    } else {
      pam_syslog(pamh, LOG_ERR, "Fork failed: %m");
      D(("fork failed"));
      retval = PAM_AUTH_ERR;
    }
    close(fds[0]);
  }
  if (sighandler != NULL) {
    (void) signal(SIGCHLD, sighandler);   /* restore old signal handler */
  }
  D(("Returning %d",retval));
  if (retval != PAM_SUCCESS) {
    return NULL;
  }
  return &spwd;
}

#endif


/*
 * PAM framework looks for this entry-point to pass control to the
 * account management module.
 */

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags,
				int argc, const char **argv)
{
	unsigned int ctrl;
	const void *void_uname;
	const char *uname;
	int retval, daysleft;
	time_t curdays;
	struct spwd *spent;
	struct passwd *pwent;
	char buf[256];

	D(("called."));

	ctrl = _set_ctrl(pamh, flags, NULL, argc, argv);

	retval = pam_get_item(pamh, PAM_USER, &void_uname);
	uname = void_uname;
	D(("user = `%s'", uname));
	if (retval != PAM_SUCCESS || uname == NULL) {
		pam_syslog(pamh, LOG_ALERT,
			 "could not identify user (from uid=%d)",
			 getuid());
		return PAM_USER_UNKNOWN;
	}

	pwent = pam_modutil_getpwnam(pamh, uname);
	if (!pwent) {
		pam_syslog(pamh, LOG_ALERT,
			 "could not identify user (from getpwnam(%s))",
			 uname);
		return PAM_USER_UNKNOWN;
	}

	if (!strcmp( pwent->pw_passwd, "*NP*" )) { /* NIS+ */
		uid_t save_euid, save_uid;

		save_euid = geteuid();
		save_uid = getuid();
		if (save_uid == pwent->pw_uid)
			setreuid( save_euid, save_uid );
		else  {
			setreuid( 0, -1 );
			if (setreuid( -1, pwent->pw_uid ) == -1) {
				setreuid( -1, 0 );
				setreuid( 0, -1 );
				if(setreuid( -1, pwent->pw_uid ) == -1)
					return PAM_CRED_INSUFFICIENT;
			}
		}
		spent = pam_modutil_getspnam (pamh, uname);
		if (save_uid == pwent->pw_uid)
			setreuid( save_uid, save_euid );
		else {
			if (setreuid( -1, 0 ) == -1)
			setreuid( save_uid, -1 );
			setreuid( -1, save_euid );
		}

	} else if (_unix_shadowed (pwent))
		spent = pam_modutil_getspnam (pamh, uname);
	else
		return PAM_SUCCESS;

#ifdef WITH_SELINUX
	if (!spent && SELINUX_ENABLED )
	    spent = _unix_run_verify_binary(pamh, ctrl, uname);
#endif

	if (!spent)
		if (on(UNIX_BROKEN_SHADOW,ctrl))
			return PAM_SUCCESS;

	if (!spent)
		return PAM_AUTHINFO_UNAVAIL;	/* Couldn't get username from shadow */

	curdays = time(NULL) / (60 * 60 * 24);
	D(("today is %d, last change %d", curdays, spent->sp_lstchg));
	if ((curdays > spent->sp_expire) && (spent->sp_expire != -1)) {
		pam_syslog(pamh, LOG_NOTICE,
			 "account %s has expired (account expired)",
			 uname);
		_make_remark(pamh, ctrl, PAM_ERROR_MSG,
			     _("Your account has expired; please contact your system administrator"));
		D(("account expired"));
		return PAM_ACCT_EXPIRED;
	}
	if (spent->sp_lstchg == 0) {
		pam_syslog(pamh, LOG_NOTICE,
			 "expired password for user %s (root enforced)",
			 uname);
		_make_remark(pamh, ctrl, PAM_ERROR_MSG,
			     _("You are required to change your password immediately (root enforced)"));
		D(("need a new password"));
		return PAM_NEW_AUTHTOK_REQD;
	}
	if (curdays < spent->sp_lstchg) {
		pam_syslog(pamh, LOG_DEBUG,
			 "account %s has password changed in future",
			 uname);
		return PAM_SUCCESS;
	}
	if ((curdays - spent->sp_lstchg > spent->sp_max)
	    && (curdays - spent->sp_lstchg > spent->sp_inact)
	    && (curdays - spent->sp_lstchg > spent->sp_max + spent->sp_inact)
	    && (spent->sp_max != -1) && (spent->sp_inact != -1)) {
		pam_syslog(pamh, LOG_NOTICE,
		    "account %s has expired (failed to change password)",
		    uname);
		_make_remark(pamh, ctrl, PAM_ERROR_MSG,
			     _("Your account has expired; please contact your system administrator"));
		D(("account expired 2"));
		return PAM_ACCT_EXPIRED;
	}
	if ((curdays - spent->sp_lstchg > spent->sp_max) && (spent->sp_max != -1)) {
		pam_syslog(pamh, LOG_DEBUG,
			 "expired password for user %s (password aged)",
			 uname);
		_make_remark(pamh, ctrl, PAM_ERROR_MSG,
			     _("You are required to change your password immediately (password aged)"));
		D(("need a new password 2"));
		return PAM_NEW_AUTHTOK_REQD;
	}
	if ((curdays - spent->sp_lstchg > spent->sp_max - spent->sp_warn)
	    && (spent->sp_max != -1) && (spent->sp_warn != -1)) {
		daysleft = (spent->sp_lstchg + spent->sp_max) - curdays;
		pam_syslog(pamh, LOG_DEBUG,
			 "password for user %s will expire in %d days",
			 uname, daysleft);
		snprintf(buf, sizeof (buf), _("Warning: your password will expire in %d day%.2s"),
			 daysleft, daysleft == 1 ? "" : "s");
		_make_remark(pamh, ctrl, PAM_TEXT_INFO, buf);
	}

	D(("all done"));

	return PAM_SUCCESS;
}


/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_unix_acct_modstruct = {
    "pam_unix_acct",
    NULL,
    NULL,
    pam_sm_acct_mgmt,
    NULL,
    NULL,
    NULL,
};
#endif
