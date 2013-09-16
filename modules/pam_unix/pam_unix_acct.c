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
#include <sys/resource.h>
#include <syslog.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>		/* for time() */
#include <errno.h>
#include <sys/wait.h>

#include <security/_pam_macros.h>

/* indicate that the following groups are defined */

#ifdef PAM_STATIC
# include "pam_unix_static.h"
#else
# define PAM_SM_ACCOUNT
#endif

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "support.h"
#include "passverify.h"

int _unix_run_verify_binary(pam_handle_t *pamh, unsigned int ctrl,
	const char *user, int *daysleft)
{
  int retval=0, child, fds[2];
  struct sigaction newsa, oldsa;
  D(("running verify_binary"));

  /* create a pipe for the messages */
  if (pipe(fds) != 0) {
    D(("could not make pipe"));
    pam_syslog(pamh, LOG_ERR, "Could not make pipe: %m");
    return PAM_AUTH_ERR;
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
     memset(&newsa, '\0', sizeof(newsa));
     newsa.sa_handler = SIG_DFL;
     sigaction(SIGCHLD, &newsa, &oldsa);
  }

  /* fork */
  child = fork();
  if (child == 0) {
    int i=0;
    struct rlimit rlim;
    static char *envp[] = { NULL };
    char *args[] = { NULL, NULL, NULL, NULL };

    /* reopen stdout as pipe */
    dup2(fds[1], STDOUT_FILENO);

    /* XXX - should really tidy up PAM here too */

    if (getrlimit(RLIMIT_NOFILE,&rlim)==0) {
      if (rlim.rlim_max >= MAX_FD_NO)
        rlim.rlim_max = MAX_FD_NO;
      for (i=0; i < (int)rlim.rlim_max; i++) {
	if (i != STDOUT_FILENO) {
	  close(i);
	}
      }
    }

    if (geteuid() == 0) {
      /* must set the real uid to 0 so the helper will not error
         out if pam is called from setuid binary (su, sudo...) */
      if (setuid(0) == -1) {
          pam_syslog(pamh, LOG_ERR, "setuid failed: %m");
          printf("-1\n");
          fflush(stdout);
          _exit(PAM_AUTHINFO_UNAVAIL);
      }
    }

    /* exec binary helper */
    args[0] = x_strdup(CHKPWD_HELPER);
    args[1] = x_strdup(user);
    args[2] = x_strdup("chkexpiry");

    execve(CHKPWD_HELPER, args, envp);

    pam_syslog(pamh, LOG_ERR, "helper binary execve failed: %m");
    /* should not get here: exit with error */
    D(("helper binary is not available"));
    printf("-1\n");
    fflush(stdout);
    _exit(PAM_AUTHINFO_UNAVAIL);
  } else {
    close(fds[1]);
    if (child > 0) {
      char buf[32];
      int rc=0;
      /* wait for helper to complete: */
      while ((rc=waitpid(child, &retval, 0)) < 0 && errno == EINTR);
      if (rc<0) {
	pam_syslog(pamh, LOG_ERR, "unix_chkpwd waitpid returned %d: %m", rc);
	retval = PAM_AUTH_ERR;
      } else if (!WIFEXITED(retval)) {
        pam_syslog(pamh, LOG_ERR, "unix_chkpwd abnormal exit: %d", retval);
        retval = PAM_AUTH_ERR;
      } else {
	retval = WEXITSTATUS(retval);
        rc = pam_modutil_read(fds[0], buf, sizeof(buf) - 1);
	if(rc > 0) {
	      buf[rc] = '\0';
	      if (sscanf(buf,"%d", daysleft) != 1 )
	        retval = PAM_AUTH_ERR;
	    }
	else {
	    pam_syslog(pamh, LOG_ERR, "read unix_chkpwd output error %d: %m", rc);
	    retval = PAM_AUTH_ERR;
	  }
      }
    } else {
      pam_syslog(pamh, LOG_ERR, "Fork failed: %m");
      D(("fork failed"));
      retval = PAM_AUTH_ERR;
    }
    close(fds[0]);
  }

  if (off(UNIX_NOREAP, ctrl)) {
        sigaction(SIGCHLD, &oldsa, NULL);   /* restore old signal handler */
  }

  D(("Returning %d",retval));
  return retval;
}

/*
 * PAM framework looks for this entry-point to pass control to the
 * account management module.
 */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	unsigned int ctrl;
	const void *void_uname;
	const char *uname;
	int retval, daysleft;
	struct spwd *spent;
	struct passwd *pwent;
	char buf[256];

	D(("called."));

	ctrl = _set_ctrl(pamh, flags, NULL, NULL, NULL, argc, argv);

	retval = pam_get_item(pamh, PAM_USER, &void_uname);
	uname = void_uname;
	D(("user = `%s'", uname));
	if (retval != PAM_SUCCESS || uname == NULL) {
		pam_syslog(pamh, LOG_ALERT,
			 "could not identify user (from uid=%lu)",
			 (unsigned long int)getuid());
		return PAM_USER_UNKNOWN;
	}

	retval = get_account_info(pamh, uname, &pwent, &spent);
	if (retval == PAM_USER_UNKNOWN) {
		pam_syslog(pamh, LOG_ALERT,
			 "could not identify user (from getpwnam(%s))",
			 uname);
		return retval;
	}

	if (retval == PAM_SUCCESS && spent == NULL)
		return PAM_SUCCESS;

	if (retval == PAM_UNIX_RUN_HELPER) {
		retval = _unix_run_verify_binary(pamh, ctrl, uname, &daysleft);
		if (retval == PAM_AUTHINFO_UNAVAIL &&
			on(UNIX_BROKEN_SHADOW, ctrl))
			return PAM_SUCCESS;
	} else if (retval != PAM_SUCCESS) {
		if (on(UNIX_BROKEN_SHADOW,ctrl))
			return PAM_SUCCESS;
		else
			return retval;
	} else
		retval = check_shadow_expiry(pamh, spent, &daysleft);

	switch (retval) {
	case PAM_ACCT_EXPIRED:
		pam_syslog(pamh, LOG_NOTICE,
			"account %s has expired (account expired)",
			uname);
		_make_remark(pamh, ctrl, PAM_ERROR_MSG,
			_("Your account has expired; please contact your system administrator"));
		break;
	case PAM_NEW_AUTHTOK_REQD:
		if (daysleft == 0) {
			pam_syslog(pamh, LOG_NOTICE,
				"expired password for user %s (root enforced)",
				uname);
			_make_remark(pamh, ctrl, PAM_ERROR_MSG,
				_("You are required to change your password immediately (root enforced)"));
		} else {
			pam_syslog(pamh, LOG_DEBUG,
				"expired password for user %s (password aged)",
				uname);
			_make_remark(pamh, ctrl, PAM_ERROR_MSG,
				_("You are required to change your password immediately (password aged)"));
		}
		break;
	case PAM_AUTHTOK_EXPIRED:
		pam_syslog(pamh, LOG_NOTICE,
			"account %s has expired (failed to change password)",
			uname);
		_make_remark(pamh, ctrl, PAM_ERROR_MSG,
			_("Your account has expired; please contact your system administrator"));
		break;
	case PAM_AUTHTOK_ERR:
		retval = PAM_SUCCESS;
		/* fallthrough */
	case PAM_SUCCESS:
		if (daysleft >= 0) {
			pam_syslog(pamh, LOG_DEBUG,
				"password for user %s will expire in %d days",
				uname, daysleft);
#if defined HAVE_DNGETTEXT && defined ENABLE_NLS
			snprintf (buf, sizeof (buf),
				dngettext(PACKAGE,
				  "Warning: your password will expire in %d day",
				  "Warning: your password will expire in %d days",
				  daysleft),
				daysleft);
#else
			if (daysleft == 1)
			    snprintf(buf, sizeof (buf),
				_("Warning: your password will expire in %d day"),
				daysleft);
			else
			    snprintf(buf, sizeof (buf),
			    /* TRANSLATORS: only used if dngettext is not supported */
				_("Warning: your password will expire in %d days"),
				daysleft);
#endif
			_make_remark(pamh, ctrl, PAM_TEXT_INFO, buf);
		}
	}

	D(("all done"));

	return retval;
}
