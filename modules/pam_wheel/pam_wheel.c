/* pam_wheel module */

/*
 * Written by Cristian Gafton <gafton@redhat.com> 1996/09/10
 * See the end of the file for Copyright Information
 *
 *
 * 1.2 - added 'deny' and 'group=' options
 * 1.1 - added 'trust' option
 * 1.0 - the code is working for at least another person, so... :-)
 * 0.1 - use vsyslog instead of vfprintf/syslog in _pam_log
 *     - return PAM_IGNORE on success (take care of sloppy sysadmins..)
 *     - use pam_get_user instead of pam_get_item(...,PAM_USER,...)
 *     - a new arg use_uid to auth the current uid instead of the
 *       initial (logged in) one.
 * 0.0 - first release
 *
 * TODO:
 *  - try to use make_remark from pam_unix/support.c
 *  - consider returning on failure PAM_FAIL_NOW if the user is not
 *    a wheel member.
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/_pam_modutil.h>

/* some syslogging */

static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("PAM-Wheel", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

/* checks if a user is on a list of members of the GID 0 group */

static int is_on_list(char * const *list, const char *member)
{
    while (list && *list) {
        if (strcmp(*list, member) == 0)
            return 1;
        list++;
    }
    return 0;
}

/* argument parsing */

#define PAM_DEBUG_ARG       0x0001
#define PAM_USE_UID_ARG     0x0002
#define PAM_TRUST_ARG       0x0004
#define PAM_DENY_ARG        0x0010
#define PAM_ROOT_ONLY_ARG   0x0020

static int _pam_parse(int argc, const char **argv, char *use_group,
		      size_t group_length)
{
     int ctrl=0;

     memset(use_group, '\0', group_length);

     /* step through arguments */
     for (ctrl=0; argc-- > 0; ++argv) {

          /* generic options */

          if (!strcmp(*argv,"debug"))
               ctrl |= PAM_DEBUG_ARG;
          else if (!strcmp(*argv,"use_uid"))
               ctrl |= PAM_USE_UID_ARG;
          else if (!strcmp(*argv,"trust"))
               ctrl |= PAM_TRUST_ARG;
          else if (!strcmp(*argv,"deny"))
               ctrl |= PAM_DENY_ARG;
          else if (!strcmp(*argv,"root_only"))
               ctrl |= PAM_ROOT_ONLY_ARG;
          else if (!strncmp(*argv,"group=",6))
	       strncpy(use_group,*argv+6,group_length-1);
          else {
               _pam_log(LOG_ERR,"pam_parse: unknown option; %s",*argv);
          }
     }

     return ctrl;
}

static int perform_check(pam_handle_t *pamh, int flags, int ctrl,
			 const char *use_group)
{
    const char *username = NULL;
    const char *fromsu;
    struct passwd *pwd, *tpwd = NULL;
    struct group *grp;
    int retval = PAM_AUTH_ERR;

    retval = pam_get_user(pamh, &username, NULL);
    if ((retval != PAM_SUCCESS) || (!username)) {
        if (ctrl & PAM_DEBUG_ARG) {
            _pam_log(LOG_DEBUG,"can not get the username");
	}
        return PAM_SERVICE_ERR;
    }

    pwd = _pammodutil_getpwnam (pamh, username);
    if (!pwd) {
        if (ctrl & PAM_DEBUG_ARG) {
            _pam_log(LOG_NOTICE,"unknown user %s",username);
        }
        return PAM_USER_UNKNOWN;
    }
    if (ctrl & PAM_ROOT_ONLY_ARG) {
	/* su to a non uid 0 account ? */
        if (pwd->pw_uid != 0) {
            return PAM_IGNORE;
        }
    }
     
    if (ctrl & PAM_USE_UID_ARG) {
	tpwd = _pammodutil_getpwuid (pamh, getuid());
	if (!tpwd) {
	    if (ctrl & PAM_DEBUG_ARG) {
                _pam_log(LOG_NOTICE, "who is running me ?!");
	    }
	    return PAM_SERVICE_ERR;
	}
	fromsu = tpwd->pw_name;
    } else {
	fromsu = _pammodutil_getlogin(pamh);
	if (fromsu) {
	    tpwd = _pammodutil_getpwnam (pamh, fromsu);
	}
	if (!fromsu || !tpwd) {
	    if (ctrl & PAM_DEBUG_ARG) {
		_pam_log(LOG_NOTICE, "who is running me ?!");
	    }
	    return PAM_SERVICE_ERR;
	}
    }

    /*
     * At this point fromsu = username-of-invoker; tpwd = pwd ptr for fromsu
     */
     
    if (!use_group[0]) {
	if ((grp = _pammodutil_getgrnam (pamh, "wheel")) == NULL) {
	    grp = _pammodutil_getgrgid (pamh, 0);
	}
    } else {
	grp = _pammodutil_getgrnam (pamh, use_group);
    }

    if (!grp || (!grp->gr_mem && (tpwd->pw_gid != grp->gr_gid))) {
	if (ctrl & PAM_DEBUG_ARG) {
	    if (!use_group[0]) {
		_pam_log(LOG_NOTICE,"no members in a GID 0 group");
	    } else {
                _pam_log(LOG_NOTICE,"no members in '%s' group", use_group);
	    }
	}
	if (ctrl & PAM_DENY_ARG) {
	    /* if this was meant to deny access to the members
	     * of this group and the group does not exist, allow
	     * access
	     */
	    return PAM_IGNORE;
	} else {
	    return PAM_AUTH_ERR;
	}
    }
     
    /*
     * test if the user is a member of the group, or if the
     * user has the "wheel" (sic) group as its primary group.
     */

    if (is_on_list(grp->gr_mem, fromsu) || (tpwd->pw_gid == grp->gr_gid)) {

	if (ctrl & PAM_DENY_ARG) {
	    retval = PAM_PERM_DENIED;

	} else if (ctrl & PAM_TRUST_ARG) {
	    retval = PAM_SUCCESS;        /* this can be a sufficient check */

	} else {
	    retval = PAM_IGNORE;
	}

    } else {

	if (ctrl & PAM_DENY_ARG) {

	    if (ctrl & PAM_TRUST_ARG) {
		retval = PAM_SUCCESS;    /* this can be a sufficient check */
	    } else {
		retval = PAM_IGNORE;
	    }

	} else {
	    retval = PAM_PERM_DENIED;
	}
    }

    if (ctrl & PAM_DEBUG_ARG) {
	if (retval == PAM_IGNORE) {
	    _pam_log(LOG_NOTICE, "Ignoring access request '%s' for '%s'",
		     fromsu, username);
	} else {
	    _pam_log(LOG_NOTICE, "Access %s to '%s' for '%s'",
		     (retval != PAM_SUCCESS) ? "denied":"granted",
		     fromsu, username);
	}
    }

    return retval;
}

/* --- authentication management functions --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
    char use_group[BUFSIZ];
    int ctrl;

    ctrl = _pam_parse(argc, argv, use_group, sizeof(use_group));

    return perform_check(pamh, flags, ctrl, use_group);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
		   ,const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
    char use_group[BUFSIZ];
    int ctrl;

    ctrl = _pam_parse(argc, argv, use_group, sizeof(use_group));

    return perform_check(pamh, flags, ctrl, use_group);
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_wheel_modstruct = {
    "pam_wheel",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif /* PAM_STATIC */

/*
 * Copyright (c) Cristian Gafton <gafton@redhat.com>, 1996, 1997
 *                                              All rights reserved
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
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
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
