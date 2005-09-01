/* pam_ftp module */

/*
 * $Id$
 *
 * Written by Andrew Morgan <morgan@linux.kernel.org> 1996/3/11
 *
 */

#define PLEASE_ENTER_PASSWORD "Password required for %s."
#define GUEST_LOGIN_PROMPT "Guest login ok, " \
"send your complete e-mail address as password."

/* the following is a password that "can't be correct" */
#define BLOCK_PASSWORD "\177BAD PASSWPRD\177"

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

/* some syslogging */

static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("PAM-ftp", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

/* argument parsing */

#define PAM_DEBUG_ARG       01
#define PAM_IGNORE_EMAIL    02
#define PAM_NO_ANON         04

static int _pam_parse(int argc, const char **argv, char **users)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else if (!strncmp(*argv,"users=",6)) {
	    *users = x_strdup(6+*argv);
	    if (*users == NULL) {
		ctrl |= PAM_NO_ANON;
		_pam_log(LOG_CRIT, "failed to duplicate user list - anon off");
	    }
	} else if (!strcmp(*argv,"ignore")) {
	    ctrl |= PAM_IGNORE_EMAIL;
	} else {
	    _pam_log(LOG_ERR,"pam_parse: unknown option; %s",*argv);
	}
    }

    return ctrl;
}

/*
 * check if name is in list or default list. place users name in *_user
 * return 1 if listed 0 if not.
 */

static int lookup(const char *name, char *list, const char **_user)
{
    int anon = 0;

    *_user = name;                 /* this is the default */
    if (list) {
	const char *l;
	char *x;

	x = list;
	while ((l = strtok(x, ","))) {
	    x = NULL;
	    if (!strcmp(name, l)) {
		*_user = list;
		anon = 1;
	    }
	}
    } else {
#define MAX_L 2
	static const char *l[MAX_L] = { "ftp", "anonymous" };
	int i;

	for (i=0; i<MAX_L; ++i) {
	    if (!strcmp(l[i], name)) {
		*_user = l[0];
		anon = 1;
		break;
	    }
	}
    }

    return anon;
}

/* --- authentication management functions (only) --- */

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    int retval, anon=0, ctrl;
    const char *user;
    char *users=NULL;

    /*
     * this module checks if the user name is ftp or annonymous. If
     * this is the case, it can set the PAM_RUSER to the entered email
     * address and SUCCEEDS, otherwise it FAILS.
     */

    ctrl = _pam_parse(argc, argv, &users);

    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS || user == NULL) {
	_pam_log(LOG_ERR, "no user specified");
	return PAM_USER_UNKNOWN;
    }

    if (!(ctrl & PAM_NO_ANON)) {
	anon = lookup(user, users, &user);
    }

    if (anon) {
	retval = pam_set_item(pamh, PAM_USER, (const void *)user);
	if (retval != PAM_SUCCESS || user == NULL) {
	    _pam_log(LOG_ERR, "user resetting failed");
	    return PAM_USER_UNKNOWN;
	}
    }

    /*
     * OK. we require an email address for user or the user's password.
     * - build conversation and get their input.
     */

    {
	char *resp = NULL;
	const char *token;

	if (!anon)
	  retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &resp,
			       PLEASE_ENTER_PASSWORD, user);
	else
	  retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &resp,
			       GUEST_LOGIN_PROMPT);

	if (retval != PAM_SUCCESS) {
	    if (resp != NULL)
		_pam_drop (resp);
	    return ((retval == PAM_CONV_AGAIN)
		    ? PAM_INCOMPLETE:PAM_AUTHINFO_UNAVAIL);
	}

	if (anon) {
	  /* XXX: Some effort should be made to verify this email address! */

	    if (!(ctrl & PAM_IGNORE_EMAIL)) {
		token = strtok(resp, "@");
		retval = pam_set_item(pamh, PAM_RUSER, token);

		if ((token) && (retval == PAM_SUCCESS)) {
		    token = strtok(NULL, "@");
		    retval = pam_set_item(pamh, PAM_RHOST, token);
		}
	    }

	    /* we are happy to grant annonymous access to the user */
	    retval = PAM_SUCCESS;

	} else {
	    /*
	     * we have a password so set AUTHTOK
	     */

	    pam_set_item(pamh, PAM_AUTHTOK, resp);

	    /*
	     * this module failed, but the next one might succeed with
	     * this password.
	     */

	    retval = PAM_AUTH_ERR;
	}

	if (resp) {                                      /* clean up */
	    _pam_drop(resp);
	}

	/* success or failure */

	return retval;
    }
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
     return PAM_IGNORE;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_ftp_modstruct = {
     "pam_ftp",
     pam_sm_authenticate,
     pam_sm_setcred,
     NULL,
     NULL,
     NULL,
     NULL,
};

#endif

/* end of module definition */
