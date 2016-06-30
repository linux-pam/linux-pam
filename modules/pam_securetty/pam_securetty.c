/* pam_securetty module */

#define SECURETTY_FILE "/etc/securetty"
#define TTY_PREFIX     "/dev/"
#define CMDLINE_FILE   "/proc/cmdline"
#define CONSOLEACTIVE_FILE	"/sys/class/tty/console/active"

/*
 * by Elliot Lee <sopwith@redhat.com>, Red Hat Software.
 * July 25, 1996.
 * This code shamelessly ripped from the pam_rootok module.
 * Slight modifications AGM. 1996/12/3
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <pwd.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define PAM_DEBUG_ARG       0x0001
#define PAM_NOCONSOLE_ARG   0x0002

static int
_pam_parse (const pam_handle_t *pamh, int argc, const char **argv)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
        else if (!strcmp(*argv, "noconsole"))
            ctrl |= PAM_NOCONSOLE_ARG;
	else {
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
	}
    }

    return ctrl;
}

static int
securetty_perform_check (pam_handle_t *pamh, int ctrl,
			 const char *function_name)
{
    int retval = PAM_AUTH_ERR;
    const char *username;
    const char *uttyname;
    const void *void_uttyname;
    char ttyfileline[256];
    char ptname[256];
    struct stat ttyfileinfo;
    struct passwd *user_pwd;
    FILE *ttyfile;

    /* log a trail for debugging */
    if (ctrl & PAM_DEBUG_ARG) {
        pam_syslog(pamh, LOG_DEBUG, "pam_securetty called via %s function",
		   function_name);
    }

    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || username == NULL) {
        pam_syslog(pamh, LOG_WARNING, "cannot determine username");
	return (retval == PAM_CONV_AGAIN ? PAM_INCOMPLETE:PAM_SERVICE_ERR);
    }

    user_pwd = pam_modutil_getpwnam(pamh, username);
    if (user_pwd != NULL && user_pwd->pw_uid != 0) {
	/* If the user is not root, securetty's does not apply to them */
	return PAM_SUCCESS;
    }
    /* The user is now either root or an invalid / mistyped username */

    retval = pam_get_item(pamh, PAM_TTY, &void_uttyname);
    uttyname = void_uttyname;
    if (retval != PAM_SUCCESS || uttyname == NULL) {
        pam_syslog (pamh, LOG_ERR, "cannot determine user's tty");
	return PAM_SERVICE_ERR;
    }

    /* The PAM_TTY item may be prefixed with "/dev/" - skip that */
    if (strncmp(TTY_PREFIX, uttyname, sizeof(TTY_PREFIX)-1) == 0) {
	uttyname += sizeof(TTY_PREFIX)-1;
    }

    if (stat(SECURETTY_FILE, &ttyfileinfo)) {
	pam_syslog(pamh, LOG_NOTICE, "Couldn't open %s: %m", SECURETTY_FILE);
	return PAM_SUCCESS; /* for compatibility with old securetty handling,
			       this needs to succeed.  But we still log the
			       error. */
    }

    if ((ttyfileinfo.st_mode & S_IWOTH) || !S_ISREG(ttyfileinfo.st_mode)) {
	/* If the file is world writable or is not a
	   normal file, return error */
	pam_syslog(pamh, LOG_ERR,
		   "%s is either world writable or not a normal file",
		   SECURETTY_FILE);
	return PAM_AUTH_ERR;
    }

    ttyfile = fopen(SECURETTY_FILE,"r");
    if (ttyfile == NULL) { /* Check that we opened it successfully */
	pam_syslog(pamh, LOG_ERR, "Error opening %s: %m", SECURETTY_FILE);
	return PAM_SERVICE_ERR;
    }

    if (isdigit(uttyname[0])) {
	snprintf(ptname, sizeof(ptname), "pts/%s", uttyname);
    } else {
	ptname[0] = '\0';
    }

    retval = 1;

    while ((fgets(ttyfileline, sizeof(ttyfileline)-1, ttyfile) != NULL)
	   && retval) {
	if (ttyfileline[strlen(ttyfileline) - 1] == '\n')
	    ttyfileline[strlen(ttyfileline) - 1] = '\0';

	retval = ( strcmp(ttyfileline, uttyname)
		   && (!ptname[0] || strcmp(ptname, uttyname)) );
    }
    fclose(ttyfile);

    if (retval && !(ctrl & PAM_NOCONSOLE_ARG)) {
        FILE *cmdlinefile;

        /* Allow access from the kernel console, if enabled */
        cmdlinefile = fopen(CMDLINE_FILE, "r");

        if (cmdlinefile != NULL) {
            char line[LINE_MAX], *p;

            p = fgets(line, sizeof(line), cmdlinefile);
            fclose(cmdlinefile);

            for (; p; p = strstr(p+1, "console=")) {
                char *e;

                /* Test whether this is a beginning of a word? */
                if (p > line && p[-1] != ' ')
                    continue;

                /* Is this our console? */
                if (strncmp(p + 8, uttyname, strlen(uttyname)))
                    continue;

                /* Is there any garbage after the TTY name? */
                e = p + 8 + strlen(uttyname);
                if (*e == ',' || *e == ' ' || *e == '\n' || *e == 0) {
                    retval = 0;
                    break;
                }
            }
        }
    }
    if (retval && !(ctrl & PAM_NOCONSOLE_ARG)) {
        FILE *consoleactivefile;

        /* Allow access from the active console */
        consoleactivefile = fopen(CONSOLEACTIVE_FILE, "r");

        if (consoleactivefile != NULL) {
            char line[LINE_MAX], *p, *n;

            line[0] = 0;
            p = fgets(line, sizeof(line), consoleactivefile);
            fclose(consoleactivefile);

	    if (p) {
		/* remove the newline character at end */
		if (line[strlen(line)-1] == '\n')
		    line[strlen(line)-1] = 0;

		for (n = p; n != NULL; p = n+1) {
		    if ((n = strchr(p, ' ')) != NULL)
			*n = '\0';

		    if (strcmp(p, uttyname) == 0) {
			retval = 0;
			break;
		    }
		}
	    }
	}
    }

    if (retval) {
	    pam_syslog(pamh, LOG_NOTICE, "access denied: tty '%s' is not secure !",
		     uttyname);

	    retval = PAM_AUTH_ERR;
	    if (user_pwd == NULL) {
		retval = PAM_USER_UNKNOWN;
	    }
    } else {
	if (ctrl & PAM_DEBUG_ARG) {
	    pam_syslog(pamh, LOG_DEBUG, "access allowed for '%s' on '%s'",
		     username, uttyname);
	}
	retval = PAM_SUCCESS;

    }

    return retval;
}

/* --- authentication management functions --- */

int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED, int argc,
			const char **argv)
{
    int ctrl;

    /* parse the arguments */
    ctrl = _pam_parse (pamh, argc, argv);

    return securetty_perform_check(pamh, ctrl, __FUNCTION__);
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

/* --- account management functions --- */

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags UNUSED,
		  int argc, const char **argv)
{
    int ctrl;

    /* parse the arguments */
    ctrl = _pam_parse (pamh, argc, argv);

    /* take the easy route */
    return securetty_perform_check(pamh, ctrl, __FUNCTION__);
}

/* end of module definition */
