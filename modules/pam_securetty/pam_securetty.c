/* pam_securetty module */

#define SECURETTY_FILE "/etc/securetty"
#define TTY_PREFIX     "/dev/"

/*
 * by Elliot Lee <sopwith@redhat.com>, Red Hat Software.
 * July 25, 1996.
 * This code shamelessly ripped from the pam_rootok module.
 * Slight modifications AGM. 1996/12/3
 */

#define _GNU_SOURCE

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
    openlog("PAM-securetty", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

/* argument parsing */

#define PAM_DEBUG_ARG       0x0001

static int _pam_parse(int argc, const char **argv)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else {
	    _pam_log(LOG_ERR,"pam_parse: unknown option; %s",*argv);
	}
    }

    return ctrl;
}

static int securetty_perform_check(pam_handle_t *pamh, int flags, int ctrl,
				   const char *function_name)
{
    int retval = PAM_AUTH_ERR;
    const char *username;
    char *uttyname;
    char ttyfileline[256];
    char ptname[256];
    struct stat ttyfileinfo;
    struct passwd *user_pwd;
    FILE *ttyfile;

    /* log a trail for debugging */
    if (ctrl & PAM_DEBUG_ARG) {
	_pam_log(LOG_DEBUG, "pam_securetty called via %s function",
		 function_name);
    }

    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || username == NULL) {
	if (ctrl & PAM_DEBUG_ARG) {
            _pam_log(LOG_WARNING, "cannot determine username");
	}
	return (retval == PAM_CONV_AGAIN ? PAM_INCOMPLETE:PAM_SERVICE_ERR);
    }

    user_pwd = _pammodutil_getpwnam(pamh, username);
    if (user_pwd == NULL) {
	return PAM_IGNORE;
    } else if (user_pwd->pw_uid != 0) { /* If the user is not root,
					   securetty's does not apply
					   to them */
	return PAM_SUCCESS;
    }

    retval = pam_get_item(pamh, PAM_TTY, (const void **)&uttyname);
    if (retval != PAM_SUCCESS || uttyname == NULL) {
        if (ctrl & PAM_DEBUG_ARG) {
            _pam_log(LOG_WARNING, "cannot determine user's tty");
	}
	return PAM_SERVICE_ERR;
    }

    /* The PAM_TTY item may be prefixed with "/dev/" - skip that */
    if (strncmp(TTY_PREFIX, uttyname, sizeof(TTY_PREFIX)-1) == 0) {
	uttyname += sizeof(TTY_PREFIX)-1;
    }

    if (stat(SECURETTY_FILE, &ttyfileinfo)) {
	_pam_log(LOG_NOTICE, "Couldn't open " SECURETTY_FILE);
	return PAM_SUCCESS; /* for compatibility with old securetty handling,
			       this needs to succeed.  But we still log the
			       error. */
    }

    if ((ttyfileinfo.st_mode & S_IWOTH) || !S_ISREG(ttyfileinfo.st_mode)) {
	/* If the file is world writable or is not a
	   normal file, return error */
	_pam_log(LOG_ERR, SECURETTY_FILE
		 " is either world writable or not a normal file");
	return PAM_AUTH_ERR;
    }

    ttyfile = fopen(SECURETTY_FILE,"r");
    if (ttyfile == NULL) { /* Check that we opened it successfully */
	_pam_log(LOG_ERR,
		 "Error opening " SECURETTY_FILE);
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

    if (retval) {
	    _pam_log(LOG_WARNING, "access denied: tty '%s' is not secure !",
		     uttyname);

	    retval = PAM_AUTH_ERR;
    } else {
	if ((retval == PAM_SUCCESS) && (ctrl & PAM_DEBUG_ARG)) {
	    _pam_log(LOG_DEBUG, "access allowed for '%s' on '%s'",
		     username, uttyname);
	}
	retval = PAM_SUCCESS;

    }

    return retval;
}

/* --- authentication management functions --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
    int ctrl;

    /* parse the arguments */
    ctrl = _pam_parse(argc, argv);

    return securetty_perform_check(pamh, flags, ctrl, __FUNCTION__);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
    int ctrl;

    /* parse the arguments */
    ctrl = _pam_parse(argc, argv);

    /* take the easy route */
    return securetty_perform_check(pamh, flags, ctrl, __FUNCTION__);
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_securetty_modstruct = {
     "pam_securetty",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     NULL,
};

#endif /* PAM_STATIC */

/* end of module definition */
