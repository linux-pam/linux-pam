/* pam_shells module */

#define SHELL_FILE "/etc/shells"

/*
 * by Erik Troan <ewt@redhat.com>, Red Hat Software.
 * August 5, 1996.
 * This code shamelessly ripped from the pam_securetty module.
 */

#define _BSD_SOURCE

#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

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
    openlog("PAM-shells", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

static int perform_check(pam_handle_t *pamh, int flags)
{
    int retval = PAM_AUTH_ERR;
    const char *userName;
    char *userShell;
    char shellFileLine[256];
    struct stat sb;
    struct passwd * pw;
    FILE * shellFile;

    retval = pam_get_user(pamh, &userName, NULL);
    if (retval != PAM_SUCCESS) {
	return PAM_SERVICE_ERR;
    }

    if (!userName || (userName[0] == '\0')) {

	/* Don't let them use a NULL username... */
	retval = pam_get_user(pamh,&userName,NULL);
        if (retval != PAM_SUCCESS)
	    return PAM_SERVICE_ERR;

	/* It could still be NULL the second time. */
    	if (!userName || (userName[0] == '\0'))
	    return PAM_SERVICE_ERR;
    }

    pw = _pammodutil_getpwnam(pamh, userName);
    if (!pw) {
	return PAM_AUTH_ERR;		/* user doesn't exist */
    }
    userShell = pw->pw_shell;

    if (stat(SHELL_FILE,&sb)) {
	_pam_log(LOG_ERR, "%s cannot be stat'd (it probably does not exist)",
		 SHELL_FILE);
	return PAM_AUTH_ERR;		/* must have /etc/shells */
    }

    if ((sb.st_mode & S_IWOTH) || !S_ISREG(sb.st_mode)) {
	_pam_log(LOG_ERR, "%s is either world writable or not a normal file",
		 SHELL_FILE);
	return PAM_AUTH_ERR;
    }

    shellFile = fopen(SHELL_FILE,"r");
    if (shellFile == NULL) {       /* Check that we opened it successfully */
	_pam_log(LOG_ERR,
		 "Error opening %s", SHELL_FILE);
	return PAM_SERVICE_ERR;
    }

    retval = 1;

    while(retval && (fgets(shellFileLine, 255, shellFile) != NULL)) {
	if (shellFileLine[strlen(shellFileLine) - 1] == '\n')
	    shellFileLine[strlen(shellFileLine) - 1] = '\0';
	retval = strcmp(shellFileLine, userShell);
    }

    fclose(shellFile);

    if (retval) {
	return PAM_AUTH_ERR;
    } else {
	return PAM_SUCCESS;
    }
}

/* --- authentication management functions (only) --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
    return perform_check(pamh, flags);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,const char **argv)
{
     return PAM_SUCCESS;
}

/* --- account management functions (only) --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
    return perform_check(pamh, flags);
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_shells_modstruct = {
     "pam_shells",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     NULL,
};

#endif /* PAM_STATIC */

/* end of module definition */
