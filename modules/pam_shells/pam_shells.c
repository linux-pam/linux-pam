/* pam_shells module */

#define SHELL_FILE "/etc/shells"

/*
 * by Erik Troan <ewt@redhat.com>, Red Hat Software.
 * August 5, 1996.
 * This code shamelessly ripped from the pam_securetty module.
 */

#include "config.h"

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
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

static int perform_check(pam_handle_t *pamh)
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

    pw = pam_modutil_getpwnam(pamh, userName);
    if (!pw) {
	return PAM_AUTH_ERR;		/* user doesn't exist */
    }
    userShell = pw->pw_shell;

    if (stat(SHELL_FILE,&sb)) {
	pam_syslog(pamh, LOG_ERR, "Cannot stat %s: %m", SHELL_FILE);
	return PAM_AUTH_ERR;		/* must have /etc/shells */
    }

    if ((sb.st_mode & S_IWOTH) || !S_ISREG(sb.st_mode)) {
	pam_syslog(pamh, LOG_ERR,
		   "%s is either world writable or not a normal file",
		   SHELL_FILE);
	return PAM_AUTH_ERR;
    }

    shellFile = fopen(SHELL_FILE,"r");
    if (shellFile == NULL) {       /* Check that we opened it successfully */
	pam_syslog(pamh, LOG_ERR, "Error opening %s: %m", SHELL_FILE);
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
int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		        int argc UNUSED, const char **argv UNUSED)
{
    return perform_check(pamh);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
		   int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

/* --- account management functions (only) --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
    return perform_check(pamh);
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
