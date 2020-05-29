/*
 * pam_shells module
 *
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
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define SHELL_FILE "/etc/shells"

#define DEFAULT_SHELL "/bin/sh"

static int perform_check(pam_handle_t *pamh)
{
    int retval = PAM_AUTH_ERR;
    const char *userName;
    const char *userShell;
    char shellFileLine[256];
    struct stat sb;
    struct passwd * pw;
    FILE * shellFile;

    retval = pam_get_user(pamh, &userName, NULL);
    if (retval != PAM_SUCCESS) {
	return PAM_SERVICE_ERR;
    }

    pw = pam_modutil_getpwnam(pamh, userName);
    if (pw == NULL || pw->pw_shell == NULL) {
	return PAM_AUTH_ERR;		/* user doesn't exist */
    }
    userShell = pw->pw_shell;
    if (userShell[0] == '\0')
	userShell = DEFAULT_SHELL;

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

int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		        int argc UNUSED, const char **argv UNUSED)
{
    return perform_check(pamh);
}

int pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
		   int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SUCCESS;
}

/* --- account management functions (only) --- */

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
    return perform_check(pamh);
}

/* end of module definition */
