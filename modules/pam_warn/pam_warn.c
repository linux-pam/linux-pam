/* pam_warn module */

/*
 * $Id$
 *
 * Written by Andrew Morgan <morgan@linux.kernel.org> 1996/3/11
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* some syslogging */

#define OBTAIN(item, value, default_value)  do {                \
     (void) pam_get_item(pamh, item, &value);                   \
     value = value ? value : default_value ;                    \
} while (0)

static void log_items(pam_handle_t *pamh, const char *function)
{
     const void *service=NULL, *user=NULL, *terminal=NULL,
	 *rhost=NULL, *ruser=NULL;

     OBTAIN(PAM_SERVICE, service, "<unknown>");
     OBTAIN(PAM_TTY, terminal, "<unknown>");
     OBTAIN(PAM_USER, user, "<unknown>");
     OBTAIN(PAM_RUSER, ruser, "<unknown>");
     OBTAIN(PAM_RHOST, rhost, "<unknown>");

     pam_syslog(pamh, LOG_NOTICE,
		"function=[%s] service=[%s] terminal=[%s] user=[%s]"
		" ruser=[%s] rhost=[%s]\n", function,
		(const char *) service, (const char *) terminal,
		(const char *) user, (const char *) ruser,
		(const char *) rhost);
}

/* --- authentication management functions (only) --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
			int argc UNUSED, const char **argv UNUSED)
{
    log_items(pamh, __FUNCTION__);
    return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags UNUSED,
		   int argc UNUSED, const char **argv UNUSED)
{
    log_items(pamh, __FUNCTION__);
    return PAM_IGNORE;
}

/* password updating functions */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
    log_items(pamh, __FUNCTION__);
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		 int argc UNUSED, const char **argv UNUSED)
{
    log_items(pamh, __FUNCTION__);
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags UNUSED,
		    int argc UNUSED, const char **argv UNUSED)
{
    log_items(pamh, __FUNCTION__);
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
    log_items(pamh, __FUNCTION__);
    return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_warn_modstruct = {
    "pam_warn",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok,
};

#endif

/* end of module definition */
