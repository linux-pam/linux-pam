/* pam_deny module */

/*
 * $Id$
 *
 * Written by Andrew Morgan <morgan@parc.power.net> 1996/3/11
 *
 */

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#include "config.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>

/* --- authentication management functions --- */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh UNUSED, int flags UNUSED,
		    int argc UNUSED, const char **argv UNUSED)
{
     return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
     return PAM_CRED_ERR;
}

/* --- account management functions --- */

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh UNUSED, int flags UNUSED,
		 int argc UNUSED, const char **argv UNUSED)
{
     return PAM_AUTH_ERR;
}

/* --- password management --- */

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh UNUSED, int flags UNUSED,
		 int argc UNUSED, const char **argv UNUSED)
{
     return PAM_AUTHTOK_ERR;
}

/* --- session management --- */

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
		    int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SESSION_ERR;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
     return PAM_SESSION_ERR;
}

/* end of module definition */

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_deny_modstruct = {
    "pam_deny",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};
#endif
