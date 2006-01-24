/* pam_permit module */

/*
 * $Id$
 *
 * Written by Andrew Morgan <morgan@kernel.org> 2001/02/04
 *
 */

#define DEFAULT_USER "nobody"

#include "config.h"

#include <stdio.h>

/*
 * This module is intended as a debugging aide for determining how
 * the PAM stack is operating.
 *
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define _PAM_ACTION_UNDEF (-10)
#include "../../libpam/pam_tokens.h"

/* --- authentication management functions --- */

static int state(pam_handle_t *pamh, const char *text)
{
    int retval;

    retval = pam_info (pamh, "%s", text);

    if (retval != PAM_SUCCESS) {
	D(("pam_info failed"));
    }

    return retval;
}

static int parse_args(int retval, const char *event,
		      pam_handle_t *pamh, int argc, const char **argv)
{
    int i;

    for (i=0; i<argc; ++i) {
	int length = strlen(event);
	if (!strncmp(event, argv[i], length) && (argv[i][length] == '=')) {
	    int j;
	    const char *return_string = argv[i] + (length+1);

	    for (j=0; j<_PAM_RETURN_VALUES; ++j) {
		if (!strcmp(return_string, _pam_token_returns[j])) {
		    retval = j;
		    state(pamh, argv[i]);
		    break;
		}
	    }
	    break;
	}
    }

    return retval;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
			int argc, const char **argv)
{
    int retval;
    const char *user=NULL;

    /*
     * authentication requires we know who the user wants to be
     */
    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS) {
	D(("get user returned error: %s", pam_strerror(pamh,retval)));
	return retval;
    }
    if (user == NULL || *user == '\0') {
	D(("username not known"));
	retval = pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
	if (retval != PAM_SUCCESS)
	    return retval;
    }
    user = NULL;                                            /* clean up */

    retval = parse_args(PAM_SUCCESS, "auth", pamh, argc, argv);

    return retval;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags UNUSED,
		   int argc, const char **argv)
{
    return parse_args(PAM_SUCCESS, "cred", pamh, argc, argv);
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    return parse_args(PAM_SUCCESS, "acct", pamh, argc, argv);
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    if (flags & PAM_PRELIM_CHECK) {
	return parse_args(PAM_SUCCESS, "prechauthtok", pamh, argc, argv);
    } else {
	return parse_args(PAM_SUCCESS, "chauthtok", pamh, argc, argv);
    }
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags UNUSED,
			int argc, const char **argv)
{
    return parse_args(PAM_SUCCESS, "open_session", pamh, argc, argv);
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags UNUSED,
			 int argc, const char **argv)
{
    return parse_args(PAM_SUCCESS, "close_session", pamh, argc, argv);
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_debug_modstruct = {
    "pam_debug",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif
