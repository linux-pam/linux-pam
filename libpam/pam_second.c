/*
 * pam_second.c -- PAM secondary authentication
 * (based on XSSO draft spec of March 1997)
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "pam_private.h"

/* p 42 */

/* XXX - there are actually no plans to support this function. It does
   not appear to be very well defined */

int pam_authenticate_secondary(pam_handle_t *pamh,
			       char *target_username,
			       char *target_module_type,
			       char *target_authn_domain,
			       char *target_supp_data,
			       unsigned char *target_module_authtok,
			       int flags);

int pam_authenticate_secondary(pam_handle_t *pamh,
			       char *target_username,
			       char *target_module_type,
			       char *target_authn_domain,
			       char *target_supp_data,
			       unsigned char *target_module_authtok,
			       int flags)
{
    int retval=PAM_SYSTEM_ERR;

    D(("called"));

    _pam_start_timer(pamh);    /* we try to make the time for a failure
				  independent of the time it takes to
				  fail */

    IF_NO_PAMH("pam_authenticate_secondary",pamh,PAM_SYSTEM_ERR);

    _pam_await_timer(pamh, retval);   /* if unsuccessful then wait now */

    D(("pam_authenticate_secondary exit"));

    return retval;
}
