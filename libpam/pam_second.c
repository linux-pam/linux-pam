/*
 * pam_second.c -- PAM secondary authentication
 * (based on XSSO draft spec of March 1997)
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/06/20 22:11:20  agmorgan
 * Initial revision
 *
 * Revision 1.1.1.1  1998/07/12 05:17:15  morgan
 * Linux PAM sources pre-0.66
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "pam_private.h"

/* p 42 */

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
