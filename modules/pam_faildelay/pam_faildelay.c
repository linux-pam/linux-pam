/* pam_faildelay module */

/*
 * Allows an admin to set the delay on failure per-application.
 * Provides "auth" interface only.
 *
 * Use by putting something like this in the relevant pam config:
 * auth    required        pam_faildelay.so delay=[microseconds]
 *
 * eg:
 * auth    required        pam_faildelay.so delay=10000000
 * will set the delay on failure to 10 seconds.
 *
 *
 * Based on pam_rootok and parts of pam_unix both by Andrew Morgan
 *  <morgan@linux.kernel.org>
 *
 * Portions Copyright (c) 2005 Darren Tucker <dtucker at zip com au>.
 *
 * Redistribution and use in source and binary forms of, with
 * or without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain any existing copyright
 *    notice, and this entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 *
 * 2. Redistributions in binary form must reproduce all prior and current
 *    copyright notices, this list of conditions, and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. The name of any author may not be used to endorse or promote
 *    products derived from this software without their specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU General Public License, in which case the provisions of the GNU
 * GPL are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential conflict between the GNU GPL and the
 * restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>


#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>


/* --- authentication management functions (only) --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
			int argc, const char **argv)
{
    int i, debug_flag = 0;
    long int delay = 0;

    /* step through arguments */
    for (i = 0; i < argc; i++) {
	if (sscanf(argv[i], "delay=%ld", &delay) == 1) {
	  /* sscanf did already everything necessary */
	} else if (strcmp (argv[i], "debug") == 0)
	  debug_flag = 1;
	else
	  pam_syslog (pamh, LOG_ERR, "unknown option; %s", argv[i]);
    }

    if (debug_flag)
      pam_syslog (pamh, LOG_DEBUG, "setting fail delay to %ld", delay);

    i = pam_fail_delay(pamh, delay);
    if (i == PAM_SUCCESS)
      return PAM_IGNORE;
    else
      return i;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
		   int argc UNUSED, const char **argv UNUSED)
{
    return PAM_IGNORE;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_rootok_modstruct = {
    "pam_faildelay",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif

/* end of module definition */
