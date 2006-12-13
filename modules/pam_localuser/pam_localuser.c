/*
 * Copyright 2001, 2004 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define MODULE_NAME "pam_localuser"

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
	int i, ret = PAM_SUCCESS;
	FILE *fp;
	int debug = 0;
	const char *filename = "/etc/passwd";
	char line[LINE_MAX], name[LINE_MAX];
	const char* user;

	/* process arguments */
	for(i = 0; i < argc; i++) {
		if(strcmp("debug", argv[i]) == 0) {
			debug = 1;
		}
	}
	for(i = 0; i < argc; i++) {
		if(strncmp("file=", argv[i], 5) == 0) {
			filename = argv[i] + 5;
			if(debug) {
				pam_syslog (pamh, LOG_DEBUG,
					    "set filename to \"%s\"",
				            filename);
			}
		}
	}

	/* open the file */
	fp = fopen(filename, "r");
	if(fp == NULL) {
		pam_syslog (pamh, LOG_ERR, "error opening \"%s\": %m",
			    filename);
		return PAM_SYSTEM_ERR;
	}

	if(pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		pam_syslog (pamh, LOG_ERR, "user name not specified yet");
		fclose(fp);
		return PAM_SYSTEM_ERR;
	}

	if ((user == NULL) || (strlen(user) == 0)) {
		pam_syslog (pamh, LOG_ERR, "user name not valid");
		fclose(fp);
		return PAM_SYSTEM_ERR;
	}

	/* scan the file, using fgets() instead of fgetpwent() because i
	 * don't want to mess with applications which call fgetpwent() */
	ret = PAM_PERM_DENIED;
	snprintf(name, sizeof(name), "%s:", user);
	i = strlen(name);
	while(fgets(line, sizeof(line), fp) != NULL) {
		if(debug) {
			pam_syslog (pamh, LOG_DEBUG, "checking \"%s\"", line);
		}
		if(strncmp(name, line, i) == 0) {
			ret = PAM_SUCCESS;
			break;
		}
	}

	/* okay, we're done */
	fclose(fp);
	return ret;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_localuser_modstruct = {
     "pam_localuser",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     pam_sm_open_session,
     pam_sm_close_session,
     pam_sm_chauthtok
};

#endif
