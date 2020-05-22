/*
 * pam_localuser module
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include "pam_inline.h"

int
pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
	int i, ret;
	FILE *fp;
	int debug = 0;
	const char *filename = "/etc/passwd";
	char line[BUFSIZ];
	const char* user;
	size_t user_len;

	/* process arguments */
	for(i = 0; i < argc; i++) {
		if(strcmp("debug", argv[i]) == 0) {
			debug = 1;
		}
	}
	for(i = 0; i < argc; i++) {
		const char *str;

		if (strcmp("debug", argv[i]) == 0) {
			/* Already processed.  */
			continue;
		}

		if ((str = pam_str_skip_prefix(argv[i], "file=")) != NULL) {
			filename = str;
			if(debug) {
				pam_syslog (pamh, LOG_DEBUG,
					    "set filename to \"%s\"",
				            filename);
			}
		} else {
			pam_syslog(pamh, LOG_ERR, "unrecognized option: %s",
				   argv[i]);
		}
	}

	/* Obtain the user name.  */
	if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_NOTICE, "cannot determine user name");
		return ret == PAM_CONV_AGAIN ? PAM_INCOMPLETE : ret;
	}

	if ((user_len = strlen(user)) == 0) {
		pam_syslog(pamh, LOG_NOTICE, "user name is not valid");
		return PAM_SERVICE_ERR;
	}

	if (user_len > sizeof(line) - sizeof(":")) {
		pam_syslog(pamh, LOG_NOTICE, "user name is too long");
		return PAM_SERVICE_ERR;
	}

	if (strchr(user, ':') != NULL) {
		/*
		 * "root:x" is not a local user name even if the passwd file
		 * contains a line starting with "root:x:".
		 */
		return PAM_PERM_DENIED;
	}

	/* Open the passwd file.  */
	if ((fp = fopen(filename, "r")) == NULL) {
		pam_syslog (pamh, LOG_ERR, "error opening \"%s\": %m",
			    filename);
		return PAM_SERVICE_ERR;
	}

	/*
	 * Scan the file using fgets() instead of fgetpwent_r() because
	 * the latter is not flexible enough in handling long lines
	 * in passwd files.
	 */
	ret = PAM_PERM_DENIED;
	while (fgets(line, sizeof(line), fp) != NULL) {
		size_t line_len;
		const char *str;

		if(debug) {
			pam_syslog (pamh, LOG_DEBUG, "checking \"%s\"", line);
		}

		/*
		 * Does this line start with the user name
		 * followed by a colon?
		 */
		if (strncmp(user, line, user_len) == 0 &&
		    line[user_len] == ':') {
			ret = PAM_SUCCESS;
			break;
		}

		/* Has a newline been read?  */
		line_len = strlen(line);
		if (line_len < sizeof(line) - 1 ||
		    line[line_len - 1] == '\n') {
			/* Yes, continue with the next line.  */
			continue;
		}

		/* No, read till the end of this line first.  */
		while ((str = fgets(line, sizeof(line), fp)) != NULL) {
			line_len = strlen(line);
			if (line_len == 0 ||
			    line[line_len - 1] == '\n') {
				break;
			}
		}
		if (str == NULL) {
			/* fgets returned NULL, we are done.  */
			break;
		}
		/* Continue with the next line.  */
	}

	/* okay, we're done */
	fclose(fp);
	return ret;
}

int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
	return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}
