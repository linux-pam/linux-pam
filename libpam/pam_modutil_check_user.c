#include "pam_modutil_private.h"
#include <security/pam_ext.h>

#include <stdio.h>
#include <string.h>
#include <syslog.h>

int
pam_modutil_check_user_in_passwd(pam_handle_t *pamh,
				 const char *user_name,
				 const char *file_name)
{
	int rc;
	size_t user_len;
	FILE *fp;
	char line[BUFSIZ];

	/* Validate the user name.  */
	if ((user_len = strlen(user_name)) == 0) {
		pam_syslog(pamh, LOG_NOTICE, "user name is not valid");
		return PAM_SERVICE_ERR;
	}

	if (user_len > sizeof(line) - sizeof(":")) {
		pam_syslog(pamh, LOG_NOTICE, "user name is too long");
		return PAM_SERVICE_ERR;
	}

	if (strchr(user_name, ':') != NULL) {
		/*
		 * "root:x" is not a local user name even if the passwd file
		 * contains a line starting with "root:x:".
		 */
		return PAM_PERM_DENIED;
	}

	/* Open the passwd file.  */
	if (file_name == NULL) {
		file_name = "/etc/passwd";
	}
	if ((fp = fopen(file_name, "r")) == NULL) {
		pam_syslog(pamh, LOG_ERR, "error opening %s: %m", file_name);
		return PAM_SERVICE_ERR;
	}

	/*
	 * Scan the file using fgets() instead of fgetpwent_r() because
	 * the latter is not flexible enough in handling long lines
	 * in passwd files.
	 */
	rc = PAM_PERM_DENIED;
	while (fgets(line, sizeof(line), fp) != NULL) {
		size_t line_len;
		const char *str;

		/*
		 * Does this line start with the user name
		 * followed by a colon?
		 */
		if (strncmp(user_name, line, user_len) == 0 &&
		    line[user_len] == ':') {
			rc = PAM_SUCCESS;
			/*
			 * Continue reading the file to avoid timing attacks.
			 */
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

	fclose(fp);
	return rc;
}
