/*
 * This file implements the following functions:
 *   pam_modutil_search_key:
 *     lookup a value for key in login.defs file or similar key value format
 */

#include "config.h"

#include "pam_private.h"
#include "pam_modutil_private.h"
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define BUF_SIZE 8192

/* lookup a value for key in login.defs file or similar key value format */
char *
pam_modutil_search_key(pam_handle_t *pamh UNUSED,
		       const char *file_name,
		       const char *key)
{
	FILE *fp;
	char *buf = NULL;
	size_t buflen = 0;
	char *retval = NULL;

	fp = fopen(file_name, "r");
	if (NULL == fp)
		return NULL;

	while (!feof(fp)) {
		char *tmp, *cp;
#if defined(HAVE_GETLINE)
		ssize_t n = getline(&buf, &buflen, fp);
#elif defined (HAVE_GETDELIM)
		ssize_t n = getdelim(&buf, &buflen, '\n', fp);
#else
		ssize_t n;

		if (buf == NULL) {
			buflen = BUF_SIZE;
			buf = malloc(buflen);
			if (buf == NULL) {
				fclose(fp);
				return NULL;
			}
		}
		buf[0] = '\0';
		if (fgets(buf, buflen - 1, fp) == NULL)
			break;
		else if (buf != NULL)
			n = strlen(buf);
		else
			n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */
		cp = buf;

		if (n < 1)
			break;
		if (cp[n - 1] == '\n')
			cp[n - 1] = '\0';

		tmp = strchr(cp, '#');  /* remove comments */
		if (tmp)
			*tmp = '\0';
		while (isspace((int)*cp))    /* remove spaces and tabs */
			++cp;
		if (*cp == '\0')        /* ignore empty lines */
			continue;

		tmp = strsep (&cp, " \t=");
		if (cp != NULL)
			while (isspace((int)*cp) || *cp == '=')
				++cp;
		else
			cp = "";

		if (strcasecmp(tmp, key) == 0) {
			retval = strdup(cp);
			break;
		}
	}
	fclose(fp);

	free(buf);

	return retval;
}
