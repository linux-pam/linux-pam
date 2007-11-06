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
 * If no delay option was given, pam_faildelay.so will use the
 * FAIL_DELAY value of /etc/login.defs.
 *
 * Based on pam_rootok and parts of pam_unix both by Andrew Morgan
 *  <morgan@linux.kernel.org>
 *
 * Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
 * - Rewrite to use extended PAM functions
 * - Add /etc/login.defs support
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

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>


#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>


#define BUF_SIZE 8192
#define LOGIN_DEFS "/etc/login.defs"

static char *
search_key (const char *filename)
{
  FILE *fp;
  char *buf = NULL;
  size_t buflen = 0;
  char *retval = NULL;

  fp = fopen (filename, "r");
  if (NULL == fp)
    return NULL;

  while (!feof (fp))
    {
      char *tmp, *cp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, fp);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', fp);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = BUF_SIZE;
          buf = malloc (buflen);
        }
      buf[0] = '\0';
      if (fgets (buf, buflen - 1, fp) == NULL)
        break;
      else if (buf != NULL)
        n = strlen (buf);
      else
        n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */
      cp = buf;

      if (n < 1)
        break;

      tmp = strchr (cp, '#');  /* remove comments */
      if (tmp)
        *tmp = '\0';
      while (isspace ((int)*cp))    /* remove spaces and tabs */
        ++cp;
      if (*cp == '\0')        /* ignore empty lines */
        continue;

      if (cp[strlen (cp) - 1] == '\n')
        cp[strlen (cp) - 1] = '\0';

      tmp = strsep (&cp, " \t=");
      if (cp != NULL)
        while (isspace ((int)*cp) || *cp == '=')
          ++cp;

      if (strcasecmp (tmp, "FAIL_DELAY") == 0)
        {
          retval = strdup (cp);
          break;
        }
    }
  fclose (fp);

  free (buf);

  return retval;
}


/* --- authentication management functions (only) --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
			int argc, const char **argv)
{
    int i, debug_flag = 0;
    long int delay = -1;

    /* step through arguments */
    for (i = 0; i < argc; i++) {
	if (sscanf(argv[i], "delay=%ld", &delay) == 1) {
	  /* sscanf did already everything necessary */
	} else if (strcmp (argv[i], "debug") == 0)
	  debug_flag = 1;
	else
	  pam_syslog (pamh, LOG_ERR, "unknown option; %s", argv[i]);
    }

    if (delay == -1)
      {
	char *endptr;
	char *val = search_key (LOGIN_DEFS);
	const char *val_orig = val;

	if (val == NULL)
	  return PAM_IGNORE;

	errno = 0;
	delay = strtol (val, &endptr, 10) & 0777;
	if (((delay == 0) && (val_orig == endptr)) ||
	    ((delay == LONG_MIN || delay == LONG_MAX) && (errno == ERANGE)))
	  {
	    pam_syslog (pamh, LOG_ERR, "FAIL_DELAY=%s in %s not valid",
			val, LOGIN_DEFS);
	    free (val);
	    return PAM_IGNORE;
	  }

	free (val);
	/* delay is in seconds, convert to microseconds. */
	delay *= 1000000;
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

struct pam_module _pam_faildelay_modstruct = {
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
