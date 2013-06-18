/*
 * Copyright (c) 2005, 2006, 2007, 2010, 2013 Thorsten Kukuk <kukuk@thkukuk.de>
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
 * the GNU Public License V2, in which case the provisions of the GPL
 * are required INSTEAD OF the above restrictions.  (This clause is
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

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <syslog.h>

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define BUF_SIZE 4096
#define LOGIN_DEFS "/etc/login.defs"
#define LOGIN_CONF "/etc/default/login"

struct options_t {
  int debug;
  int usergroups;
  int silent;
  char *umask;
};
typedef struct options_t options_t;

static void
parse_option (const pam_handle_t *pamh, const char *argv, options_t *options)
{
  if (argv == NULL || argv[0] == '\0')
    return;

  if (strcasecmp (argv, "debug") == 0)
    options->debug = 1;
  else if (strncasecmp (argv, "umask=", 6) == 0)
    options->umask = strdup (&argv[6]);
  else if (strcasecmp (argv, "usergroups") == 0)
    options->usergroups = 1;
  else if (strcasecmp (argv, "silent") == 0)
    options->silent = 1;
  else
    pam_syslog (pamh, LOG_ERR, "Unknown option: `%s'", argv);
}

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
	  if (buf == NULL) {
	    fclose (fp);
	    return NULL;
	  }
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

      if (strcasecmp (tmp, "UMASK") == 0)
	{
	  retval = strdup (cp);
	  break;
	}
    }
  fclose (fp);

  free (buf);

  return retval;
}

static int
get_options (const pam_handle_t *pamh, options_t *options,
	     int argc, const char **argv)
{
  memset (options, 0, sizeof (options_t));
  /* Parse parameters for module */
  for ( ; argc-- > 0; argv++)
    parse_option (pamh, *argv, options);

  if (options->umask == NULL)
    options->umask = search_key (LOGIN_DEFS);
  if (options->umask == NULL)
    options->umask = search_key (LOGIN_CONF);

  return 0;
}

static void
set_umask (const char *value)
{
  const char *value_orig = value;
  mode_t mask;
  char *endptr;

  mask = strtoul (value, &endptr, 8) & 0777;
  if (((mask == 0) && (value_orig == endptr)) ||
      ((mask == UINT_MAX) && (errno == ERANGE)))
    return;
  umask (mask);
  return;
}

/* Set the process nice, ulimit, and umask from the
   password file entry.  */
static void
setup_limits_from_gecos (pam_handle_t *pamh, options_t *options,
			 struct passwd *pw)
{
  char *cp;

  if (options->usergroups)
    {
      /* if not root and username is the same as primary group name,
         set umask group bits to be the same as owner bits
	 (examples: 022 -> 002, 077 -> 007).  */
      if (pw->pw_uid != 0)
	{
	  struct group *grp = pam_modutil_getgrgid (pamh, pw->pw_gid);
	  if (grp && (strcmp (pw->pw_name, grp->gr_name) == 0))
	    {
	      mode_t oldmask = umask (0777);
	      umask ((oldmask & ~070) | ((oldmask >> 3) & 070));
	    }
        }
    }

  /* See if the GECOS field contains values for NICE, UMASK or ULIMIT.  */
  for (cp = pw->pw_gecos; cp != NULL; cp = strchr (cp, ','))
    {
      if (*cp == ',')
	cp++;

      if (strncasecmp (cp, "umask=", 6) == 0)
	umask (strtol (cp + 6, NULL, 8) & 0777);
      else if (strncasecmp (cp, "pri=", 4) == 0)
	{
	  errno = 0;
	  if (nice (strtol (cp + 4, NULL, 10)) == -1 && errno != 0)
	    {
	      if (!options->silent || options->debug)
		pam_error (pamh, "nice failed: %m\n");
	      pam_syslog (pamh, LOG_ERR, "nice failed: %m");
	    }
	}
      else if (strncasecmp (cp, "ulimit=", 7) == 0)
	{
	  struct rlimit rlimit_fsize;
	  rlimit_fsize.rlim_cur = 512L * strtol (cp + 7, NULL, 10);
	  rlimit_fsize.rlim_max = rlimit_fsize.rlim_cur;
	  if (setrlimit (RLIMIT_FSIZE, &rlimit_fsize) == -1)
	    {
	      if (!options->silent || options->debug)
		pam_error (pamh, "setrlimit failed: %m\n");
	      pam_syslog (pamh, LOG_ERR, "setrlimit failed: %m");
	    }
        }
    }
}


PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags UNUSED,
                     int argc, const char **argv)
{
  struct passwd *pw;
  options_t options;
  const char *name;
  int retval = PAM_SUCCESS;

  get_options (pamh, &options, argc, argv);
  if (flags & PAM_SILENT)
    options.silent = 1;

  /* get the user name. */
  if ((retval = pam_get_user (pamh, &name, NULL)) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "pam_get_user failed: return %d", retval);
      return (retval == PAM_CONV_AGAIN ? PAM_INCOMPLETE:retval);
    }

  if (name == NULL || name[0] == '\0')
    {
      if (name)
        {
          pam_syslog (pamh, LOG_ERR, "bad username [%s]", name);
          return PAM_USER_UNKNOWN;
        }
      return PAM_SERVICE_ERR;
    }

  pw = pam_modutil_getpwnam (pamh, name);
  if (pw == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "account for %s not found", name);
      return PAM_USER_UNKNOWN;
    }

  if (options.umask != NULL)
    {
      set_umask (options.umask);
      free (options.umask);
    }

  setup_limits_from_gecos (pamh, &options, pw);

  return retval;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
  return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_umask_modstruct = {
     "pam_umask",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL
};

#endif

/* end of module definition */
