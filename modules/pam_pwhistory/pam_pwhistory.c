/*
 * Copyright (c) 2008, 2012 Thorsten Kukuk
 * Author: Thorsten Kukuk <kukuk@thkukuk.de>
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

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#define PAM_SM_PASSWORD

#include <pwd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <shadow.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>

#include "opasswd.h"

#define DEFAULT_BUFLEN 2048

struct options_t {
  int debug;
  int enforce_for_root;
  int remember;
  int tries;
};
typedef struct options_t options_t;


static void
parse_option (pam_handle_t *pamh, const char *argv, options_t *options)
{
  if (strcasecmp (argv, "try_first_pass") == 0)
    /* ignore */;
  else if (strcasecmp (argv, "use_first_pass") == 0)
    /* ignore */;
  else if (strcasecmp (argv, "use_authtok") == 0)
    /* ignore, handled by pam_get_authtok */;
  else if (strcasecmp (argv, "debug") == 0)
    options->debug = 1;
  else if (strncasecmp (argv, "remember=", 9) == 0)
    {
      options->remember = strtol(&argv[9], NULL, 10);
      if (options->remember < 0)
        options->remember = 0;
      if (options->remember > 400)
        options->remember = 400;
    }
  else if (strncasecmp (argv, "retry=", 6) == 0)
    {
      options->tries = strtol(&argv[6], NULL, 10);
      if (options->tries < 0)
        options->tries = 1;
    }
  else if (strcasecmp (argv, "enforce_for_root") == 0)
    options->enforce_for_root = 1;
  else if (strncasecmp (argv, "authtok_type=", 13) == 0)
    { /* ignore, for pam_get_authtok */; }
  else
    pam_syslog (pamh, LOG_ERR, "pam_pwhistory: unknown option: %s", argv);
}


/* This module saves the current crypted password in /etc/security/opasswd
   and then compares the new password with all entries in this file. */

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  struct passwd *pwd;
  const char *newpass;
  const char *user;
    int retval, tries;
  options_t options;

  memset (&options, 0, sizeof (options));

  /* Set some default values, which could be overwritten later.  */
  options.remember = 10;
  options.tries = 1;

  /* Parse parameters for module */
  for ( ; argc-- > 0; argv++)
    parse_option (pamh, *argv, &options);

  if (options.debug)
    pam_syslog (pamh, LOG_DEBUG, "pam_sm_chauthtok entered");


  if (options.remember == 0)
    return PAM_IGNORE;

  retval = pam_get_user (pamh, &user, NULL);
  if (retval != PAM_SUCCESS)
    return retval;

  if (user == NULL || strlen (user) == 0)
    {
      if (options.debug)
	pam_syslog (pamh, LOG_DEBUG,
		    "User is not known to system");

      return PAM_USER_UNKNOWN;
    }

  if (flags & PAM_PRELIM_CHECK)
    {
      if (options.debug)
	pam_syslog (pamh, LOG_DEBUG,
		    "pam_sm_chauthtok(PAM_PRELIM_CHECK)");

      return PAM_SUCCESS;
    }

  pwd = pam_modutil_getpwnam (pamh, user);
  if (pwd == NULL)
    return PAM_USER_UNKNOWN;

  if ((strcmp(pwd->pw_passwd, "x") == 0)  ||
      ((pwd->pw_passwd[0] == '#') &&
       (pwd->pw_passwd[1] == '#') &&
       (strcmp(pwd->pw_name, pwd->pw_passwd + 2) == 0)))
    {
      struct spwd *spw = pam_modutil_getspnam (pamh, user);
      if (spw == NULL)
	return PAM_USER_UNKNOWN;

      retval = save_old_pass (pamh, user, pwd->pw_uid, spw->sp_pwdp,
			      options.remember, options.debug);
      if (retval != PAM_SUCCESS)
	return retval;
    }
  else
    {
      retval = save_old_pass (pamh, user, pwd->pw_uid, pwd->pw_passwd,
			      options.remember, options.debug);
      if (retval != PAM_SUCCESS)
	return retval;
    }

  newpass = NULL;
  tries = 0;
  while ((newpass == NULL) && (tries < options.tries))
    {
      retval = pam_get_authtok (pamh, PAM_AUTHTOK, &newpass, NULL);
      if (retval != PAM_SUCCESS && retval != PAM_TRY_AGAIN)
	{
	  if (retval == PAM_CONV_AGAIN)
	    retval = PAM_INCOMPLETE;
	  return retval;
	}
      tries++;

      if (options.debug)
	{
	  if (newpass)
	    pam_syslog (pamh, LOG_DEBUG, "got new auth token");
	  else
	    pam_syslog (pamh, LOG_DEBUG, "got no auth token");
	}

      if (newpass == NULL || retval == PAM_TRY_AGAIN)
	continue;

      if (options.debug)
	pam_syslog (pamh, LOG_DEBUG, "check against old password file");

      if (check_old_pass (pamh, user, newpass,
			  options.debug) != PAM_SUCCESS)
	{
	  if (getuid() || options.enforce_for_root ||
	      (flags & PAM_CHANGE_EXPIRED_AUTHTOK))
	    {
	      pam_error (pamh,
		         _("Password has been already used. Choose another."));
	      newpass = NULL;
	      /* Remove password item, else following module will use it */
	      pam_set_item (pamh, PAM_AUTHTOK, (void *) NULL);
	    }
	  else
	    pam_info (pamh,
		       _("Password has been already used."));
	}
    }

  if (newpass == NULL && tries >= options.tries)
    {
      if (options.debug)
	pam_syslog (pamh, LOG_DEBUG, "Aborted, too many tries");
      return PAM_MAXTRIES;
    }

  return PAM_SUCCESS;
}


#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_pwhistory_modstruct = {
  "pam_pwhistory",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  pam_sm_chauthtok
};
#endif
