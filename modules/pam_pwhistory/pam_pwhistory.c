/*
 * Copyright (c) 2008 Thorsten Kukuk
 * Author: Thorsten Kukuk <kukuk@suse.de>
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

#define NEW_PASSWORD_PROMPT _("New %s%spassword: ")
#define AGAIN_PASSWORD_PROMPT _("Retype new %s%spassword: ")
#define MISTYPED_PASSWORD _("Sorry, passwords do not match.")

#define DEFAULT_BUFLEN 2048

struct options_t {
  int debug;
  int use_authtok;
  int enforce_for_root;
  int remember;
  int tries;
};
typedef struct options_t options_t;


static void
parse_option (pam_handle_t *pamh, const char *argv, options_t *options)
{
  if (strcasecmp (argv, "use_first_pass") == 0)
    /* ignore */;
  else if (strcasecmp (argv, "use_first_pass") == 0)
    /* ignore */;
  else if (strcasecmp (argv, "use_authtok") == 0)
    options->use_authtok = 1;
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
  else
    pam_syslog (pamh, LOG_ERR, "pam_pwhistory: unknown option: %s", argv);
}


PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  struct passwd *pwd;
  char *newpass;
  const char *user;
  void *newpass_void;
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

  /* Ignore root if not enforced */
  if (pwd->pw_uid == 0 && !options.enforce_for_root)
    return PAM_SUCCESS;

  if ((strcmp(pwd->pw_passwd, "x") == 0)  ||
      ((pwd->pw_passwd[0] == '#') &&
       (pwd->pw_passwd[1] == '#') &&
       (strcmp(pwd->pw_name, pwd->pw_passwd + 2) == 0)))
    {
      struct spwd *spw = pam_modutil_getspnam (pamh, user);
      if (spw == NULL)
	return PAM_USER_UNKNOWN;

      retval = save_old_password (pamh, user, pwd->pw_uid, spw->sp_pwdp,
				  options.remember, options.debug);
      if (retval != PAM_SUCCESS)
	return retval;
    }
  else
    {
      retval = save_old_password (pamh, user, pwd->pw_uid, pwd->pw_passwd,
				  options.remember, options.debug);
      if (retval != PAM_SUCCESS)
	return retval;
    }

  retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &newpass_void);
  newpass = (char *) newpass_void;
  if (retval != PAM_SUCCESS)
    return retval;
  if (options.debug)
    {
      if (newpass)
	pam_syslog (pamh, LOG_DEBUG, "got new auth token");
      else
	pam_syslog (pamh, LOG_DEBUG, "new auth token not set");
    }

  /* If we haven't been given a password yet, prompt for one... */
  if (newpass == NULL)
    {
      if (options.use_authtok)
	/* We are not allowed to ask for a new password */
	return PAM_AUTHTOK_ERR;

      tries = 0;

      while ((newpass == NULL) && (tries++ < options.tries))
	{
	  retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &newpass,
			       NEW_PASSWORD_PROMPT, "UNIX", " ");
	  if (retval != PAM_SUCCESS)
	    {
	      _pam_drop (newpass);
	      if (retval == PAM_CONV_AGAIN)
		retval = PAM_INCOMPLETE;
	      return retval;
	    }

	  if (newpass == NULL)
	    {
	      /* We want to abort the password change */
	      pam_error (pamh, _("Password change aborted."));
	      return PAM_AUTHTOK_ERR;
	    }

	  if (options.debug)
	    pam_syslog (pamh, LOG_DEBUG, "check against old password file");

	  if (check_old_password (pamh, user, newpass,
				  options.debug) != PAM_SUCCESS)
	    {
	      pam_error (pamh,
			 _("Password has been already used. Choose another."));
	      _pam_overwrite (newpass);
	      _pam_drop (newpass);
	      if (tries >= options.tries)
		{
		  if (options.debug)
		    pam_syslog (pamh, LOG_DEBUG,
				"Aborted, too many tries");
		  return PAM_MAXTRIES;
		}
	    }
	  else
	    {
	      int failed;
	      char *new2;

	      retval = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &new2,
				   AGAIN_PASSWORD_PROMPT, "UNIX", " ");
              if (retval != PAM_SUCCESS)
		return retval;

              if (new2 == NULL)
                {                       /* Aborting password change... */
		  pam_error (pamh, _("Password change aborted."));
                  return PAM_AUTHTOK_ERR;
                }

              failed = (strcmp (newpass, new2) != 0);

              _pam_overwrite (new2);
              _pam_drop (new2);

	      if (failed)
                {
                  pam_error (pamh, MISTYPED_PASSWORD);
		  _pam_overwrite (newpass);
                  _pam_drop (newpass);
		  if (tries >= options.tries)
		    {
		      if (options.debug)
			pam_syslog (pamh, LOG_DEBUG,
				    "Aborted, too many tries");
		      return PAM_MAXTRIES;
		    }
                }
	    }
	}

      /* Remember new password */
      pam_set_item (pamh, PAM_AUTHTOK, (void *) newpass);
    }
  else /* newpass != NULL, we found an old password */
    {
      if (options.debug)
        pam_syslog (pamh, LOG_DEBUG, "look in old password file");

      if (check_old_password (pamh, user, newpass,
			      options.debug) != PAM_SUCCESS)
	{
	  pam_error (pamh,
		     _("Password has been already used. Choose another."));
	  /* We are only here, because old password was set.
             So overwrite it, else it will be stored! */
          pam_set_item (pamh, PAM_AUTHTOK, (void *) NULL);

	  return PAM_AUTHTOK_ERR;
	}
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
