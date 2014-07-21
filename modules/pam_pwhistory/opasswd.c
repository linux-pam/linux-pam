/*
 * Copyright (c) 2008 Thorsten Kukuk <kukuk@suse.de>
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

#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>

#if defined (HAVE_XCRYPT_H)
#include <xcrypt.h>
#elif defined (HAVE_CRYPT_H)
#include <crypt.h>
#endif

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "opasswd.h"

#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif

#define OLD_PASSWORDS_FILE "/etc/security/opasswd"
#define TMP_PASSWORDS_FILE OLD_PASSWORDS_FILE".tmpXXXXXX"

#define DEFAULT_BUFLEN 4096

typedef struct {
  char *user;
  char *uid;
  int count;
  char *old_passwords;
} opwd;


static int
parse_entry (char *line, opwd *data)
{
  const char delimiters[] = ":";
  char *endptr;
  char *count;

  data->user = strsep (&line, delimiters);
  data->uid = strsep (&line, delimiters);
  count = strsep (&line, delimiters);
  if (count == NULL)
      return 1;

  data->count = strtol (count, &endptr, 10);
  if (endptr != NULL && *endptr != '\0')
      return 1;

  data->old_passwords = strsep (&line, delimiters);

  return 0;
}

static int
compare_password(const char *newpass, const char *oldpass)
{
  char *outval;
#ifdef HAVE_CRYPT_R
  struct crypt_data output;

  output.initialized = 0;

  outval = crypt_r (newpass, oldpass, &output);
#else
  outval = crypt (newpass, oldpass);
#endif

  return outval != NULL && strcmp(outval, oldpass) == 0;
}

/* Check, if the new password is already in the opasswd file.  */
int
check_old_pass (pam_handle_t *pamh, const char *user,
		const char *newpass, int debug)
{
  int retval = PAM_SUCCESS;
  FILE *oldpf;
  char *buf = NULL;
  size_t buflen = 0;
  opwd entry;
  int found = 0;

  if ((oldpf = fopen (OLD_PASSWORDS_FILE, "r")) == NULL)
    {
      if (errno != ENOENT)
	pam_syslog (pamh, LOG_ERR, "Cannot open %s: %m", OLD_PASSWORDS_FILE);
      return PAM_SUCCESS;
    }

  while (!feof (oldpf))
    {
      char *cp, *tmp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, oldpf);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', oldpf);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = DEFAULT_BUFLEN;
          buf = malloc (buflen);
	  if (buf == NULL)
	    return PAM_BUF_ERR;
        }
      buf[0] = '\0';
      fgets (buf, buflen - 1, oldpf);
      n = strlen (buf);
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

      if (strncmp (cp, user, strlen (user)) == 0 &&
          cp[strlen (user)] == ':')
        {
          /* We found the line we needed */
	  if (parse_entry (cp, &entry) == 0)
	    {
	      found = 1;
	      break;
	    }
	}
    }

  fclose (oldpf);

  if (found && entry.old_passwords)
    {
      const char delimiters[] = ",";
      char *running;
      char *oldpass;

      running = entry.old_passwords;

      do {
	oldpass = strsep (&running, delimiters);
	if (oldpass && strlen (oldpass) > 0 &&
	    compare_password(newpass, oldpass) )
	  {
	    if (debug)
	      pam_syslog (pamh, LOG_DEBUG, "New password already used");
	    retval = PAM_AUTHTOK_ERR;
	    break;
	  }
      } while (oldpass != NULL);
    }

  if (buf)
    free (buf);

  return retval;
}

int
save_old_pass (pam_handle_t *pamh, const char *user, uid_t uid,
	       const char *oldpass, int howmany, int debug UNUSED)
{
  char opasswd_tmp[] = TMP_PASSWORDS_FILE;
  struct stat opasswd_stat;
  FILE *oldpf, *newpf;
  int newpf_fd;
  int do_create = 0;
  int retval = PAM_SUCCESS;
  char *buf = NULL;
  size_t buflen = 0;
  int found = 0;

  if (howmany <= 0)
    return PAM_SUCCESS;

  if (oldpass == NULL || *oldpass == '\0')
    return PAM_SUCCESS;

  if ((oldpf = fopen (OLD_PASSWORDS_FILE, "r")) == NULL)
    {
      if (errno == ENOENT)
	{
	  pam_syslog (pamh, LOG_NOTICE, "Creating %s",
		      OLD_PASSWORDS_FILE);
	  do_create = 1;
	}
      else
	{
	  pam_syslog (pamh, LOG_ERR, "Cannot open %s: %m",
		      OLD_PASSWORDS_FILE);
	  return PAM_AUTHTOK_ERR;
	}
    }
  else if (fstat (fileno (oldpf), &opasswd_stat) < 0)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot stat %s: %m", OLD_PASSWORDS_FILE);
      fclose (oldpf);
      return PAM_AUTHTOK_ERR;
    }

  /* Open a temp passwd file */
  newpf_fd = mkstemp (opasswd_tmp);
  if (newpf_fd == -1)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot create %s temp file: %m",
		  OLD_PASSWORDS_FILE);
      if (oldpf)
	fclose (oldpf);
      return PAM_AUTHTOK_ERR;
    }
  if (do_create)
    {
      if (fchmod (newpf_fd, S_IRUSR|S_IWUSR) != 0)
	pam_syslog (pamh, LOG_ERR,
		    "Cannot set permissions of %s temp file: %m",
		    OLD_PASSWORDS_FILE);
      if (fchown (newpf_fd, 0, 0) != 0)
	pam_syslog (pamh, LOG_ERR,
		    "Cannot set owner/group of %s temp file: %m",
		    OLD_PASSWORDS_FILE);
    }
  else
    {
      if (fchmod (newpf_fd, opasswd_stat.st_mode) != 0)
	pam_syslog (pamh, LOG_ERR,
		    "Cannot set permissions of %s temp file: %m",
		    OLD_PASSWORDS_FILE);
      if (fchown (newpf_fd, opasswd_stat.st_uid, opasswd_stat.st_gid) != 0)
	pam_syslog (pamh, LOG_ERR,
		    "Cannot set owner/group of %s temp file: %m",
		    OLD_PASSWORDS_FILE);
    }
  newpf = fdopen (newpf_fd, "w+");
  if (newpf == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "Cannot fdopen %s: %m", opasswd_tmp);
      if (oldpf)
	fclose (oldpf);
      close (newpf_fd);
      retval = PAM_AUTHTOK_ERR;
      goto error_opasswd;
    }

  if (!do_create)
    while (!feof (oldpf))
      {
	char *cp, *tmp, *save;
#if defined(HAVE_GETLINE)
	ssize_t n = getline (&buf, &buflen, oldpf);
#elif defined (HAVE_GETDELIM)
	ssize_t n = getdelim (&buf, &buflen, '\n', oldpf);
#else
	ssize_t n;

	if (buf == NULL)
	  {
	    buflen = DEFAULT_BUFLEN;
	    buf = malloc (buflen);
	    if (buf == NULL)
              {
		fclose (oldpf);
		fclose (newpf);
		retval = PAM_BUF_ERR;
		goto error_opasswd;
              }
	  }
	buf[0] = '\0';
	fgets (buf, buflen - 1, oldpf);
	n = strlen (buf);
#endif /* HAVE_GETLINE / HAVE_GETDELIM */

	cp = buf;
	save = strdup (buf); /* Copy to write the original data back.  */
	if (save == NULL)
          {
	    fclose (oldpf);
	    fclose (newpf);
	    retval = PAM_BUF_ERR;
	    goto error_opasswd;
          }

	if (n < 1)
	  break;

	tmp = strchr (cp, '#');  /* remove comments */
	if (tmp)
	  *tmp = '\0';
	while (isspace ((int)*cp))    /* remove spaces and tabs */
	  ++cp;
	if (*cp == '\0')        /* ignore empty lines */
	  goto write_old_data;

	if (cp[strlen (cp) - 1] == '\n')
	  cp[strlen (cp) - 1] = '\0';

	if (strncmp (cp, user, strlen (user)) == 0 &&
	    cp[strlen (user)] == ':')
	  {
	    /* We found the line we needed */
	    opwd entry;

	    if (parse_entry (cp, &entry) == 0)
	      {
		char *out = NULL;

		found = 1;

		/* Don't save the current password twice */
		if (entry.old_passwords && entry.old_passwords[0] != '\0')
		  {
		    char *last = entry.old_passwords;

		    cp = entry.old_passwords;
		    entry.count = 1;  /* Don't believe the count */
		    while ((cp = strchr (cp, ',')) != NULL)
		      {
			entry.count++;
			last = ++cp;
		      }

		    /* compare the last password */
		    if (strcmp (last, oldpass) == 0)
		      goto write_old_data;
		  }
		else
		  entry.count = 0;

		/* increase count.  */
		entry.count++;

		/* check that we don't remember to many passwords.  */
		while (entry.count > howmany && entry.count > 1)
		  {
		    char *p = strpbrk (entry.old_passwords, ",");
		    if (p != NULL)
		      entry.old_passwords = ++p;
		    entry.count--;
		  }

		if (entry.count == 1)
		  {
		    if (asprintf (&out, "%s:%s:%d:%s\n",
				  entry.user, entry.uid, entry.count,
				  oldpass) < 0)
		      {
		        free (save);
			retval = PAM_AUTHTOK_ERR;
			fclose (oldpf);
			fclose (newpf);
			goto error_opasswd;
		      }
		  }
		else
		  {
		    if (asprintf (&out, "%s:%s:%d:%s,%s\n",
				  entry.user, entry.uid, entry.count,
				  entry.old_passwords, oldpass) < 0)
		      {
		        free (save);
			retval = PAM_AUTHTOK_ERR;
			fclose (oldpf);
			fclose (newpf);
			goto error_opasswd;
		      }
		  }

		if (fputs (out, newpf) < 0)
		  {
		    free (out);
		    free (save);
		    retval = PAM_AUTHTOK_ERR;
		    fclose (oldpf);
		    fclose (newpf);
		    goto error_opasswd;
		  }
		free (out);
	      }
	  }
	else
	  {
	  write_old_data:
	    if (fputs (save, newpf) < 0)
	      {
		free (save);
		retval = PAM_AUTHTOK_ERR;
		fclose (oldpf);
		fclose (newpf);
		goto error_opasswd;
	      }
	  }
	free (save);
      }

  if (!found)
    {
      char *out;

      if (asprintf (&out, "%s:%d:1:%s\n", user, uid, oldpass) < 0)
	{
	  retval = PAM_AUTHTOK_ERR;
	  if (oldpf)
	    fclose (oldpf);
	  fclose (newpf);
	  goto error_opasswd;
	}
      if (fputs (out, newpf) < 0)
	{
	  free (out);
	  retval = PAM_AUTHTOK_ERR;
	  if (oldpf)
	    fclose (oldpf);
	  fclose (newpf);
	  goto error_opasswd;
	}
      free (out);
    }

  if (oldpf)
    if (fclose (oldpf) != 0)
      {
	pam_syslog (pamh, LOG_ERR, "Error while closing old opasswd file: %m");
	retval = PAM_AUTHTOK_ERR;
	fclose (newpf);
	goto error_opasswd;
      }

  if (fflush (newpf) != 0 || fsync (fileno (newpf)) != 0)
    {
      pam_syslog (pamh, LOG_ERR,
		  "Error while syncing temporary opasswd file: %m");
      retval = PAM_AUTHTOK_ERR;
      fclose (newpf);
      goto error_opasswd;
    }

  if (fclose (newpf) != 0)
    {
      pam_syslog (pamh, LOG_ERR,
		  "Error while closing temporary opasswd file: %m");
      retval = PAM_AUTHTOK_ERR;
      goto error_opasswd;
    }

  unlink (OLD_PASSWORDS_FILE".old");
  if (link (OLD_PASSWORDS_FILE, OLD_PASSWORDS_FILE".old") != 0 &&
      errno != ENOENT)
    pam_syslog (pamh, LOG_ERR, "Cannot create backup file of %s: %m",
		OLD_PASSWORDS_FILE);
  rename (opasswd_tmp, OLD_PASSWORDS_FILE);
 error_opasswd:
  unlink (opasswd_tmp);
  free (buf);

  return retval;
}
