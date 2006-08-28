/*
 * Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
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
#include "config.h"
#endif

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>


#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

static int
call_exec (pam_handle_t *pamh, int argc, const char **argv)
{
  int debug = 0;
  int call_setuid = 0;
  int optargc;
  const char *logfile = NULL;
  pid_t pid;

  if (argc < 1) {
    pam_syslog (pamh, LOG_ERR,
		"This module needs at least one argument");
    return PAM_SERVICE_ERR;
  }

  for (optargc = 0; optargc < argc; optargc++)
    {
      if (argv[optargc][0] == '/') /* paths starts with / */
	break;

      if (strcasecmp (argv[optargc], "debug") == 0)
	debug = 1;
      else if (strncasecmp (argv[optargc], "log=", 4) == 0)
	logfile = &argv[optargc][4];
      else if (strcasecmp (argv[optargc], "seteuid") == 0)
	call_setuid = 1;
      else
	break; /* Unknown option, assume program to execute. */
    }


  if (optargc >= argc) {
    pam_syslog (pamh, LOG_ERR, "No path given as argument");
    return PAM_SERVICE_ERR;
  }

  pid = fork();
  if (pid == -1)
    return PAM_SYSTEM_ERR;
  if (pid > 0) /* parent */
    {
      int status = 0;
      pid_t retval;
      while ((retval = waitpid (pid, &status, 0)) == -1 &&
	     errno == EINTR);
      if (retval == (pid_t)-1)
	{
	  pam_syslog (pamh, LOG_ERR, "waitpid returns with -1: %m");
	  return PAM_SYSTEM_ERR;
	}
      else if (status != 0)
	{
	  if (WIFEXITED(status))
	    {
	      pam_syslog (pamh, LOG_ERR, "%s failed: exit code %d",
			  argv[optargc], WEXITSTATUS(status));
	      pam_error (pamh, _("%s failed: exit code %d"),
			 argv[optargc], WEXITSTATUS(status));
	    }
	  else if (WIFSIGNALED(status))
	    {
	      pam_syslog (pamh, LOG_ERR, "%s failed: caught signal %d%s",
			  argv[optargc], WTERMSIG(status),
			  WCOREDUMP(status) ? " (core dumped)" : "");
	      pam_error (pamh, _("%s failed: caught signal %d%s"),
			 argv[optargc], WTERMSIG(status),
			 WCOREDUMP(status) ? " (core dumped)" : "");
	    }
	  else
	    {
	      pam_syslog (pamh, LOG_ERR, "%s failed: unknown status 0x%x",
			  argv[optargc], status);
	      pam_error (pamh, _("%s failed: unknown status 0x%x"),
			 argv[optargc], status);
	    }
	  return PAM_SYSTEM_ERR;
	}
      return PAM_SUCCESS;
    }
  else /* child */
    {
      char **arggv;
      int i;

      for (i = 0; i < sysconf (_SC_OPEN_MAX); i++)
	close (i);

      /* New stdin.  */
      if ((i = open ("/dev/null", O_RDWR)) < 0)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "open of /dev/null failed: %m");
	  exit (err);
	}
      /* New stdout and stderr.  */
      if (logfile)
	{
	  time_t tm = time (NULL);
	  char *buffer = NULL;

	  if ((i = open (logfile, O_CREAT|O_APPEND|O_WRONLY,
	  		 S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1)
	    {
	      int err = errno;
	      pam_syslog (pamh, LOG_ERR, "open of %s failed: %m",
			  logfile);
	      exit (err);
	    }
	  if (asprintf (&buffer, "*** %s", ctime (&tm)) > 0)
	    {
	      pam_modutil_write (i, buffer, strlen (buffer));
	      free (buffer);
	    }
	}
      else
	if (dup (i) == -1)
	  {
	    int err = errno;
	    pam_syslog (pamh, LOG_ERR, "dup failed: %m");
	    exit (err);
	  }
      if (dup (i) == -1)
        {
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "dup failed: %m");
          exit (err);
        }

      if (call_setuid)
	if (setuid (geteuid ()) == -1)
	  {
	    int err = errno;
	    pam_syslog (pamh, LOG_ERR, "setuid(%lu) failed: %m",
			(unsigned long) geteuid ());
	    exit (err);
	  }

      if (setsid () == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "setsid failed: %m");
	  exit (err);
	}

      arggv = calloc (argc + 4, sizeof (char *));
      if (arggv == NULL)
	exit (ENOMEM);

      for (i = 0; i < (argc - optargc); i++)
	arggv[i] = argv[i+optargc];
      arggv[i] = NULL;

      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "Calling %s ...", arggv[0]);

      if (execv (arggv[0], arggv) == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "execv(%s,...) failed: %m",
		      arggv[0]);
	  exit (err);
	}
      exit (1); /* should never be reached. */
    }
  return PAM_SYSTEM_ERR;
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  return call_exec (pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

/* password updating functions */

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  if (flags & PAM_PRELIM_CHECK)
    return PAM_SUCCESS;
  return call_exec (pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		 int argc, const char **argv)
{
  return call_exec (pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
  return call_exec (pamh, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  return call_exec (pamh, argc, argv);
}

#ifdef PAM_STATIC
struct pam_module _pam_exec_modstruct = {
  "pam_exec",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok,
};
#endif
