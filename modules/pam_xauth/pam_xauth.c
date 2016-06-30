/*
 * Copyright 2001-2003 Red Hat, Inc.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <fnmatch.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <sys/stat.h>
#endif

#define DATANAME "pam_xauth_cookie_file"
#define XAUTHENV "XAUTHORITY"
#define HOMEENV  "HOME"
#define XAUTHDEF ".Xauthority"
#define XAUTHTMP ".xauthXXXXXX"

/* Hurd compatibility */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Possible paths to xauth executable */
static const char * const xauthpaths[] = {
#ifdef PAM_PATH_XAUTH
	PAM_PATH_XAUTH,
#endif
	"/usr/X11R6/bin/xauth",
	"/usr/bin/xauth",
	"/usr/bin/X11/xauth"
};

/* Run a given command (with a NULL-terminated argument list), feeding it the
 * given input on stdin, and storing any output it generates. */
static int
run_coprocess(pam_handle_t *pamh, const char *input, char **output,
	      uid_t uid, gid_t gid, const char *command, ...)
{
	int ipipe[2], opipe[2], i;
	char buf[LINE_MAX];
	pid_t child;
	char *buffer = NULL;
	size_t buffer_size = 0;
	va_list ap;

	*output = NULL;

	/* Create stdio pipery. */
	if (pipe(ipipe) == -1) {
		pam_syslog(pamh, LOG_ERR, "Could not create pipe: %m");
		return -1;
	}
	if (pipe(opipe) == -1) {
		pam_syslog(pamh, LOG_ERR, "Could not create pipe: %m");
		close(ipipe[0]);
		close(ipipe[1]);
		return -1;
	}

	/* Fork off a child. */
	child = fork();
	if (child == -1) {
		pam_syslog(pamh, LOG_ERR, "Could not fork: %m");
		close(ipipe[0]);
		close(ipipe[1]);
		close(opipe[0]);
		close(opipe[1]);
		return -1;
	}

	if (child == 0) {
		/* We're the child. */
		size_t j;
		const char *args[10];
		/* Drop privileges. */
		if (setgid(gid) == -1)
		  {
		    int err = errno;
		    pam_syslog (pamh, LOG_ERR, "setgid(%lu) failed: %m",
				(unsigned long) getegid ());
		    _exit (err);
		  }
		if (setgroups(0, NULL) == -1)
		  {
		    int err = errno;
		    pam_syslog (pamh, LOG_ERR, "setgroups() failed: %m");
		    _exit (err);
		  }
		if (setuid(uid) == -1)
		  {
		    int err = errno;
		    pam_syslog (pamh, LOG_ERR, "setuid(%lu) failed: %m",
				(unsigned long) geteuid ());
		    _exit (err);
		  }
		/* Set the pipe descriptors up as stdin and stdout, and close
		 * everything else, including the original values for the
		 * descriptors. */
		if (dup2(ipipe[0], STDIN_FILENO) != STDIN_FILENO) {
		    int err = errno;
		    pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdin");
		    _exit(err);
		}
		if (dup2(opipe[1], STDOUT_FILENO) != STDOUT_FILENO) {
		    int err = errno;
		    pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdout");
		    _exit(err);
		}
		if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_IGNORE_FD,
						    PAM_MODUTIL_IGNORE_FD,
						    PAM_MODUTIL_NULL_FD) < 0) {
		    _exit(1);
		}
		/* Initialize the argument list. */
		memset(args, 0, sizeof(args));
		/* Convert the varargs list into a regular array of strings. */
		va_start(ap, command);
		args[0] = command;
		for (j = 1; j < ((sizeof(args) / sizeof(args[0])) - 1); j++) {
			args[j] = va_arg(ap, const char*);
			if (args[j] == NULL) {
				break;
			}
		}
		/* Run the command. */
		execv(command, (char *const *) args);
		/* Never reached. */
		_exit(1);
	}

	/* We're the parent, so close the other ends of the pipes. */
	close(opipe[1]);
	/* Send input to the process (if we have any), then send an EOF. */
	if (input) {
		(void)pam_modutil_write(ipipe[1], input, strlen(input));
	}
	close(ipipe[0]); /* close here to avoid possible SIGPIPE above */
	close(ipipe[1]);

	/* Read data output until we run out of stuff to read. */
	i = pam_modutil_read(opipe[0], buf, sizeof(buf));
	while ((i != 0) && (i != -1)) {
		char *tmp;
		/* Resize the buffer to hold the data. */
		tmp = realloc(buffer, buffer_size + i + 1);
		if (tmp == NULL) {
			/* Uh-oh, bail. */
			if (buffer != NULL) {
				free(buffer);
			}
			close(opipe[0]);
			waitpid(child, NULL, 0);
			return -1;
		}
		/* Save the new buffer location, copy the newly-read data into
		 * the buffer, and make sure the result will be
		 * nul-terminated. */
		buffer = tmp;
		memcpy(buffer + buffer_size, buf, i);
		buffer[buffer_size + i] = '\0';
		buffer_size += i;
		/* Try to read again. */
		i = pam_modutil_read(opipe[0], buf, sizeof(buf));
	}
	/* No more data.  Clean up and return data. */
	close(opipe[0]);
	*output = buffer;
	waitpid(child, NULL, 0);
	return 0;
}

/* Free a data item. */
static void
cleanup (pam_handle_t *pamh UNUSED, void *data, int err UNUSED)
{
	free (data);
}

/* Check if we want to allow export to the other user, or import from the
 * other user. */
static int
check_acl(pam_handle_t *pamh,
	  const char *sense, const char *this_user, const char *other_user,
	  int noent_code, int debug)
{
	char path[PATH_MAX];
	struct passwd *pwd;
	FILE *fp = NULL;
	int i, fd = -1, save_errno;
	struct stat st;
	PAM_MODUTIL_DEF_PRIVS(privs);

	/* Check this user's <sense> file. */
	pwd = pam_modutil_getpwnam(pamh, this_user);
	if (pwd == NULL) {
		pam_syslog(pamh, LOG_ERR,
			   "error determining home directory for '%s'",
			   this_user);
		return PAM_SESSION_ERR;
	}
	/* Figure out what that file is really named. */
	i = snprintf(path, sizeof(path), "%s/.xauth/%s", pwd->pw_dir, sense);
	if ((i >= (int)sizeof(path)) || (i < 0)) {
		pam_syslog(pamh, LOG_ERR,
			   "name of user's home directory is too long");
		return PAM_SESSION_ERR;
	}
	if (pam_modutil_drop_priv(pamh, &privs, pwd))
		return PAM_SESSION_ERR;
	if (!stat(path, &st)) {
		if (!S_ISREG(st.st_mode))
			errno = EINVAL;
		else
			fd = open(path, O_RDONLY | O_NOCTTY);
	}
	save_errno = errno;
	if (pam_modutil_regain_priv(pamh, &privs)) {
		if (fd >= 0)
			close(fd);
		return PAM_SESSION_ERR;
	}
	if (fd >= 0) {
		if (!fstat(fd, &st)) {
			if (!S_ISREG(st.st_mode))
				errno = EINVAL;
			else
				fp = fdopen(fd, "r");
		}
		if (!fp) {
			save_errno = errno;
			close(fd);
		}
	}
	if (fp) {
		char buf[LINE_MAX], *tmp;
		/* Scan the file for a list of specs of users to "trust". */
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			tmp = memchr(buf, '\r', sizeof(buf));
			if (tmp != NULL) {
				*tmp = '\0';
			}
			tmp = memchr(buf, '\n', sizeof(buf));
			if (tmp != NULL) {
				*tmp = '\0';
			}
			if (fnmatch(buf, other_user, 0) == 0) {
				if (debug) {
					pam_syslog(pamh, LOG_DEBUG,
						   "%s %s allowed by %s",
						   other_user, sense, path);
				}
				fclose(fp);
				return PAM_SUCCESS;
			}
		}
		/* If there's no match in the file, we fail. */
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG, "%s not listed in %s",
				   other_user, path);
		}
		fclose(fp);
		return PAM_PERM_DENIED;
	} else {
		/* Default to okay if the file doesn't exist. */
	        errno = save_errno;
		switch (errno) {
		case ENOENT:
			if (noent_code == PAM_SUCCESS) {
				if (debug) {
					pam_syslog(pamh, LOG_DEBUG,
						   "%s does not exist, ignoring",
						   path);
				}
			} else {
				if (debug) {
					pam_syslog(pamh, LOG_DEBUG,
						   "%s does not exist, failing",
						   path);
				}
			}
			return noent_code;
		default:
			if (debug) {
				pam_syslog(pamh, LOG_DEBUG,
					   "error opening %s: %m", path);
			}
			return PAM_PERM_DENIED;
		}
	}
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
	char *cookiefile = NULL, *xauthority = NULL,
	     *cookie = NULL, *display = NULL, *tmp = NULL,
	     *xauthlocalhostname = NULL;
	const char *user, *xauth = NULL;
	struct passwd *tpwd, *rpwd;
	int fd, i, debug = 0;
	int retval = PAM_SUCCESS;
	uid_t systemuser = 499, targetuser = 0;

	/* Parse arguments.  We don't understand many, so no sense in breaking
	 * this into a separate function. */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
			continue;
		}
		if (strncmp(argv[i], "xauthpath=", 10) == 0) {
			xauth = argv[i] + 10;
			continue;
		}
		if (strncmp(argv[i], "targetuser=", 11) == 0) {
			long l = strtol(argv[i] + 11, &tmp, 10);
			if ((strlen(argv[i] + 11) > 0) && (*tmp == '\0')) {
				targetuser = l;
			} else {
				pam_syslog(pamh, LOG_WARNING,
					   "invalid value for targetuser (`%s')",
					   argv[i] + 11);
			}
			continue;
		}
		if (strncmp(argv[i], "systemuser=", 11) == 0) {
			long l = strtol(argv[i] + 11, &tmp, 10);
			if ((strlen(argv[i] + 11) > 0) && (*tmp == '\0')) {
				systemuser = l;
			} else {
				pam_syslog(pamh, LOG_WARNING,
					   "invalid value for systemuser (`%s')",
					   argv[i] + 11);
			}
			continue;
		}
		pam_syslog(pamh, LOG_WARNING, "unrecognized option `%s'",
			   argv[i]);
	}

	if (xauth == NULL) {
	        size_t j;
		for (j = 0; j < sizeof(xauthpaths)/sizeof(xauthpaths[0]); j++) {
			if (access(xauthpaths[j], X_OK) == 0) {
				xauth = xauthpaths[j];
				break;
			}
		}
		if (xauth == NULL) {
			/* xauth executable not found - nothing to do */
			return PAM_SUCCESS;
		}
	}

	/* If DISPLAY isn't set, we don't really care, now do we? */
	if ((display = getenv("DISPLAY")) == NULL) {
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG,
				   "user has no DISPLAY, doing nothing");
		}
		return PAM_SUCCESS;
	}

	/* Read the target user's name. */
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
			   "error determining target user's name");
		retval = PAM_SESSION_ERR;
		goto cleanup;
	}
	rpwd = pam_modutil_getpwuid(pamh, getuid());
	if (rpwd == NULL) {
		pam_syslog(pamh, LOG_ERR,
			   "error determining invoking user's name");
		retval = PAM_SESSION_ERR;
		goto cleanup;
	}

	/* Get the target user's UID and primary GID, which we'll need to set
	 * on the xauthority file we create later on. */
	tpwd = pam_modutil_getpwnam(pamh, user);
	if (tpwd == NULL) {
		pam_syslog(pamh, LOG_ERR,
			   "error determining target user's UID");
		retval = PAM_SESSION_ERR;
		goto cleanup;
	}

	if (debug) {
		pam_syslog(pamh, LOG_DEBUG,
			   "requesting user %lu/%lu, target user %lu/%lu",
			   (unsigned long) rpwd->pw_uid,
			   (unsigned long) rpwd->pw_gid,
			   (unsigned long) tpwd->pw_uid,
			   (unsigned long) tpwd->pw_gid);
	}

	/* If the UID is a system account (and not the superuser), forget
	 * about forwarding keys. */
	if ((tpwd->pw_uid != 0) &&
	    (tpwd->pw_uid != targetuser) &&
	    (tpwd->pw_uid <= systemuser)) {
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG,
				   "not forwarding cookies to user ID %lu",
				   (unsigned long) tpwd->pw_uid);
		}
		retval = PAM_SESSION_ERR;
		goto cleanup;
	}


	/* If current user and the target user are the same, don't
	   check the ACL list, but forward X11 */
	if (strcmp (rpwd->pw_name, tpwd->pw_name) != 0) {

	  /* Check that both users are amenable to this.  By default, this
	   * boils down to this policy:
	   * export(ruser=root): only if <user> is listed in .xauth/export
	   * export(ruser=*) if <user> is listed in .xauth/export, or
	   *                 if .xauth/export does not exist
	   * import(user=*): if <ruser> is listed in .xauth/import, or
	   *                 if .xauth/import does not exist */
	  i = (getuid() != 0 || tpwd->pw_uid == 0) ? PAM_SUCCESS : PAM_PERM_DENIED;
	  i = check_acl(pamh, "export", rpwd->pw_name, user, i, debug);
	  if (i != PAM_SUCCESS) {
	    retval = PAM_SESSION_ERR;
	    goto cleanup;
	  }
	  i = PAM_SUCCESS;
	  i = check_acl(pamh, "import", user, rpwd->pw_name, i, debug);
	  if (i != PAM_SUCCESS) {
	    retval = PAM_SESSION_ERR;
	    goto cleanup;
	  }
	}  else {
	  if (debug)
	    pam_syslog (pamh, LOG_DEBUG, "current and target user are the same, forward X11");
	}

	/* Figure out where the source user's .Xauthority file is. */
	if (getenv(XAUTHENV) != NULL) {
		cookiefile = strdup(getenv(XAUTHENV));
	} else {
		cookiefile = malloc(strlen(rpwd->pw_dir) + 1 +
				    strlen(XAUTHDEF) + 1);
		if (cookiefile == NULL) {
			retval = PAM_SESSION_ERR;
			goto cleanup;
		}
		strcpy(cookiefile, rpwd->pw_dir);
		strcat(cookiefile, "/");
		strcat(cookiefile, XAUTHDEF);
	}
	if (debug) {
		pam_syslog(pamh, LOG_DEBUG, "reading keys from `%s'",
			   cookiefile);
	}

	/* Read the user's .Xauthority file.  Because the current UID is
	 * the original user's UID, this will only fail if something has
	 * gone wrong, or we have no cookies. */
	if (debug) {
		pam_syslog(pamh, LOG_DEBUG,
			   "running \"%s %s %s %s %s\" as %lu/%lu",
			   xauth, "-f", cookiefile, "nlist", display,
			   (unsigned long) getuid(), (unsigned long) getgid());
	}
	if (run_coprocess(pamh, NULL, &cookie,
			  getuid(), getgid(),
			  xauth, "-f", cookiefile, "nlist", display,
			  NULL) == 0) {
#ifdef WITH_SELINUX
		security_context_t context = NULL;
#endif
		PAM_MODUTIL_DEF_PRIVS(privs);

		/* Check that we got a cookie.  If not, we get creative. */
		if (((cookie == NULL) || (strlen(cookie) == 0)) &&
		    ((strncmp(display, "localhost:", 10) == 0) ||
		     (strncmp(display, "localhost/unix:", 15) == 0))) {
			char *t, *screen;
			size_t tlen, slen;
			/* Free the useless cookie string. */
			if (cookie != NULL) {
				free(cookie);
				cookie = NULL;
			}
			/* Allocate enough space to hold an adjusted name. */
			tlen = strlen(display) + LINE_MAX + 1;
			t = malloc(tlen);
			if (t != NULL) {
				memset(t, 0, tlen);
				if (gethostname(t, tlen - 1) != -1) {
					/* Append the protocol and then the
					 * screen number. */
					if (strlen(t) < tlen - 6) {
						strcat(t, "/unix:");
					}
					screen = strchr(display, ':');
					if (screen != NULL) {
						screen++;
						slen = strlen(screen);
						if (strlen(t) + slen < tlen) {
							strcat(t, screen);
						}
					}
					if (debug) {
						pam_syslog(pamh, LOG_DEBUG,
							   "no key for `%s', "
							   "trying `%s'",
							   display, t);
					}
					/* Read the cookie for this display. */
					if (debug) {
						pam_syslog(pamh, LOG_DEBUG,
						       "running "
						       "\"%s %s %s %s %s\" as "
						       "%lu/%lu",
						       xauth,
						       "-f",
						       cookiefile,
						       "nlist",
						       t,
						       (unsigned long) getuid(),
						       (unsigned long) getgid());
					}
					run_coprocess(pamh, NULL, &cookie,
						      getuid(), getgid(),
						      xauth, "-f", cookiefile,
						      "nlist", t, NULL);
				}
				free(t);
				t = NULL;
			}
		}

		/* Check that we got a cookie, this time for real. */
		if ((cookie == NULL) || (strlen(cookie) == 0)) {
			if (debug) {
				pam_syslog(pamh, LOG_DEBUG, "no key");
			}
			retval = PAM_SESSION_ERR;
			goto cleanup;
		}

		/* Generate the environment variable
		 * "XAUTHORITY=<homedir>/filename". */
		if (asprintf(&xauthority, "%s=%s/%s",
			     XAUTHENV, tpwd->pw_dir, XAUTHTMP) < 0) {
			xauthority = NULL;
			if (debug) {
				pam_syslog(pamh, LOG_DEBUG, "out of memory");
			}
			retval = PAM_SESSION_ERR;
			goto cleanup;
		}

		/* Generate a new file to hold the data. */
		if (pam_modutil_drop_priv(pamh, &privs, tpwd)) {
			retval = PAM_SESSION_ERR;
			goto cleanup;
		}
#ifdef WITH_SELINUX
		if (is_selinux_enabled() > 0) {
			struct selabel_handle *ctx = selabel_open(SELABEL_CTX_FILE, NULL, 0);
			if (ctx != NULL) {
				if (selabel_lookup(ctx, &context,
						   xauthority + sizeof(XAUTHENV), S_IFREG) != 0) {
					pam_syslog(pamh, LOG_WARNING,
						   "could not get SELinux label for '%s'",
						   xauthority + sizeof(XAUTHENV));
				}
				selabel_close(ctx);
				if (setfscreatecon(context)) {
					pam_syslog(pamh, LOG_WARNING,
						   "setfscreatecon(%s) failed: %m", context);
				}
			}
		}
#endif /* WITH_SELINUX */
		fd = mkstemp(xauthority + sizeof(XAUTHENV));
		if (fd < 0)
			pam_syslog(pamh, LOG_ERR,
				   "error creating temporary file `%s': %m",
				   xauthority + sizeof(XAUTHENV));
#ifdef WITH_SELINUX
		if (context != NULL) {
			free(context);
			setfscreatecon(NULL);
		}
#endif /* WITH_SELINUX */
		if (fd >= 0)
			close(fd);
		if (pam_modutil_regain_priv(pamh, &privs) || fd < 0) {
			retval = PAM_SESSION_ERR;
			goto cleanup;
		}

		/* Get a copy of the filename to save as a data item for
		 * removal at session-close time. */
		free(cookiefile);
		cookiefile = strdup(xauthority + sizeof(XAUTHENV));

		/* Save the filename. */
		if (pam_set_data(pamh, DATANAME, cookiefile, cleanup) != PAM_SUCCESS) {
			pam_syslog(pamh, LOG_ERR,
				   "error saving name of temporary file `%s'",
				   cookiefile);
			unlink(cookiefile);
			retval = PAM_SESSION_ERR;
			goto cleanup;
		}

		/* Set the new variable in the environment. */
		if (pam_putenv (pamh, xauthority) != PAM_SUCCESS)
			pam_syslog(pamh, LOG_ERR,
				   "can't set environment variable '%s'",
				   xauthority);
		putenv (xauthority); /* The environment owns this string now. */
		xauthority = NULL; /* Don't free environment variables. */

		/* set $DISPLAY in pam handle to make su - work */
		{
		  char *d;

		  if (asprintf(&d, "DISPLAY=%s", display) < 0)
		    {
		      pam_syslog(pamh, LOG_CRIT, "out of memory");
		      cookiefile = NULL;
		      retval = PAM_SESSION_ERR;
		      goto cleanup;
		    }

		  if (pam_putenv (pamh, d) != PAM_SUCCESS)
		    pam_syslog (pamh, LOG_ERR,
				"can't set environment variable '%s'", d);
		  free (d);
		}

		/* set XAUTHLOCALHOSTNAME to make sure that su - work under gnome */
		if ((xauthlocalhostname = getenv("XAUTHLOCALHOSTNAME")) != NULL) {
		  char *d;

		  if (asprintf(&d, "XAUTHLOCALHOSTNAME=%s", xauthlocalhostname) < 0) {
		    pam_syslog(pamh, LOG_CRIT, "out of memory");
		    retval = PAM_SESSION_ERR;
		    goto cleanup;
		  }

		  if (pam_putenv (pamh, d) != PAM_SUCCESS)
		    pam_syslog (pamh, LOG_ERR,
				"can't set environment variable '%s'", d);
		  free (d);
		}

		/* Merge the cookie we read before into the new file. */
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG,
				   "writing key `%s' to temporary file `%s'",
				   cookie, cookiefile);
		}
		if (debug) {
			pam_syslog(pamh, LOG_DEBUG,
				  "running \"%s %s %s %s %s\" as %lu/%lu",
				  xauth, "-f", cookiefile, "nmerge", "-",
				  (unsigned long) tpwd->pw_uid,
				  (unsigned long) tpwd->pw_gid);
		}
		run_coprocess(pamh, cookie, &tmp,
			      tpwd->pw_uid, tpwd->pw_gid,
			      xauth, "-f", cookiefile, "nmerge", "-", NULL);

		/* We don't need to keep a copy of these around any more. */
		cookiefile = NULL;
		free(tmp);
	}
cleanup:
	/* Unset any old XAUTHORITY variable in the environment. */
	if (retval != PAM_SUCCESS && getenv (XAUTHENV))
		unsetenv (XAUTHENV);
	free(cookiefile);
	free(cookie);
	free(xauthority);
	return retval;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags UNUSED,
		      int argc, const char **argv)
{
	int i, debug = 0;
	const char *user;
	const void *data;
	const char *cookiefile;
	struct passwd *tpwd;
	PAM_MODUTIL_DEF_PRIVS(privs);

	/* Try to retrieve the name of a file we created when
	 * the session was opened. */
	if (pam_get_data(pamh, DATANAME, &data) != PAM_SUCCESS)
		return PAM_SUCCESS;
	cookiefile = data;

	/* Parse arguments.  We don't understand many, so
	 * no sense in breaking this into a separate function. */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
			continue;
		}
		if (strncmp(argv[i], "xauthpath=", 10) == 0)
			continue;
		if (strncmp(argv[i], "systemuser=", 11) == 0)
			continue;
		if (strncmp(argv[i], "targetuser=", 11) == 0)
			continue;
		pam_syslog(pamh, LOG_WARNING, "unrecognized option `%s'",
		       argv[i]);
	}

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
			   "error determining target user's name");
		return PAM_SESSION_ERR;
	}
	if (!(tpwd = pam_modutil_getpwnam(pamh, user))) {
		pam_syslog(pamh, LOG_ERR,
			   "error determining target user's UID");
		return PAM_SESSION_ERR;
	}

	if (debug)
		pam_syslog(pamh, LOG_DEBUG, "removing `%s'", cookiefile);
	if (pam_modutil_drop_priv(pamh, &privs, tpwd))
		return PAM_SESSION_ERR;
	if (unlink(cookiefile) == -1 && errno != ENOENT)
	  pam_syslog(pamh, LOG_WARNING, "Couldn't remove `%s': %m", cookiefile);
	if (pam_modutil_regain_priv(pamh, &privs))
		return PAM_SESSION_ERR;

	return PAM_SUCCESS;
}
