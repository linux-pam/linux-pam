/*
 * Copyright information at end of file.
 */

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <limits.h>
#include <utmp.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/resource.h>
#ifdef HAVE_RPCSVC_YPCLNT_H
#include <rpcsvc/ypclnt.h>
#endif

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "support.h"
#include "passverify.h"

static char *
search_key (const char *key, const char *filename)
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

      if (strcasecmp (tmp, key) == 0)
        {
          retval = strdup (cp);
          break;
        }
    }
  fclose (fp);

  free (buf);

  return retval;
}


/* this is a front-end for module-application conversations */

int _make_remark(pam_handle_t * pamh, unsigned int ctrl,
		    int type, const char *text)
{
	int retval = PAM_SUCCESS;

	if (off(UNIX__QUIET, ctrl)) {
		retval = pam_prompt(pamh, type, NULL, "%s", text);
	}
	return retval;
}

/*
 * set the control flags for the UNIX module.
 */

int _set_ctrl(pam_handle_t *pamh, int flags, int *remember, int *rounds,
	      int *pass_min_len, int argc, const char **argv)
{
	unsigned int ctrl;
	char *val;
	int j;

	D(("called."));

	ctrl = UNIX_DEFAULTS;	/* the default selection of options */

	/* set some flags manually */

	if (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK)) {
		D(("IAMROOT"));
		set(UNIX__IAMROOT, ctrl);
	}
	if (flags & PAM_UPDATE_AUTHTOK) {
		D(("UPDATE_AUTHTOK"));
		set(UNIX__UPDATE, ctrl);
	}
	if (flags & PAM_PRELIM_CHECK) {
		D(("PRELIM_CHECK"));
		set(UNIX__PRELIM, ctrl);
	}
	if (flags & PAM_SILENT) {
		D(("SILENT"));
		set(UNIX__QUIET, ctrl);
	}

	/* preset encryption method with value from /etc/login.defs */
	val = search_key ("ENCRYPT_METHOD", LOGIN_DEFS);
	if (val) {
	  for (j = 0; j < UNIX_CTRLS_; ++j) {
	    if (unix_args[j].token && unix_args[j].is_hash_algo
		&& !strncasecmp(val, unix_args[j].token, strlen(unix_args[j].token))) {
	      break;
	    }
	  }
	  if (j >= UNIX_CTRLS_) {
	    pam_syslog(pamh, LOG_WARNING, "unrecognized ENCRYPT_METHOD value [%s]", val);
	  } else {
	    ctrl &= unix_args[j].mask;	/* for turning things off */
	    ctrl |= unix_args[j].flag;	/* for turning things on  */
	  }
	  free (val);

	  /* read number of rounds for crypt algo */
	  if (rounds && (on(UNIX_SHA256_PASS, ctrl) || on(UNIX_SHA512_PASS, ctrl))) {
	    val=search_key ("SHA_CRYPT_MAX_ROUNDS", LOGIN_DEFS);

	    if (val) {
	      *rounds = strtol(val, NULL, 10);
	      free (val);
	    }
	  }
	}

	/* now parse the arguments to this module */

	for (; argc-- > 0; ++argv) {

		D(("pam_unix arg: %s", *argv));

		for (j = 0; j < UNIX_CTRLS_; ++j) {
			if (unix_args[j].token
			    && !strncmp(*argv, unix_args[j].token, strlen(unix_args[j].token))) {
				break;
			}
		}

		if (j >= UNIX_CTRLS_) {
			pam_syslog(pamh, LOG_ERR,
			         "unrecognized option [%s]", *argv);
		} else {
			/* special cases */
			if (j == UNIX_REMEMBER_PASSWD) {
				if (remember == NULL) {
					pam_syslog(pamh, LOG_ERR,
					    "option remember not allowed for this module type");
					continue;
				}
				*remember = strtol(*argv + 9, NULL, 10);
				if ((*remember == INT_MIN) || (*remember == INT_MAX))
					*remember = -1;
				if (*remember > 400)
					*remember = 400;
			} else if (j == UNIX_MIN_PASS_LEN) {
				if (pass_min_len == NULL) {
					pam_syslog(pamh, LOG_ERR,
					    "option minlen not allowed for this module type");
					continue;
				}
				*pass_min_len = atoi(*argv + 7);
			} else if (j == UNIX_ALGO_ROUNDS) {
				if (rounds == NULL) {
					pam_syslog(pamh, LOG_ERR,
					    "option rounds not allowed for this module type");
					continue;
				}
				*rounds = strtol(*argv + 7, NULL, 10);
			}

			ctrl &= unix_args[j].mask;	/* for turning things off */
			ctrl |= unix_args[j].flag;	/* for turning things on  */
		}
	}

	if (UNIX_DES_CRYPT(ctrl)
	    && pass_min_len && *pass_min_len > 8)
	  {
	    pam_syslog (pamh, LOG_NOTICE, "Password minlen reset to 8 characters");
	    *pass_min_len = 8;
	  }

	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
		D(("DISALLOW_NULL_AUTHTOK"));
		set(UNIX__NONULL, ctrl);
	}

	/* Set default rounds for blowfish */
	if (on(UNIX_BLOWFISH_PASS, ctrl) && off(UNIX_ALGO_ROUNDS, ctrl) && rounds != NULL) {
		*rounds = 5;
		set(UNIX_ALGO_ROUNDS, ctrl);
	}

	/* Enforce sane "rounds" values */
	if (on(UNIX_ALGO_ROUNDS, ctrl)) {
		if (on(UNIX_BLOWFISH_PASS, ctrl)) {
			if (*rounds < 4 || *rounds > 31)
				*rounds = 5;
		} else if (on(UNIX_SHA256_PASS, ctrl) || on(UNIX_SHA512_PASS, ctrl)) {
			if ((*rounds < 1000) || (*rounds == INT_MAX))
				/* don't care about bogus values */
				unset(UNIX_ALGO_ROUNDS, ctrl);
			if (*rounds >= 10000000)
				*rounds = 9999999;
		}
	}

	/* auditing is a more sensitive version of debug */

	if (on(UNIX_AUDIT, ctrl)) {
		set(UNIX_DEBUG, ctrl);
	}
	/* return the set of flags */

	D(("done."));
	return ctrl;
}

static void _cleanup(pam_handle_t * pamh UNUSED, void *x, int error_status UNUSED)
{
	_pam_delete(x);
}

/* ************************************************************** *
 * Useful non-trivial functions                                   *
 * ************************************************************** */

  /*
   * the following is used to keep track of the number of times a user fails
   * to authenticate themself.
   */

#define FAIL_PREFIX                   "-UN*X-FAIL-"
#define UNIX_MAX_RETRIES              3

struct _pam_failed_auth {
	char *user;		/* user that's failed to be authenticated */
	char *name;		/* attempt from user with name */
	int uid;		/* uid of calling user */
	int euid;		/* euid of calling process */
	int count;		/* number of failures so far */
};

#ifndef PAM_DATA_REPLACE
#error "Need to get an updated libpam 0.52 or better"
#endif

static void _cleanup_failures(pam_handle_t * pamh, void *fl, int err)
{
	int quiet;
	const void *service = NULL;
	const void *ruser = NULL;
	const void *rhost = NULL;
	const void *tty = NULL;
	struct _pam_failed_auth *failure;

	D(("called"));

	quiet = err & PAM_DATA_SILENT;	/* should we log something? */
	err &= PAM_DATA_REPLACE;	/* are we just replacing data? */
	failure = (struct _pam_failed_auth *) fl;

	if (failure != NULL) {

		if (!quiet && !err) {	/* under advisement from Sun,may go away */

			/* log the number of authentication failures */
			if (failure->count > 1) {
				(void) pam_get_item(pamh, PAM_SERVICE,
						    &service);
				(void) pam_get_item(pamh, PAM_RUSER,
						    &ruser);
				(void) pam_get_item(pamh, PAM_RHOST,
						    &rhost);
				(void) pam_get_item(pamh, PAM_TTY,
						    &tty);
				pam_syslog(pamh, LOG_NOTICE,
				         "%d more authentication failure%s; "
				         "logname=%s uid=%d euid=%d "
				         "tty=%s ruser=%s rhost=%s "
				         "%s%s",
				         failure->count - 1, failure->count == 2 ? "" : "s",
				         failure->name, failure->uid, failure->euid,
				         tty ? (const char *)tty : "", ruser ? (const char *)ruser : "",
				         rhost ? (const char *)rhost : "",
				         (failure->user && failure->user[0] != '\0')
				          ? " user=" : "", failure->user
				);

				if (failure->count > UNIX_MAX_RETRIES) {
					pam_syslog(pamh, LOG_NOTICE,
						 "service(%s) ignoring max retries; %d > %d",
						 service == NULL ? "**unknown**" : (const char *)service,
						 failure->count,
						 UNIX_MAX_RETRIES);
				}
			}
		}
		_pam_delete(failure->user);	/* tidy up */
		_pam_delete(failure->name);	/* tidy up */
		free(failure);
	}
}

/*
 * _unix_getpwnam() searches only /etc/passwd and NIS to find user information
 */
static void _unix_cleanup(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED)
{
	free(data);
}

int _unix_getpwnam(pam_handle_t *pamh, const char *name,
		   int files, int nis, struct passwd **ret)
{
	FILE *passwd;
	char buf[16384];
	int matched = 0, buflen;
	char *slogin, *spasswd, *suid, *sgid, *sgecos, *shome, *sshell, *p;

	memset(buf, 0, sizeof(buf));

	if (!matched && files) {
		int userlen = strlen(name);
		passwd = fopen("/etc/passwd", "r");
		if (passwd != NULL) {
			while (fgets(buf, sizeof(buf), passwd) != NULL) {
				if ((buf[userlen] == ':') &&
				    (strncmp(name, buf, userlen) == 0)) {
					p = buf + strlen(buf) - 1;
					while (isspace(*p) && (p >= buf)) {
						*p-- = '\0';
					}
					matched = 1;
					break;
				}
			}
			fclose(passwd);
		}
	}

#if defined(HAVE_YP_GET_DEFAULT_DOMAIN) && defined (HAVE_YP_BIND) && defined (HAVE_YP_MATCH) && defined (HAVE_YP_UNBIND)
	if (!matched && nis) {
		char *userinfo = NULL, *domain = NULL;
		int len = 0, i;
		len = yp_get_default_domain(&domain);
		if (len == YPERR_SUCCESS) {
			len = yp_bind(domain);
		}
		if (len == YPERR_SUCCESS) {
			i = yp_match(domain, "passwd.byname", name,
				     strlen(name), &userinfo, &len);
			yp_unbind(domain);
			if ((i == YPERR_SUCCESS) && ((size_t)len < sizeof(buf))) {
				strncpy(buf, userinfo, sizeof(buf) - 1);
				buf[sizeof(buf) - 1] = '\0';
				matched = 1;
			}
		}
	}
#else
	/* we don't have NIS support, make compiler happy. */
	nis = 0;
#endif

	if (matched && (ret != NULL)) {
		*ret = NULL;

		slogin = buf;

		spasswd = strchr(slogin, ':');
		if (spasswd == NULL) {
			return matched;
		}
		*spasswd++ = '\0';

		suid = strchr(spasswd, ':');
		if (suid == NULL) {
			return matched;
		}
		*suid++ = '\0';

		sgid = strchr(suid, ':');
		if (sgid == NULL) {
			return matched;
		}
		*sgid++ = '\0';

		sgecos = strchr(sgid, ':');
		if (sgecos == NULL) {
			return matched;
		}
		*sgecos++ = '\0';

		shome = strchr(sgecos, ':');
		if (shome == NULL) {
			return matched;
		}
		*shome++ = '\0';

		sshell = strchr(shome, ':');
		if (sshell == NULL) {
			return matched;
		}
		*sshell++ = '\0';

		buflen = sizeof(struct passwd) +
			 strlen(slogin) + 1 +
			 strlen(spasswd) + 1 +
			 strlen(sgecos) + 1 +
			 strlen(shome) + 1 +
			 strlen(sshell) + 1;
		*ret = malloc(buflen);
		if (*ret == NULL) {
			return matched;
		}
		memset(*ret, '\0', buflen);

		(*ret)->pw_uid = strtol(suid, &p, 10);
		if ((strlen(suid) == 0) || (*p != '\0')) {
			free(*ret);
			*ret = NULL;
			return matched;
		}

		(*ret)->pw_gid = strtol(sgid, &p, 10);
		if ((strlen(sgid) == 0) || (*p != '\0')) {
			free(*ret);
			*ret = NULL;
			return matched;
		}

		p = ((char*)(*ret)) + sizeof(struct passwd);
		(*ret)->pw_name = strcpy(p, slogin);
		p += strlen(p) + 1;
		(*ret)->pw_passwd = strcpy(p, spasswd);
		p += strlen(p) + 1;
		(*ret)->pw_gecos = strcpy(p, sgecos);
		p += strlen(p) + 1;
		(*ret)->pw_dir = strcpy(p, shome);
		p += strlen(p) + 1;
		(*ret)->pw_shell = strcpy(p, sshell);

		snprintf(buf, sizeof(buf), "_pam_unix_getpwnam_%s", name);

		if (pam_set_data(pamh, buf,
				 *ret, _unix_cleanup) != PAM_SUCCESS) {
			free(*ret);
			*ret = NULL;
		}
	}

	return matched;
}

/*
 * _unix_comsefromsource() is a quick check to see if information about a given
 * user comes from a particular source (just files and nis for now)
 *
 */
int _unix_comesfromsource(pam_handle_t *pamh,
			  const char *name, int files, int nis)
{
	return _unix_getpwnam(pamh, name, files, nis, NULL);
}

/*
 * verify the password of a user
 */

#include <sys/types.h>
#include <sys/wait.h>

static int _unix_run_helper_binary(pam_handle_t *pamh, const char *passwd,
				   unsigned int ctrl, const char *user)
{
    int retval, child, fds[2];
    struct sigaction newsa, oldsa;

    D(("called."));
    /* create a pipe for the password */
    if (pipe(fds) != 0) {
	D(("could not make pipe"));
	return PAM_AUTH_ERR;
    }

    if (off(UNIX_NOREAP, ctrl)) {
	/*
	 * This code arranges that the demise of the child does not cause
	 * the application to receive a signal it is not expecting - which
	 * may kill the application or worse.
	 *
	 * The "noreap" module argument is provided so that the admin can
	 * override this behavior.
	 */
        memset(&newsa, '\0', sizeof(newsa));
	newsa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &newsa, &oldsa);
    }

    /* fork */
    child = fork();
    if (child == 0) {
	static char *envp[] = { NULL };
	const char *args[] = { NULL, NULL, NULL, NULL };

	/* XXX - should really tidy up PAM here too */

	/* reopen stdin as pipe */
	if (dup2(fds[0], STDIN_FILENO) != STDIN_FILENO) {
		pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", "stdin");
		_exit(PAM_AUTHINFO_UNAVAIL);
	}

	if (pam_modutil_sanitize_helper_fds(pamh, PAM_MODUTIL_IGNORE_FD,
					    PAM_MODUTIL_PIPE_FD,
					    PAM_MODUTIL_PIPE_FD) < 0) {
		_exit(PAM_AUTHINFO_UNAVAIL);
	}

	if (geteuid() == 0) {
          /* must set the real uid to 0 so the helper will not error
	     out if pam is called from setuid binary (su, sudo...) */
	  if (setuid(0) == -1) {
             D(("setuid failed"));
	     _exit(PAM_AUTHINFO_UNAVAIL);
          }
	}

	/* exec binary helper */
	args[0] = CHKPWD_HELPER;
	args[1] = user;
	if (off(UNIX__NONULL, ctrl)) {	/* this means we've succeeded */
	  args[2]="nullok";
	} else {
	  args[2]="nonull";
	}

	execve(CHKPWD_HELPER, (char *const *) args, envp);

	/* should not get here: exit with error */
	D(("helper binary is not available"));
	_exit(PAM_AUTHINFO_UNAVAIL);
    } else if (child > 0) {
	/* wait for child */
	/* if the stored password is NULL */
        int rc=0;
	if (passwd != NULL) {            /* send the password to the child */
	    int len = strlen(passwd);

	    if (len > PAM_MAX_RESP_SIZE)
	      len = PAM_MAX_RESP_SIZE;
	    if (write(fds[1], passwd, len) == -1 ||
	        write(fds[1], "", 1) == -1) {
	      pam_syslog (pamh, LOG_ERR, "Cannot send password to helper: %m");
	      retval = PAM_AUTH_ERR;
	    }
	    passwd = NULL;
	} else {                         /* blank password */
	    if (write(fds[1], "", 1) == -1) {
	      pam_syslog (pamh, LOG_ERR, "Cannot send password to helper: %m");
	      retval = PAM_AUTH_ERR;
	    }
	}
	close(fds[0]);       /* close here to avoid possible SIGPIPE above */
	close(fds[1]);
	/* wait for helper to complete: */
	while ((rc=waitpid(child, &retval, 0)) < 0 && errno == EINTR);
	if (rc<0) {
	  pam_syslog(pamh, LOG_ERR, "unix_chkpwd waitpid returned %d: %m", rc);
	  retval = PAM_AUTH_ERR;
	} else if (!WIFEXITED(retval)) {
	  pam_syslog(pamh, LOG_ERR, "unix_chkpwd abnormal exit: %d", retval);
	  retval = PAM_AUTH_ERR;
	} else {
	  retval = WEXITSTATUS(retval);
	}
    } else {
	D(("fork failed"));
	close(fds[0]);
	close(fds[1]);
	retval = PAM_AUTH_ERR;
    }

    if (off(UNIX_NOREAP, ctrl)) {
        sigaction(SIGCHLD, &oldsa, NULL);   /* restore old signal handler */
    }

    D(("returning %d", retval));
    return retval;
}

/*
 * _unix_blankpasswd() is a quick check for a blank password
 *
 * returns TRUE if user does not have a password
 * - to avoid prompting for one in such cases (CG)
 */

int
_unix_blankpasswd (pam_handle_t *pamh, unsigned int ctrl, const char *name)
{
	struct passwd *pwd = NULL;
	char *salt = NULL;
	int retval;

	D(("called"));

	/*
	 * This function does not have to be too smart if something goes
	 * wrong, return FALSE and let this case to be treated somewhere
	 * else (CG)
	 */

	if (on(UNIX__NONULL, ctrl))
		return 0;	/* will fail but don't let on yet */

	/* UNIX passwords area */

	retval = get_pwd_hash(pamh, name, &pwd, &salt);

	if (retval == PAM_UNIX_RUN_HELPER) {
		/* salt will not be set here so we can return immediately */
		if (_unix_run_helper_binary(pamh, NULL, ctrl, name) == PAM_SUCCESS)
			return 1;
		else
			return 0;
	}

	/* Does this user have a password? */
	if (salt == NULL) {
		retval = 0;
	} else {
		if (strlen(salt) == 0)
			retval = 1;
		else
			retval = 0;
	}

	/* tidy up */

	if (salt)
		_pam_delete(salt);

	return retval;
}

int _unix_verify_password(pam_handle_t * pamh, const char *name
			  ,const char *p, unsigned int ctrl)
{
	struct passwd *pwd = NULL;
	char *salt = NULL;
	char *data_name;
	int retval;


	D(("called"));

#ifdef HAVE_PAM_FAIL_DELAY
	if (off(UNIX_NODELAY, ctrl)) {
		D(("setting delay"));
		(void) pam_fail_delay(pamh, 2000000);	/* 2 sec delay for on failure */
	}
#endif

	/* locate the entry for this user */

	D(("locating user's record"));

	retval = get_pwd_hash(pamh, name, &pwd, &salt);

	data_name = (char *) malloc(sizeof(FAIL_PREFIX) + strlen(name));
	if (data_name == NULL) {
		pam_syslog(pamh, LOG_CRIT, "no memory for data-name");
	} else {
		strcpy(data_name, FAIL_PREFIX);
		strcpy(data_name + sizeof(FAIL_PREFIX) - 1, name);
	}

	if (retval != PAM_SUCCESS) {
		if (retval == PAM_UNIX_RUN_HELPER) {
			D(("running helper binary"));
			retval = _unix_run_helper_binary(pamh, p, ctrl, name);
		} else {
			D(("user's record unavailable"));
			p = NULL;
			if (on(UNIX_AUDIT, ctrl)) {
				/* this might be a typo and the user has given a password
				   instead of a username. Careful with this. */
				pam_syslog(pamh, LOG_NOTICE,
				         "check pass; user (%s) unknown", name);
			} else {
				name = NULL;
				if (on(UNIX_DEBUG, ctrl) || pwd == NULL) {
				    pam_syslog(pamh, LOG_NOTICE,
				            "check pass; user unknown");
				} else {
				    /* don't log failure as another pam module can succeed */
				    goto cleanup;
				}
			}
		}
	} else {
		retval = verify_pwd_hash(p, salt, off(UNIX__NONULL, ctrl));
	}

	if (retval == PAM_SUCCESS) {
		if (data_name)	/* reset failures */
			pam_set_data(pamh, data_name, NULL, _cleanup_failures);
	} else {
		if (data_name != NULL) {
			struct _pam_failed_auth *new = NULL;
			const struct _pam_failed_auth *old = NULL;

			/* get a failure recorder */

			new = (struct _pam_failed_auth *)
			    malloc(sizeof(struct _pam_failed_auth));

			if (new != NULL) {

			    const char *login_name;
			    const void *void_old;


			    login_name = pam_modutil_getlogin(pamh);
			    if (login_name == NULL) {
				login_name = "";
			    }

			        new->user = strdup(name ? name : "");
				new->uid = getuid();
				new->euid = geteuid();
				new->name = strdup(login_name);

				/* any previous failures for this user ? */
				if (pam_get_data(pamh, data_name, &void_old)
				    == PAM_SUCCESS)
				        old = void_old;
				else
				        old = NULL;

				if (old != NULL) {
					new->count = old->count + 1;
					if (new->count >= UNIX_MAX_RETRIES) {
						retval = PAM_MAXTRIES;
					}
				} else {
					const void *service=NULL;
					const void *ruser=NULL;
					const void *rhost=NULL;
					const void *tty=NULL;

					(void) pam_get_item(pamh, PAM_SERVICE,
							    &service);
					(void) pam_get_item(pamh, PAM_RUSER,
							    &ruser);
					(void) pam_get_item(pamh, PAM_RHOST,
							    &rhost);
					(void) pam_get_item(pamh, PAM_TTY,
							    &tty);

					pam_syslog(pamh, LOG_NOTICE,
					         "authentication failure; "
					         "logname=%s uid=%d euid=%d "
					         "tty=%s ruser=%s rhost=%s "
					         "%s%s",
					         new->name, new->uid, new->euid,
					         tty ? (const char *)tty : "",
					         ruser ? (const char *)ruser : "",
					         rhost ? (const char *)rhost : "",
					         (new->user && new->user[0] != '\0')
					          ? " user=" : "",
					         new->user
					);
					new->count = 1;
				}

				pam_set_data(pamh, data_name, new, _cleanup_failures);

			} else {
				pam_syslog(pamh, LOG_CRIT,
				         "no memory for failure recorder");
			}
		}
	}

cleanup:
	if (data_name)
		_pam_delete(data_name);
	if (salt)
		_pam_delete(salt);

	D(("done [%d].", retval));

	return retval;
}

/* ****************************************************************** *
 * Copyright (c) Jan Rêkorajski 1999.
 * Copyright (c) Andrew G. Morgan 1996-8.
 * Copyright (c) Alex O. Yuriev, 1996.
 * Copyright (c) Cristian Gafton 1996.
 * Copyright (c) Red Hat, Inc. 2007.
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
