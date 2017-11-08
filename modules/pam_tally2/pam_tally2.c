/*
 * pam_tally2.c
 *
 */


/* By Tim Baverstock <warwick@mmm.co.uk>, Multi Media Machine Ltd.
 * 5 March 1997
 *
 * Stuff stolen from pam_rootok and pam_listfile
 *
 * Changes by Tomas Mraz <tmraz@redhat.com> 5 January 2005, 26 January 2006
 * Audit option added for Tomas patch by Sebastien Tricaud <toady@gscore.org> 13 January 2005
 * Portions Copyright 2006, Red Hat, Inc.
 * Portions Copyright 1989 - 1993, Julianne Frances Haugh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Julianne F. Haugh nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JULIE HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL JULIE HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#if defined(MAIN) && defined(MEMORY_DEBUG)
# undef exit
#endif /* defined(MAIN) && defined(MEMORY_DEBUG) */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>
#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include "tallylog.h"

#ifndef TRUE
#define TRUE  1L
#define FALSE 0L
#endif

#ifndef HAVE_FSEEKO
#define fseeko fseek
#endif

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#ifndef MAIN
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
/* #define PAM_SM_SESSION  */
/* #define PAM_SM_PASSWORD */

#include <security/pam_ext.h>
#endif
#include <security/pam_modutil.h>
#include <security/pam_modules.h>

/*---------------------------------------------------------------------*/

#define DEFAULT_LOGFILE "/var/log/tallylog"
#define MODULE_NAME     "pam_tally2"

#define tally_t    uint16_t
#define TALLY_HI   ((tally_t)~0L)

struct tally_options {
    const char *filename;
    tally_t deny;
    long lock_time;
    long unlock_time;
    long root_unlock_time;
    unsigned int ctrl;
};

#define PHASE_UNKNOWN 0
#define PHASE_AUTH    1
#define PHASE_ACCOUNT 2
#define PHASE_SESSION 3

#define OPT_MAGIC_ROOT			  01
#define OPT_FAIL_ON_ERROR		  02
#define OPT_DENY_ROOT			  04
#define OPT_QUIET                        040
#define OPT_AUDIT                       0100
#define OPT_NOLOGNOTICE                 0400
#define OPT_SERIALIZE                  01000
#define OPT_DEBUG                      02000

#define MAX_LOCK_WAITING_TIME 10

/*---------------------------------------------------------------------*/

/* some syslogging */

#ifdef MAIN
#define pam_syslog tally_log
static void
tally_log (const pam_handle_t *pamh UNUSED, int priority UNUSED,
	    const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, "%s: ", MODULE_NAME);
	vfprintf(stderr, fmt, args);
	fprintf(stderr,"\n");
	va_end(args);
}

#define pam_modutil_getpwnam(pamh, user) getpwnam(user)
#endif

/*---------------------------------------------------------------------*/

/* --- Support function: parse arguments --- */

#ifndef MAIN

static void
log_phase_no_auth(pam_handle_t *pamh, int phase, const char *argv)
{
    if ( phase != PHASE_AUTH ) {
	pam_syslog(pamh, LOG_ERR,
		   "option %s allowed in auth phase only", argv);
    }
}

static int
tally_parse_args(pam_handle_t *pamh, struct tally_options *opts,
		    int phase, int argc, const char **argv)
{
    memset(opts, 0, sizeof(*opts));
    opts->filename = DEFAULT_LOGFILE;
    opts->ctrl = OPT_FAIL_ON_ERROR;
    opts->root_unlock_time = -1;

    for ( ; argc-- > 0; ++argv ) {

      if ( ! strncmp( *argv, "file=", 5 ) ) {
	const char *from = *argv + 5;
        if ( *from!='/' ) {
          pam_syslog(pamh, LOG_ERR,
		     "filename not /rooted; %s", *argv);
          return PAM_AUTH_ERR;
        }
        opts->filename = from;
      }
      else if ( ! strcmp( *argv, "onerr=fail" ) ) {
        opts->ctrl |= OPT_FAIL_ON_ERROR;
      }
      else if ( ! strcmp( *argv, "onerr=succeed" ) ) {
        opts->ctrl &= ~OPT_FAIL_ON_ERROR;
      }
      else if ( ! strcmp( *argv, "magic_root" ) ) {
        opts->ctrl |= OPT_MAGIC_ROOT;
      }
      else if ( ! strcmp( *argv, "serialize" ) ) {
        opts->ctrl |= OPT_SERIALIZE;
      }
      else if ( ! strcmp( *argv, "debug" ) ) {
        opts->ctrl |= OPT_DEBUG;
      }
      else if ( ! strcmp( *argv, "even_deny_root_account" ) ||
                ! strcmp( *argv, "even_deny_root" ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        opts->ctrl |= OPT_DENY_ROOT;
      }
      else if ( ! strncmp( *argv, "deny=", 5 ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        if ( sscanf((*argv)+5,"%hu",&opts->deny) != 1 ) {
          pam_syslog(pamh, LOG_ERR, "bad number supplied: %s", *argv);
          return PAM_AUTH_ERR;
        }
      }
      else if ( ! strncmp( *argv, "lock_time=", 10 ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        if ( sscanf((*argv)+10,"%ld",&opts->lock_time) != 1 ) {
          pam_syslog(pamh, LOG_ERR, "bad number supplied: %s", *argv);
          return PAM_AUTH_ERR;
        }
      }
      else if ( ! strncmp( *argv, "unlock_time=", 12 ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        if ( sscanf((*argv)+12,"%ld",&opts->unlock_time) != 1 ) {
          pam_syslog(pamh, LOG_ERR, "bad number supplied: %s", *argv);
          return PAM_AUTH_ERR;
        }
      }
      else if ( ! strncmp( *argv, "root_unlock_time=", 17 ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        if ( sscanf((*argv)+17,"%ld",&opts->root_unlock_time) != 1 ) {
          pam_syslog(pamh, LOG_ERR, "bad number supplied: %s", *argv);
          return PAM_AUTH_ERR;
        }
        opts->ctrl |= OPT_DENY_ROOT; /* even_deny_root implied */
      }
      else if ( ! strcmp( *argv, "quiet" ) ||
		! strcmp ( *argv, "silent")) {
        opts->ctrl |= OPT_QUIET;
      }
      else if ( ! strcmp ( *argv, "no_log_info") ) {
	opts->ctrl |= OPT_NOLOGNOTICE;
      }
      else if ( ! strcmp ( *argv, "audit") ) {
	opts->ctrl |= OPT_AUDIT;
      }
      else {
        pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
      }
    }

    if (opts->root_unlock_time == -1)
	opts->root_unlock_time = opts->unlock_time;

    return PAM_SUCCESS;
}

#endif   /* #ifndef MAIN */

/*---------------------------------------------------------------------*/

/* --- Support function: get uid (and optionally username) from PAM or
        cline_user --- */

#ifdef MAIN
static char *cline_user=0;  /* cline_user is used in the administration prog */
#endif

static int
pam_get_uid(pam_handle_t *pamh, uid_t *uid, const char **userp, struct tally_options *opts)
{
    const char *user = NULL;
    struct passwd *pw;

#ifdef MAIN
    user = cline_user;
#else
    if ((pam_get_user( pamh, &user, NULL )) != PAM_SUCCESS) {
      user = NULL;
    }
#endif

    if ( !user || !*user ) {
      pam_syslog(pamh, LOG_ERR, "pam_get_uid; user?");
      return PAM_AUTH_ERR;
    }

    if ( ! ( pw = pam_modutil_getpwnam( pamh, user ) ) ) {
      opts->ctrl & OPT_AUDIT ?
	      pam_syslog(pamh, LOG_ERR, "pam_get_uid; no such user %s", user) :
	      pam_syslog(pamh, LOG_ERR, "pam_get_uid; no such user");
      return PAM_USER_UNKNOWN;
    }

    if ( uid )   *uid   = pw->pw_uid;
    if ( userp ) *userp = user;
    return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

/* --- Support functions: set/get tally data --- */

#ifndef MAIN

struct tally_data {
    time_t time;
    int    tfile;
};

static void
_cleanup(pam_handle_t *pamh UNUSED, void *void_data, int error_status UNUSED)
{
    struct tally_data *data = void_data;
    if (data->tfile != -1)
	close(data->tfile);
    free(data);
}

static void
tally_set_data( pam_handle_t *pamh, time_t oldtime, int tfile )
{
    struct tally_data *data;

    if ( (data=malloc(sizeof(*data))) != NULL ) {
        data->time = oldtime;
        data->tfile = tfile;
        pam_set_data(pamh, MODULE_NAME, (void *)data, _cleanup);
    }
}

static int
tally_get_data( pam_handle_t *pamh, time_t *oldtime, int *tfile )
{
    int rv;
    const void *void_data;
    const struct tally_data *data;

    rv = pam_get_data(pamh, MODULE_NAME, &void_data);
    if ( rv == PAM_SUCCESS && void_data != NULL && oldtime != NULL ) {
      data = void_data;
      *oldtime = data->time;
      *tfile = data->tfile;
    }
    else {
      rv = -1;
      *oldtime = 0;
    }
    return rv;
}
#endif   /* #ifndef MAIN */

/*---------------------------------------------------------------------*/

/* --- Support function: open/create tallyfile and return tally for uid --- */

/* If on entry tallyfile doesn't exist, creation is attempted. */

static void
alarm_handler(int sig UNUSED)
{   /* we just need to ignore it */
}

static int
get_tally(pam_handle_t *pamh, uid_t uid, const char *filename,
        int *tfile, struct tallylog *tally, unsigned int ctrl)
{
    struct stat fileinfo;
    int lstat_ret;
    void *void_tally = tally;
    int preopened = 0;

    if (*tfile != -1) {
	preopened = 1;
	goto skip_open;
    }

    lstat_ret = lstat(filename, &fileinfo);
    if (lstat_ret) {
      *tfile=open(filename, O_APPEND|O_CREAT, S_IRUSR|S_IWUSR);
      /* Create file, or append-open in pathological case. */
      if (*tfile == -1) {
#ifndef MAIN
        if (errno == EACCES) {
	    return PAM_IGNORE; /* called with insufficient access rights */
	}
#endif
        pam_syslog(pamh, LOG_ALERT, "Couldn't create %s: %m", filename);
        return PAM_AUTH_ERR;
      }
      lstat_ret = fstat(*tfile, &fileinfo);
      close(*tfile);
    }

    *tfile = -1;

    if ( lstat_ret ) {
      pam_syslog(pamh, LOG_ALERT, "Couldn't stat %s", filename);
      return PAM_AUTH_ERR;
    }

    if ((fileinfo.st_mode & S_IWOTH) || !S_ISREG(fileinfo.st_mode)) {
      /* If the file is world writable or is not a
         normal file, return error */
      pam_syslog(pamh, LOG_ALERT,
               "%s is either world writable or not a normal file",
               filename);
      return PAM_AUTH_ERR;
    }

    if ((*tfile = open(filename, O_RDWR)) == -1) {
#ifndef MAIN
      if (errno == EACCES) /* called with insufficient access rights */
	  return PAM_IGNORE;
#endif
      pam_syslog(pamh, LOG_ALERT, "Error opening %s for update: %m", filename);

      return PAM_AUTH_ERR;
    }

skip_open:
    if (lseek(*tfile, (off_t)uid*(off_t)sizeof(*tally), SEEK_SET) == (off_t)-1) {
        pam_syslog(pamh, LOG_ALERT, "lseek failed for %s: %m", filename);
        if (!preopened) {
	    close(*tfile);
            *tfile = -1;
        }
        return PAM_AUTH_ERR;
    }

    if (!preopened && (ctrl & OPT_SERIALIZE)) {
	/* this code is not thread safe as it uses fcntl locks and alarm()
	   so never use serialize with multithreaded services */
	struct sigaction newsa, oldsa;
	unsigned int oldalarm;
	int rv;

	memset(&newsa, '\0', sizeof(newsa));
	newsa.sa_handler = alarm_handler;
	sigaction(SIGALRM, &newsa, &oldsa);
	oldalarm = alarm(MAX_LOCK_WAITING_TIME);

	rv = lockf(*tfile, F_LOCK, sizeof(*tally));
	/* lock failure is not fatal, we attempt to read the tally anyway */

	/* reinstate the eventual old alarm handler */
	if (rv == -1 && errno == EINTR) {
	    if (oldalarm > MAX_LOCK_WAITING_TIME) {
		oldalarm -= MAX_LOCK_WAITING_TIME;
	    } else if (oldalarm > 0) {
		oldalarm = 1;
	    }
	}
	sigaction(SIGALRM, &oldsa, NULL);
	alarm(oldalarm);
    }

    if (pam_modutil_read(*tfile, void_tally, sizeof(*tally)) != sizeof(*tally)) {
	memset(tally, 0, sizeof(*tally));
    }

    tally->fail_line[sizeof(tally->fail_line)-1] = '\0';

    return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

/* --- Support function: update tallyfile with tally!=TALLY_HI --- */

static int
set_tally(pam_handle_t *pamh, uid_t uid,
	  const char *filename, int *tfile, struct tallylog *tally)
{
    void *void_tally = tally;
    if (tally->fail_cnt != TALLY_HI) {
        if (lseek(*tfile, (off_t)uid * sizeof(*tally), SEEK_SET) == (off_t)-1) {
                  pam_syslog(pamh, LOG_ALERT, "lseek failed for %s: %m", filename);
                            return PAM_AUTH_ERR;
        }
        if (pam_modutil_write(*tfile, void_tally, sizeof(*tally)) != sizeof(*tally)) {
	    pam_syslog(pamh, LOG_ALERT, "update (write) failed for %s: %m", filename);
	    return PAM_AUTH_ERR;
        }
    }

    if (fsync(*tfile)) {
      pam_syslog(pamh, LOG_ALERT, "update (fsync) failed for %s: %m", filename);
      return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

/* --- PAM bits --- */

#ifndef MAIN

#define RETURN_ERROR(i) return ((opts->ctrl & OPT_FAIL_ON_ERROR)?(i):(PAM_SUCCESS))

/*---------------------------------------------------------------------*/

static int
tally_check (tally_t oldcnt, time_t oldtime, pam_handle_t *pamh, uid_t uid,
             const char *user, struct tally_options *opts,
	     struct tallylog *tally)
{
    int rv = PAM_SUCCESS;
    int loglevel = LOG_DEBUG;
#ifdef HAVE_LIBAUDIT
    char buf[64];
    int audit_fd = -1;
    const void *rhost = NULL, *tty = NULL;
#endif

    if ((opts->ctrl & OPT_MAGIC_ROOT) && getuid() == 0) {
      return PAM_SUCCESS;
    }
    /* magic_root skips tally check */
#ifdef HAVE_LIBAUDIT
    audit_fd = audit_open();
    /* If there is an error & audit support is in the kernel report error */
    if ((audit_fd < 0) && !(errno == EINVAL || errno == EPROTONOSUPPORT ||
                            errno == EAFNOSUPPORT))
         return PAM_SYSTEM_ERR;
    (void)pam_get_item(pamh, PAM_TTY, &tty);
    (void)pam_get_item(pamh, PAM_RHOST, &rhost);
#endif
    if (opts->deny != 0 &&                        /* deny==0 means no deny        */
        tally->fail_cnt > opts->deny &&           /* tally>deny means exceeded    */
        ((opts->ctrl & OPT_DENY_ROOT) || uid)) {  /* even_deny stops uid check    */
#ifdef HAVE_LIBAUDIT
        if (tally->fail_cnt == opts->deny+1) {
            /* First say that max number was hit. */
            snprintf(buf, sizeof(buf), "pam_tally2 uid=%u ", uid);
            audit_log_user_message(audit_fd, AUDIT_ANOM_LOGIN_FAILURES, buf,
                                   rhost, NULL, tty, 1);
        }
#endif
        if (uid) {
            /* Unlock time check */
            if (opts->unlock_time && oldtime) {
                if (opts->unlock_time + oldtime <= time(NULL)) {
                    /* ignore deny check after unlock_time elapsed */
#ifdef HAVE_LIBAUDIT
                    snprintf(buf, sizeof(buf), "pam_tally2 uid=%u ", uid);
                    audit_log_user_message(audit_fd, AUDIT_RESP_ACCT_UNLOCK_TIMED, buf,
                                   rhost, NULL, tty, 1);
#endif
	            rv = PAM_SUCCESS;
		    goto cleanup;
	        }
            }
        } else {
            /* Root unlock time check */
            if (opts->root_unlock_time && oldtime) {
                if (opts->root_unlock_time + oldtime <= time(NULL)) {
	            /* ignore deny check after unlock_time elapsed */
#ifdef HAVE_LIBAUDIT
                    snprintf(buf, sizeof(buf), "pam_tally2 uid=%u ", uid);
                    audit_log_user_message(audit_fd, AUDIT_RESP_ACCT_UNLOCK_TIMED, buf,
                                   rhost, NULL, tty, 1);
#endif
	            rv = PAM_SUCCESS;
	            goto cleanup;
	        }
            }
        }

#ifdef HAVE_LIBAUDIT
        if (tally->fail_cnt == opts->deny+1) {
            /* First say that max number was hit. */
            audit_log_user_message(audit_fd, AUDIT_RESP_ACCT_LOCK, buf,
                                   rhost, NULL, tty, 1);
        }
#endif

        if (!(opts->ctrl & OPT_QUIET)) {
            pam_info(pamh, _("Account locked due to %u failed logins"),
		    (unsigned int)tally->fail_cnt);
        }
	loglevel = LOG_NOTICE;
        rv = PAM_AUTH_ERR;                 /* Only unconditional failure   */
        goto cleanup;
    }

    /* Lock time check */
    if (opts->lock_time && oldtime) {
        if (opts->lock_time + oldtime > time(NULL)) {
	    /* don't increase fail_cnt or update fail_time when
	       lock_time applies */
	    tally->fail_cnt = oldcnt;
	    tally->fail_time = oldtime;

	    if (!(opts->ctrl & OPT_QUIET)) {
	        pam_info(pamh, _("Account temporary locked (%ld seconds left)"),
                         oldtime+opts->lock_time-time(NULL));
            }
	    if (!(opts->ctrl & OPT_NOLOGNOTICE)) {
		pam_syslog(pamh, LOG_NOTICE,
	               "user %s (%lu) has time limit [%lds left]"
	               " since last failure.",
                       user, (unsigned long)uid,
	               oldtime+opts->lock_time-time(NULL));
	    }
	    rv = PAM_AUTH_ERR;
	    goto cleanup;
	}
    }

cleanup:
    if (!(opts->ctrl & OPT_NOLOGNOTICE) && (loglevel != LOG_DEBUG || opts->ctrl & OPT_DEBUG)) {
        pam_syslog(pamh, loglevel,
            "user %s (%lu) tally %hu, deny %hu",
            user, (unsigned long)uid, tally->fail_cnt, opts->deny);
    }
#ifdef HAVE_LIBAUDIT
    if (audit_fd != -1) {
        close(audit_fd);
    }
#endif
    return rv;
}

/* --- tally bump function: bump tally for uid by (signed) inc --- */

static int
tally_bump (int inc, time_t *oldtime, pam_handle_t *pamh,
            uid_t uid, const char *user, struct tally_options *opts, int *tfile)
{
    struct tallylog tally;
    tally_t oldcnt;
    const void *remote_host = NULL;
    int i, rv;

    tally.fail_cnt = 0;  /* !TALLY_HI --> Log opened for update */

    i = get_tally(pamh, uid, opts->filename, tfile, &tally, opts->ctrl);
    if (i != PAM_SUCCESS) {
        if (*tfile != -1) {
            close(*tfile);
            *tfile = -1;
        }
        RETURN_ERROR(i);
    }

    /* to remember old fail time (for locktime) */
    if (oldtime) {
        *oldtime = (time_t)tally.fail_time;
    }

    tally.fail_time = time(NULL);

    (void) pam_get_item(pamh, PAM_RHOST, &remote_host);
    if (!remote_host) {
	(void) pam_get_item(pamh, PAM_TTY, &remote_host);
	if (!remote_host) {
	    remote_host = "unknown";
	}
    }

    strncpy(tally.fail_line, remote_host,
		    sizeof(tally.fail_line)-1);
    tally.fail_line[sizeof(tally.fail_line)-1] = 0;

    oldcnt = tally.fail_cnt;

    if (!(opts->ctrl & OPT_MAGIC_ROOT) || getuid()) {
      /* magic_root doesn't change tally */
      tally.fail_cnt += inc;

      if (tally.fail_cnt == TALLY_HI) { /* Overflow *and* underflow. :) */
          tally.fail_cnt -= inc;
          pam_syslog(pamh, LOG_ALERT, "Tally %sflowed for user %s",
                 (inc<0)?"under":"over",user);
      }
    }

    rv = tally_check(oldcnt, *oldtime, pamh, uid, user, opts, &tally);

    i = set_tally(pamh, uid, opts->filename, tfile, &tally);
    if (i != PAM_SUCCESS) {
        if (*tfile != -1) {
            close(*tfile);
            *tfile = -1;
        }
        if (rv == PAM_SUCCESS)
	    RETURN_ERROR( i );
	/* fallthrough */
    } else if (!(opts->ctrl & OPT_SERIALIZE)) {
	close(*tfile);
	*tfile = -1;
    }

    return rv;
}

static int
tally_reset (pam_handle_t *pamh, uid_t uid, struct tally_options *opts, int old_tfile)
{
    struct tallylog tally;
    int tfile = old_tfile;
    int i;

    /* resets only if not magic root */

    if ((opts->ctrl & OPT_MAGIC_ROOT) && getuid() == 0) {
        return PAM_SUCCESS;
    }

    tally.fail_cnt = 0;  /* !TALLY_HI --> Log opened for update */

    i=get_tally(pamh, uid, opts->filename, &tfile, &tally, opts->ctrl);
    if (i != PAM_SUCCESS) {
        if (tfile != old_tfile) /* the descriptor is not owned by pam data */
            close(tfile);
        RETURN_ERROR(i);
    }

    memset(&tally, 0, sizeof(tally));

    i=set_tally(pamh, uid, opts->filename, &tfile, &tally);
    if (i != PAM_SUCCESS) {
        if (tfile != old_tfile) /* the descriptor is not owned by pam data */
            close(tfile);
        RETURN_ERROR(i);
    }

    if (tfile != old_tfile)
	close(tfile);

    return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

/* --- authentication management functions (only) --- */

int
pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
  int
    rv, tfile = -1;
  time_t
    oldtime = 0;
  struct tally_options
    options, *opts = &options;
  uid_t
    uid;
  const char
    *user;

  rv = tally_parse_args(pamh, opts, PHASE_AUTH, argc, argv);
  if (rv != PAM_SUCCESS)
      RETURN_ERROR(rv);

  if (flags & PAM_SILENT)
    opts->ctrl |= OPT_QUIET;

  rv = pam_get_uid(pamh, &uid, &user, opts);
  if (rv != PAM_SUCCESS)
      RETURN_ERROR(rv);

  rv = tally_bump(1, &oldtime, pamh, uid, user, opts, &tfile);

  tally_set_data(pamh, oldtime, tfile);

  return rv;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags UNUSED,
	       int argc, const char **argv)
{
  int
    rv, tfile = -1;
  time_t
    oldtime = 0;
  struct tally_options
    options, *opts = &options;
  uid_t
    uid;
  const char
    *user;

  rv = tally_parse_args(pamh, opts, PHASE_AUTH, argc, argv);
  if ( rv != PAM_SUCCESS )
      RETURN_ERROR( rv );

  rv = pam_get_uid(pamh, &uid, &user, opts);
  if ( rv != PAM_SUCCESS )
      RETURN_ERROR( rv );

  if ( tally_get_data(pamh, &oldtime, &tfile) != 0 )
  /* no data found */
      return PAM_SUCCESS;

  rv = tally_reset(pamh, uid, opts, tfile);

  pam_set_data(pamh, MODULE_NAME, NULL, NULL);

  return rv;
}

/*---------------------------------------------------------------------*/

/* --- authentication management functions (only) --- */

/* To reset failcount of user on successfull login */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		 int argc, const char **argv)
{
  int
    rv, tfile = -1;
  time_t
    oldtime = 0;
  struct tally_options
    options, *opts = &options;
  uid_t
    uid;
  const char
    *user;

  rv = tally_parse_args(pamh, opts, PHASE_ACCOUNT, argc, argv);
  if ( rv != PAM_SUCCESS )
      RETURN_ERROR( rv );

  rv = pam_get_uid(pamh, &uid, &user, opts);
  if ( rv != PAM_SUCCESS )
      RETURN_ERROR( rv );

  if ( tally_get_data(pamh, &oldtime, &tfile) != 0 )
  /* no data found */
      return PAM_SUCCESS;

  rv = tally_reset(pamh, uid, opts, tfile);

  pam_set_data(pamh, MODULE_NAME, NULL, NULL);

  return rv;
}

/*-----------------------------------------------------------------------*/

#else   /* #ifndef MAIN */

static const char *cline_filename = DEFAULT_LOGFILE;
static tally_t cline_reset = TALLY_HI; /* Default is `interrogate only' */
static int cline_quiet =  0;

/*
 *  Not going to link with pamlib just for these.. :)
 */

static const char *
pam_errors( int i )
{
  switch (i) {
  case PAM_AUTH_ERR:     return _("Authentication error");
  case PAM_SERVICE_ERR:  return _("Service error");
  case PAM_USER_UNKNOWN: return _("Unknown user");
  default:               return _("Unknown error");
  }
}

static int
getopts( char **argv )
{
  const char *pname = *argv;
  for ( ; *argv ; (void)(*argv && ++argv) ) {
    if      ( !strcmp (*argv,"--file")    ) cline_filename=*++argv;
    else if ( !strcmp(*argv,"-f")         ) cline_filename=*++argv;
    else if ( !strncmp(*argv,"--file=",7) ) cline_filename=*argv+7;
    else if ( !strcmp (*argv,"--user")    ) cline_user=*++argv;
    else if ( !strcmp (*argv,"-u")        ) cline_user=*++argv;
    else if ( !strncmp(*argv,"--user=",7) ) cline_user=*argv+7;
    else if ( !strcmp (*argv,"--reset")   ) cline_reset=0;
    else if ( !strcmp (*argv,"-r")        ) cline_reset=0;
    else if ( !strncmp(*argv,"--reset=",8)) {
      if ( sscanf(*argv+8,"%hu",&cline_reset) != 1 )
        fprintf(stderr,_("%s: Bad number given to --reset=\n"),pname), exit(0);
    }
    else if ( !strcmp (*argv,"--quiet")   ) cline_quiet=1;
    else {
      fprintf(stderr,_("%s: Unrecognised option %s\n"),pname,*argv);
      return FALSE;
    }
  }
  return TRUE;
}

static void
print_one(const struct tallylog *tally, uid_t uid)
{
   static int once;
   char *cp = "[UNKNOWN]";
   time_t fail_time;
   struct tm *tm;
   struct passwd *pwent;
   const char *username = "[NONAME]";
   char ptime[80];

   pwent = getpwuid(uid);
   fail_time = tally->fail_time;
   if ((tm = localtime(&fail_time)) != NULL) {
        strftime (ptime, sizeof (ptime), "%D %H:%M:%S", tm);
        cp = ptime;
   }
   if (pwent) {
        username = pwent->pw_name;
   }
   if (!once) {
        printf (_("Login           Failures Latest failure     From\n"));
        once++;
   }
   printf ("%-15.15s %5hu    ", username, tally->fail_cnt);
   if (tally->fail_time) {
        printf ("%-17.17s  %s", cp, tally->fail_line);
   }
   putchar ('\n');
}

int
main( int argc UNUSED, char **argv )
{
  struct tallylog tally;

  if ( ! getopts( argv+1 ) ) {
    printf(_("%s: [-f rooted-filename] [--file rooted-filename]\n"
             "   [-u username] [--user username]\n"
	     "   [-r] [--reset[=n]] [--quiet]\n"),
           *argv);
    exit(2);
  }

  umask(077);

  /*
   * Major difference between individual user and all users:
   *  --user just handles one user, just like PAM.
   *  without --user it handles all users, sniffing cline_filename for nonzeros
   */

  if ( cline_user ) {
    uid_t uid;
    int tfile = -1;
    struct tally_options opts;
    int i;

    memset(&opts, 0, sizeof(opts));
    opts.ctrl = OPT_AUDIT;
    i=pam_get_uid(NULL, &uid, NULL, &opts);
    if ( i != PAM_SUCCESS ) {
      fprintf(stderr,"%s: %s\n",*argv,pam_errors(i));
      exit(1);
    }

    if (cline_reset == 0) {
      struct stat st;

      if (stat(cline_filename, &st) && errno == ENOENT) {
	if (!cline_quiet) {
	  memset(&tally, 0, sizeof(tally));
	  print_one(&tally, uid);
	}
	return 0;	/* no file => nothing to reset */
      }
    }

    i=get_tally(NULL, uid, cline_filename, &tfile, &tally, 0);
    if ( i != PAM_SUCCESS ) {
      if (tfile != -1)
          close(tfile);
      fprintf(stderr, "%s: %s\n", *argv, pam_errors(i));
      exit(1);
    }

    if ( !cline_quiet )
      print_one(&tally, uid);

    if (cline_reset != TALLY_HI) {
#ifdef HAVE_LIBAUDIT
        char buf[64];
        int audit_fd = audit_open();
        snprintf(buf, sizeof(buf), "pam_tally2 uid=%u reset=%hu", uid, cline_reset);
        audit_log_user_message(audit_fd, AUDIT_USER_ACCT,
                buf, NULL, NULL, ttyname(STDIN_FILENO), 1);
        if (audit_fd >=0)
                close(audit_fd);
#endif
        if (cline_reset == 0) {
            memset(&tally, 0, sizeof(tally));
        } else {
            tally.fail_cnt = cline_reset;
        }
        i=set_tally(NULL, uid, cline_filename, &tfile, &tally);
        close(tfile);
        if (i != PAM_SUCCESS) {
            fprintf(stderr,"%s: %s\n",*argv,pam_errors(i));
            exit(1);
        }
    } else {
        close(tfile);
    }
  }
  else /* !cline_user (ie, operate on all users) */ {
    FILE *tfile=fopen(cline_filename, "r");
    uid_t uid=0;
    if (!tfile  && cline_reset != 0) {
	perror(*argv);
	exit(1);
    }

    for ( ; tfile && !feof(tfile); uid++ ) {
      if ( !fread(&tally, sizeof(tally), 1, tfile)
	   || !tally.fail_cnt ) {
	 continue;
      }
      print_one(&tally, uid);
    }
    if (tfile)
      fclose(tfile);
    if ( cline_reset!=0 && cline_reset!=TALLY_HI ) {
      fprintf(stderr,_("%s: Can't reset all users to non-zero\n"),*argv);
    }
    else if ( !cline_reset ) {
#ifdef HAVE_LIBAUDIT
      char buf[64];
      int audit_fd = audit_open();
      snprintf(buf, sizeof(buf), "pam_tally2 uid=all reset=0");
      audit_log_user_message(audit_fd, AUDIT_USER_ACCT,
              buf, NULL, NULL, ttyname(STDIN_FILENO), 1);
      if (audit_fd >=0)
              close(audit_fd);
#endif
      tfile=fopen(cline_filename, "w");
      if ( !tfile ) perror(*argv), exit(0);
      fclose(tfile);
    }
  }
  return 0;
}


#endif   /* #ifndef MAIN */
