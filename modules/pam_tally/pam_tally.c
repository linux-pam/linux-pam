/*
 * pam_tally.c
 *
 */


/* By Tim Baverstock <warwick@mmm.co.uk>, Multi Media Machine Ltd.
 * 5 March 1997
 *
 * Stuff stolen from pam_rootok and pam_listfile
 *
 * Changes by Tomas Mraz <tmraz@redhat.com> 5 January 2005
 * Audit option added for Tomas patch by
 * Sebastien Tricaud <toady@gscore.org> 13 January 2005
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "faillog.h"

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

#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#endif
#include <security/pam_modules.h>

#ifndef TRUE
#define TRUE  1L
#define FALSE 0L
#endif

#ifndef HAVE_FSEEKO
#define fseeko fseek
#endif

/*---------------------------------------------------------------------*/

#define DEFAULT_LOGFILE "/var/log/faillog"
#define MODULE_NAME     "pam_tally"

#define tally_t    unsigned short int
#define TALLY_FMT  "%hu"
#define TALLY_HI   ((tally_t)~0L)

#ifndef FILENAME_MAX
# define FILENAME_MAX MAXPATHLEN
#endif

struct fail_s {
    struct faillog fs_faillog;
#ifndef MAIN
    time_t fs_fail_time;
#endif /* ndef MAIN */
};

struct tally_options {
    const char *filename;
    tally_t deny;
    long lock_time;
    long unlock_time;
    unsigned int ctrl;
};

#define PHASE_UNKNOWN 0
#define PHASE_AUTH    1
#define PHASE_ACCOUNT 2
#define PHASE_SESSION 3

#define OPT_MAGIC_ROOT			  01
#define OPT_FAIL_ON_ERROR		  02
#define OPT_DENY_ROOT			  04
#define OPT_PER_USER			 010
#define	OPT_NO_LOCK_TIME		 020
#define OPT_NO_RESET			 040
#define OPT_AUDIT                       0100
#define OPT_SILENT                      0200
#define OPT_NOLOGNOTICE                 0400


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

#define pam_modutil_getpwnam(pamh,user) getpwnam(user)

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

    for ( ; argc-- > 0; ++argv ) {

      if ( ! strncmp( *argv, "file=", 5 ) ) {
	const char *from = *argv + 5;
        if ( *from!='/' || strlen(from)>FILENAME_MAX-1 ) {
          pam_syslog(pamh, LOG_ERR,
		     "filename not /rooted or too long; %s", *argv);
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
      else if ( ! strcmp( *argv, "even_deny_root_account" ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        opts->ctrl |= OPT_DENY_ROOT;
      }
      else if ( ! strncmp( *argv, "deny=", 5 ) ) {
	log_phase_no_auth(pamh, phase, *argv);
        if ( sscanf((*argv)+5,TALLY_FMT,&opts->deny) != 1 ) {
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
      else if ( ! strcmp( *argv, "per_user" ) )
      {
	log_phase_no_auth(pamh, phase, *argv);
	opts->ctrl |= OPT_PER_USER;
      }
      else if ( ! strcmp( *argv, "no_lock_time") )
      {
	log_phase_no_auth(pamh, phase, *argv);
	opts->ctrl |= OPT_NO_LOCK_TIME;
      }
      else if ( ! strcmp( *argv, "no_reset" ) ) {
        opts->ctrl |= OPT_NO_RESET;
      }
      else if ( ! strcmp ( *argv, "audit") ) {
	opts->ctrl |= OPT_AUDIT;
      }
      else if ( ! strcmp ( *argv, "silent") ) {
	opts->ctrl |= OPT_SILENT;
      }
      else if ( ! strcmp ( *argv, "no_log_info") ) {
	opts->ctrl |= OPT_NOLOGNOTICE;
      }
      else {
        pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
      }
    }

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
      pam_syslog(pamh, LOG_ERR, "pam_get_user; user?");
      return PAM_AUTH_ERR;
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

static void
_cleanup(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED)
{
    free(data);
}


static void
tally_set_data( pam_handle_t *pamh, time_t oldtime )
{
    time_t *data;

    if ( (data=malloc(sizeof(time_t))) != NULL ) {
        *data = oldtime;
        pam_set_data(pamh, MODULE_NAME, (void *)data, _cleanup);
    }
}

static int
tally_get_data( pam_handle_t *pamh, time_t *oldtime )
{
    int rv;
    const void *data;

    rv = pam_get_data(pamh, MODULE_NAME, &data);
    if ( rv == PAM_SUCCESS && data != NULL && oldtime != NULL ) {
      *oldtime = *(const time_t *)data;
      pam_set_data(pamh, MODULE_NAME, NULL, NULL);
    }
    else {
      rv = -1;
      if (oldtime)
	*oldtime = 0;
    }
    return rv;
}
#endif   /* #ifndef MAIN */

/*---------------------------------------------------------------------*/

/* --- Support function: open/create tallyfile and return tally for uid --- */

/* If on entry *tally==TALLY_HI, tallyfile is opened READONLY */
/* Otherwise, if on entry tallyfile doesn't exist, creation is attempted. */

static int
get_tally(pam_handle_t *pamh, tally_t *tally, uid_t uid,
	     const char *filename, FILE **TALLY, struct fail_s *fsp)
{
    struct stat fileinfo;
    int lstat_ret = lstat(filename,&fileinfo);

    if ( lstat_ret && *tally!=TALLY_HI ) {
      int oldmask = umask(077);
      *TALLY=fopen(filename, "a");
      /* Create file, or append-open in pathological case. */
      umask(oldmask);
      if ( !*TALLY ) {
        pam_syslog(pamh, LOG_ALERT, "Couldn't create %s", filename);
        return PAM_AUTH_ERR;
      }
      lstat_ret = fstat(fileno(*TALLY),&fileinfo);
      fclose(*TALLY);
    }

    if ( lstat_ret ) {
      pam_syslog(pamh, LOG_ALERT, "Couldn't stat %s", filename);
      return PAM_AUTH_ERR;
    }

    if((fileinfo.st_mode & S_IWOTH) || !S_ISREG(fileinfo.st_mode)) {
      /* If the file is world writable or is not a
         normal file, return error */
      pam_syslog(pamh, LOG_ALERT,
               "%s is either world writable or not a normal file",
               filename);
      return PAM_AUTH_ERR;
    }

    if ( ! ( *TALLY = fopen(filename,(*tally!=TALLY_HI)?"r+":"r") ) ) {
      pam_syslog(pamh, LOG_ALERT, "Error opening %s for %s", filename, *tally!=TALLY_HI?"update":"read");

/* Discovering why account service fails: e/uid are target user.
 *
 *      perror(MODULE_NAME);
 *      fprintf(stderr,"uid %d euid %d\n",getuid(), geteuid());
 */
      return PAM_AUTH_ERR;
    }

    if ( fseeko( *TALLY, (off_t) uid * sizeof(struct faillog), SEEK_SET ) ) {
          pam_syslog(pamh, LOG_ALERT, "fseek failed for %s", filename);
          fclose(*TALLY);
          return PAM_AUTH_ERR;
    }

    if ( (size_t)fileinfo.st_size <= uid * sizeof(struct faillog) ) {

	memset(fsp, 0, sizeof(struct faillog));
	*tally=0;
	fsp->fs_faillog.fail_time = time(NULL);

    } else if (( fread((char *) &fsp->fs_faillog,
		       sizeof(struct faillog), 1, *TALLY) )==0 ) {

	*tally=0; /* Assuming a gappy filesystem */

    } else {

	*tally = fsp->fs_faillog.fail_cnt;

    }

    return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

/* --- Support function: update and close tallyfile with tally!=TALLY_HI --- */

static int
set_tally(pam_handle_t *pamh, tally_t tally, uid_t uid,
	     const char *filename, FILE **TALLY, struct fail_s *fsp)
{
    int retval = PAM_SUCCESS;

    if ( tally!=TALLY_HI ) {
      if ( fseeko( *TALLY, (off_t) uid * sizeof(struct faillog), SEEK_SET ) ) {
	pam_syslog(pamh, LOG_ALERT, "fseek failed for %s", filename);
	retval = PAM_AUTH_ERR;
      } else {
	fsp->fs_faillog.fail_cnt = tally;
	if (fwrite((char *) &fsp->fs_faillog,
		   sizeof(struct faillog), 1, *TALLY)==0 ) {
	  pam_syslog(pamh, LOG_ALERT, "update (fwrite) failed for %s", filename);
	  retval = PAM_AUTH_ERR;
        }
      }
    }

    if ( fclose(*TALLY) ) {
      pam_syslog(pamh, LOG_ALERT, "update (fclose) failed for %s", filename);
      return PAM_AUTH_ERR;
    }
    *TALLY=NULL;
    return retval;
}

/*---------------------------------------------------------------------*/

/* --- PAM bits --- */

#ifndef MAIN

#define RETURN_ERROR(i) return ((opts->ctrl & OPT_FAIL_ON_ERROR)?(i):(PAM_SUCCESS))

/*---------------------------------------------------------------------*/

/* --- tally bump function: bump tally for uid by (signed) inc --- */

static int
tally_bump (int inc, time_t *oldtime, pam_handle_t *pamh,
            uid_t uid, const char *user, struct tally_options *opts)
{
  tally_t
    tally         = 0;  /* !TALLY_HI --> Log opened for update */

    FILE
      *TALLY = NULL;
    const void
      *remote_host = NULL,
      *cur_tty = NULL;
    struct fail_s fs, *fsp = &fs;
    int i;

    i=get_tally(pamh, &tally, uid, opts->filename, &TALLY, fsp);
    if ( i != PAM_SUCCESS ) { RETURN_ERROR( i ); }

    /* to remember old fail time (for locktime) */
    fsp->fs_fail_time = fsp->fs_faillog.fail_time;
    if ( inc > 0 ) {
        if ( oldtime ) {
            *oldtime = fsp->fs_faillog.fail_time;
        }
        fsp->fs_faillog.fail_time = time(NULL);
    } else {
        if ( oldtime ) {
            fsp->fs_faillog.fail_time = *oldtime;
        }
    }
    (void) pam_get_item(pamh, PAM_RHOST, &remote_host);
    if (!remote_host) {

	(void) pam_get_item(pamh, PAM_TTY, &cur_tty);
	if (!cur_tty) {
	    strncpy(fsp->fs_faillog.fail_line, "unknown",
		    sizeof(fsp->fs_faillog.fail_line) - 1);
	    fsp->fs_faillog.fail_line[sizeof(fsp->fs_faillog.fail_line)-1] = 0;
	} else {
	    strncpy(fsp->fs_faillog.fail_line, cur_tty,
		    sizeof(fsp->fs_faillog.fail_line)-1);
	    fsp->fs_faillog.fail_line[sizeof(fsp->fs_faillog.fail_line)-1] = 0;
	}

    } else {
	strncpy(fsp->fs_faillog.fail_line, remote_host,
		(size_t)sizeof(fsp->fs_faillog.fail_line));
	fsp->fs_faillog.fail_line[sizeof(fsp->fs_faillog.fail_line)-1] = 0;
    }

    if ( !(opts->ctrl & OPT_MAGIC_ROOT) || getuid() ) {   /* magic_root doesn't change tally */

      tally+=inc;

      if ( tally==TALLY_HI ) { /* Overflow *and* underflow. :) */
        tally-=inc;
        pam_syslog(pamh, LOG_ALERT, "Tally %sflowed for user %s",
                 (inc<0)?"under":"over",user);
      }
    }

    i=set_tally(pamh, tally, uid, opts->filename, &TALLY, fsp );
    if ( i != PAM_SUCCESS ) { RETURN_ERROR( i ); }

    return PAM_SUCCESS;
}

static int
tally_check (time_t oldtime, pam_handle_t *pamh, uid_t uid,
               const char *user, struct tally_options *opts)
{
  tally_t
    deny          = opts->deny;
  tally_t
    tally         = TALLY_HI;
  long
    lock_time     = opts->lock_time;

    struct fail_s fs, *fsp = &fs;
    FILE *TALLY=0;
    int i;

    i=get_tally(pamh, &tally, uid, opts->filename, &TALLY, fsp);
    if ( i != PAM_SUCCESS ) { RETURN_ERROR( i ); }

    if ( TALLY != NULL ) {
      fclose(TALLY);
    }

    if ( !(opts->ctrl & OPT_MAGIC_ROOT) || getuid() ) {       /* magic_root skips tally check */

      /* To deny or not to deny; that is the question */

      /* if there's .fail_max entry and per_user=TRUE then deny=.fail_max */

      if ( (fsp->fs_faillog.fail_max) && (opts->ctrl & OPT_PER_USER) ) {
	  deny = fsp->fs_faillog.fail_max;
      }
      if ( (fsp->fs_faillog.fail_locktime) && (opts->ctrl & OPT_PER_USER) ) {
	  lock_time = fsp->fs_faillog.fail_locktime;
      }
      if (lock_time && oldtime
	  && !(opts->ctrl & OPT_NO_LOCK_TIME) )
      {
	if ( lock_time + oldtime > time(NULL) )
	{
	  if (!(opts->ctrl & OPT_SILENT))
	       pam_info (pamh,
			 _("Account temporary locked (%ld seconds left)"),
			 oldtime+lock_time-time(NULL));

	  if (!(opts->ctrl & OPT_NOLOGNOTICE))
	       pam_syslog (pamh, LOG_NOTICE,
			   "user %s (%lu) has time limit [%lds left]"
			   " since last failure.",
			   user, (unsigned long int) uid,
			   oldtime+lock_time-time(NULL));
		return PAM_AUTH_ERR;
	}
      }
      if (opts->unlock_time && oldtime)
      {
	if ( opts->unlock_time + oldtime <= time(NULL) )
	{       /* ignore deny check after unlock_time elapsed */
		return PAM_SUCCESS;
	}
      }
      if (
        ( deny != 0 ) &&                     /* deny==0 means no deny        */
        ( tally > deny ) &&                  /* tally>deny means exceeded    */
        ( ((opts->ctrl & OPT_DENY_ROOT) || uid) )    /* even_deny stops uid check    */
        ) {
	if (!(opts->ctrl & OPT_SILENT))
	  pam_info (pamh, _("Account locked due to %u failed logins"),
		    (unsigned int)tally);

	if (!(opts->ctrl & OPT_NOLOGNOTICE))
	  pam_syslog(pamh, LOG_NOTICE,
		     "user %s (%lu) tally "TALLY_FMT", deny "TALLY_FMT,
		     user, (unsigned long int) uid, tally, deny);
        return PAM_AUTH_ERR;                 /* Only unconditional failure   */
      }
    }

    return PAM_SUCCESS;
}

static int
tally_reset (pam_handle_t *pamh, uid_t uid, struct tally_options *opts)
{
  tally_t
    tally         = 0;  /* !TALLY_HI --> Log opened for update */

    struct fail_s fs, *fsp = &fs;
    FILE *TALLY=0;
    int i;

    i=get_tally(pamh, &tally, uid, opts->filename, &TALLY, fsp);
    if ( i != PAM_SUCCESS ) { RETURN_ERROR( i ); }

      /* resets if not magic root
       */

    if ( (!(opts->ctrl & OPT_MAGIC_ROOT) || getuid())
         && !(opts->ctrl & OPT_NO_RESET) )
        { tally=0; }

    if (tally == 0)
    {
	fsp->fs_faillog.fail_time = (time_t) 0;
	strcpy(fsp->fs_faillog.fail_line, "");
    }

    i=set_tally(pamh, tally, uid, opts->filename, &TALLY, fsp);
    if ( i != PAM_SUCCESS ) { RETURN_ERROR( i ); }

    return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

/* --- authentication management functions (only) --- */

#ifdef PAM_SM_AUTH

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  int
    rvcheck, rvbump;
  time_t
    oldtime = 0;
  struct tally_options
    options, *opts = &options;
  uid_t
    uid;
  const char
    *user;

  rvcheck = tally_parse_args(pamh, opts, PHASE_AUTH, argc, argv);
  if ( rvcheck != PAM_SUCCESS )
      RETURN_ERROR( rvcheck );

  if (flags & PAM_SILENT)
    opts->ctrl |= OPT_SILENT;

  rvcheck = pam_get_uid(pamh, &uid, &user, opts);
  if ( rvcheck != PAM_SUCCESS )
      RETURN_ERROR( rvcheck );

  rvbump = tally_bump(1, &oldtime, pamh, uid, user, opts);
  rvcheck = tally_check(oldtime, pamh, uid, user, opts);

  tally_set_data(pamh, oldtime);

  return rvcheck != PAM_SUCCESS ? rvcheck : rvbump;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
  int
    rv;
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

  if (flags & PAM_SILENT)
    opts->ctrl |= OPT_SILENT;

  rv = pam_get_uid(pamh, &uid, &user, opts);
  if ( rv != PAM_SUCCESS )
      RETURN_ERROR( rv );

  if ( tally_get_data(pamh, &oldtime) != 0 )
  /* no data found */
      return PAM_SUCCESS;

  if ( (rv=tally_bump(-1, &oldtime, pamh, uid, user, opts)) != PAM_SUCCESS )
      return rv;
  return tally_reset(pamh, uid, opts);
}

#endif

/*---------------------------------------------------------------------*/

/* --- authentication management functions (only) --- */

#ifdef PAM_SM_ACCOUNT

/* To reset failcount of user on successfull login */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  int
    rv;
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

  if (flags & PAM_SILENT)
    opts->ctrl |= OPT_SILENT;

  rv = pam_get_uid(pamh, &uid, &user, opts);
  if ( rv != PAM_SUCCESS )
      RETURN_ERROR( rv );

  if ( tally_get_data(pamh, &oldtime) != 0 )
  /* no data found */
      return PAM_SUCCESS;

  if ( (rv=tally_bump(-1, &oldtime, pamh, uid, user, opts)) != PAM_SUCCESS )
      return rv;
  return tally_reset(pamh, uid, opts);
}

#endif  /* #ifdef PAM_SM_ACCOUNT */

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
    else if ( !strncmp(*argv,"--file=",7) ) cline_filename=*argv+7;
    else if ( !strcmp (*argv,"--user")    ) cline_user=*++argv;
    else if ( !strncmp(*argv,"--user=",7) ) cline_user=*argv+7;
    else if ( !strcmp (*argv,"--reset")   ) cline_reset=0;
    else if ( !strncmp(*argv,"--reset=",8)) {
      if ( sscanf(*argv+8,TALLY_FMT,&cline_reset) != 1 )
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

int main ( int argc UNUSED, char **argv )
{
  struct fail_s fs, *fsp = &fs;

  if ( ! getopts( argv+1 ) ) {
    printf(_("%s: [--file rooted-filename] [--user username] "
	     "[--reset[=n]] [--quiet]\n"),
           *argv);
    exit(0);
  }

  umask(077);

  /*
   * Major difference between individual user and all users:
   *  --user just handles one user, just like PAM.
   *  --user=* handles all users, sniffing cline_filename for nonzeros
   */

  if ( cline_user ) {
    uid_t uid;
    tally_t tally=cline_reset;
    FILE *TALLY=0;
    struct tally_options opts;
    int i;

    memset(&opts, 0, sizeof(opts));
    opts.ctrl = OPT_AUDIT;
    i=pam_get_uid(NULL, &uid, NULL, &opts);
    if ( i != PAM_SUCCESS ) {
      fprintf(stderr,"%s: %s\n",*argv,pam_errors(i));
      exit(0);
    }

    i=get_tally(NULL, &tally, uid, cline_filename, &TALLY, fsp);
    if ( i != PAM_SUCCESS ) {
      fprintf(stderr,"%s: %s\n",*argv,pam_errors(i));
      exit(0);
    }

    if ( !cline_quiet )
      printf("User %s\t(%lu)\t%s "TALLY_FMT"\n",cline_user,
	     (unsigned long int) uid,
             (cline_reset!=TALLY_HI)?"had":"has",tally);

    i=set_tally(NULL, cline_reset, uid, cline_filename, &TALLY, fsp);
    if ( i != PAM_SUCCESS ) {
      fprintf(stderr,"%s: %s\n",*argv,pam_errors(i));
      exit(0);
    }
  }
  else /* !cline_user (ie, operate on all users) */ {
    FILE *TALLY=fopen(cline_filename, "r");
    uid_t uid=0;
    if ( !TALLY ) perror(*argv), exit(0);

    for ( ; !feof(TALLY); uid++ ) {
      tally_t tally;
      struct passwd *pw;
      if ( ! fread((char *) &fsp->fs_faillog,
		   sizeof (struct faillog), 1, TALLY)
	   || ! fsp->fs_faillog.fail_cnt ) {
	continue;
      }
      tally = fsp->fs_faillog.fail_cnt;

      if ( ( pw=getpwuid(uid) ) ) {
        printf("User %s\t(%lu)\t%s "TALLY_FMT"\n",pw->pw_name,
	       (unsigned long int) uid,
               (cline_reset!=TALLY_HI)?"had":"has",tally);
      }
      else {
        printf("User [NONAME]\t(%lu)\t%s "TALLY_FMT"\n",
	       (unsigned long int) uid,
               (cline_reset!=TALLY_HI)?"had":"has",tally);
      }
    }
    fclose(TALLY);
    if ( cline_reset!=0 && cline_reset!=TALLY_HI ) {
      fprintf(stderr,_("%s: Can't reset all users to non-zero\n"),*argv);
    }
    else if ( !cline_reset ) {
      TALLY=fopen(cline_filename, "w");
      if ( !TALLY ) perror(*argv), exit(0);
      fclose(TALLY);
    }
  }
  return 0;
}


#endif   /* #ifndef MAIN */
