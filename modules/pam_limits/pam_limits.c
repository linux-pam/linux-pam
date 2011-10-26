/*
 * pam_limits - impose resource limits when opening a user session
 *
 * 1.6 - modified for PLD (added process priority settings)
 *       by Marcin Korzonek <mkorz@shadow.eu.org>
 * 1.5 - Elliot Lee's "max system logins patch"
 * 1.4 - addressed bug in configuration file parser
 * 1.3 - modified the configuration file format
 * 1.2 - added 'debug' and 'conf=' arguments
 * 1.1 - added @group support
 * 1.0 - initial release - Linux ONLY
 *
 * See end for Copyright information
 */

#if !defined(linux) && !defined(__linux)
#warning THIS CODE IS KNOWN TO WORK ONLY ON LINUX !!!
#endif

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <limits.h>
#include <glob.h>
#include <utmp.h>
#ifndef UT_USER  /* some systems have ut_name instead of ut_user */
#define UT_USER ut_user
#endif

#include <grp.h>
#include <pwd.h>
#include <locale.h>

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#endif

/* Module defines */
#define LINE_LENGTH 1024

#define LIMITS_DEF_USER     0 /* limit was set by an user entry */
#define LIMITS_DEF_GROUP    1 /* limit was set by a group entry */
#define LIMITS_DEF_ALLGROUP 2 /* limit was set by a group entry */
#define LIMITS_DEF_ALL      3 /* limit was set by an all entry */
#define LIMITS_DEF_DEFAULT  4 /* limit was set by a default entry */
#define LIMITS_DEF_KERNEL   5 /* limit was set from /proc/1/limits */
#define LIMITS_DEF_NONE     6 /* this limit was not set yet */

#define LIMIT_RANGE_ERR    -1 /* error in specified uid/gid range */
#define LIMIT_RANGE_NONE    0 /* no range specified */
#define LIMIT_RANGE_ONE     1 /* exact uid/gid specified (:max_uid)*/
#define LIMIT_RANGE_MIN     2 /* only minimum uid/gid specified (min_uid:) */
#define LIMIT_RANGE_MM      3 /* both min and max uid/gid specified (min_uid:max_uid) */

static const char *limits_def_names[] = {
       "USER",
       "GROUP",
       "ALLGROUP",
       "ALL",
       "DEFAULT",
       "KERNEL",
       "NONE",
       NULL
};

struct user_limits_struct {
    int supported;
    int src_soft;
    int src_hard;
    struct rlimit limit;
};

/* internal data */
struct pam_limit_s {
    int login_limit;     /* the max logins limit */
    int login_limit_def; /* which entry set the login limit */
    int flag_numsyslogins; /* whether to limit logins only for a
			      specific user or to count all logins */
    int priority;	 /* the priority to run user process with */
    struct user_limits_struct limits[RLIM_NLIMITS];
    const char *conf_file;
    int utmp_after_pam_call;
    char login_group[LINE_LENGTH];
};

#define LIMIT_LOGIN RLIM_NLIMITS+1
#define LIMIT_NUMSYSLOGINS RLIM_NLIMITS+2

#define LIMIT_PRI RLIM_NLIMITS+3

#define LIMIT_SOFT  1
#define LIMIT_HARD  2

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

/* argument parsing */

#define PAM_DEBUG_ARG       0x0001
#define PAM_UTMP_EARLY      0x0004
#define PAM_NO_AUDIT        0x0008
#define PAM_SET_ALL         0x0010

/* Limits from globbed files. */
#define LIMITS_CONF_GLOB LIMITS_FILE_DIR

#define CONF_FILE (pl->conf_file != NULL)?pl->conf_file:LIMITS_FILE

static int
_pam_parse (const pam_handle_t *pamh, int argc, const char **argv,
	    struct pam_limit_s *pl)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug")) {
	    ctrl |= PAM_DEBUG_ARG;
	} else if (!strncmp(*argv,"conf=",5)) {
	    pl->conf_file = *argv+5;
	} else if (!strcmp(*argv,"utmp_early")) {
	    ctrl |= PAM_UTMP_EARLY;
	} else if (!strcmp(*argv,"noaudit")) {
	    ctrl |= PAM_NO_AUDIT;
	} else if (!strcmp(*argv,"set_all")) {
	    ctrl |= PAM_SET_ALL;
	} else {
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
	}
    }

    return ctrl;
}

static const char *
rlimit2str (int i)
{
  switch (i) {
  case RLIMIT_CPU:
    return "cpu";
    break;
  case RLIMIT_FSIZE:
    return "fsize";
    break;
  case RLIMIT_DATA:
    return "data";
    break;
  case RLIMIT_STACK:
    return "stack";
    break;
  case RLIMIT_CORE:
    return "core";
    break;
  case RLIMIT_RSS:
    return "rss";
    break;
  case RLIMIT_NPROC:
    return "nproc";
    break;
  case RLIMIT_NOFILE:
    return "nofile";
    break;
  case RLIMIT_MEMLOCK:
    return "memlock";
    break;
#ifdef RLIMIT_AS
  case RLIMIT_AS:
    return "as";
    break;
#endif
#ifdef RLIMIT_LOCKS
  case RLIMIT_LOCKS:
    return "locks";
    break;
#endif
#ifdef RLIMIT_SIGPENDING
  case RLIMIT_SIGPENDING:
    return "sigpending";
    break;
#endif
#ifdef RLIMIT_MSGQUEUE
  case RLIMIT_MSGQUEUE:
    return "msgqueue";
    break;
#endif
#ifdef RLIMIT_NICE
  case RLIMIT_NICE:
    return "nice";
    break;
#endif
#ifdef RLIMIT_RTPRIO
  case RLIMIT_RTPRIO:
    return "rtprio";
    break;
#endif
  default:
    return "UNKNOWN";
    break;
  }
}


#define LIMITED_OK 0 /* limit setting appeared to work */
#define LIMIT_ERR  1 /* error setting a limit */
#define LOGIN_ERR  2 /* too many logins err */

/* Counts the number of user logins and check against the limit*/
static int
check_logins (pam_handle_t *pamh, const char *name, int limit, int ctrl,
              struct pam_limit_s *pl)
{
    struct utmp *ut;
    int count;

    if (ctrl & PAM_DEBUG_ARG) {
        pam_syslog(pamh, LOG_DEBUG,
		   "checking logins for '%s' (maximum of %d)", name, limit);
    }

    if (limit < 0)
        return 0; /* no limits imposed */
    if (limit == 0) /* maximum 0 logins ? */ {
        pam_syslog(pamh, LOG_WARNING, "No logins allowed for '%s'", name);
        return LOGIN_ERR;
    }

    setutent();

    /* Because there is no definition about when an application
       actually adds a utmp entry, some applications bizarrely do the
       utmp call before the have PAM authenticate them to the system:
       you're logged it, sort of...? Anyway, you can use the
       "utmp_early" module argument in your PAM config file to make
       allowances for this sort of problem. (There should be a PAM
       standard for this, since if a module wants to actually map a
       username then any early utmp entry will be for the unmapped
       name = broken.) */

    if (ctrl & PAM_UTMP_EARLY) {
	count = 0;
    } else {
	count = 1;
    }

    while((ut = getutent())) {
#ifdef USER_PROCESS
        if (ut->ut_type != USER_PROCESS) {
            continue;
	}
#endif
        if (ut->UT_USER[0] == '\0') {
            continue;
	}
        if (!pl->flag_numsyslogins) {
	    if (((pl->login_limit_def == LIMITS_DEF_USER)
	         || (pl->login_limit_def == LIMITS_DEF_GROUP)
		 || (pl->login_limit_def == LIMITS_DEF_DEFAULT))
		&& strncmp(name, ut->UT_USER, sizeof(ut->UT_USER)) != 0) {
                continue;
	    }
	    if ((pl->login_limit_def == LIMITS_DEF_ALLGROUP)
		&& !pam_modutil_user_in_group_nam_nam(pamh, ut->UT_USER, pl->login_group)) {
                continue;
	    }
	}
	if (++count > limit) {
	    break;
	}
    }
    endutent();
    if (count > limit) {
	if (name) {
	    pam_syslog(pamh, LOG_WARNING,
		       "Too many logins (max %d) for %s", limit, name);
	} else {
	    pam_syslog(pamh, LOG_WARNING, "Too many system logins (max %d)", limit);
	}
        return LOGIN_ERR;
    }
    return 0;
}

static const char *lnames[RLIM_NLIMITS] = {
        [RLIMIT_CPU] = "Max cpu time",
        [RLIMIT_FSIZE] = "Max file size",
        [RLIMIT_DATA] = "Max data size",
        [RLIMIT_STACK] = "Max stack size",
        [RLIMIT_CORE] = "Max core file size",
        [RLIMIT_RSS] = "Max resident set",
        [RLIMIT_NPROC] = "Max processes",
        [RLIMIT_NOFILE] = "Max open files",
        [RLIMIT_MEMLOCK] = "Max locked memory",
#ifdef RLIMIT_AS
        [RLIMIT_AS] = "Max address space",
#endif
#ifdef RLIMIT_LOCKS
        [RLIMIT_LOCKS] = "Max file locks",
#endif
#ifdef RLIMIT_SIGPENDING
        [RLIMIT_SIGPENDING] = "Max pending signals",
#endif
#ifdef RLIMIT_MSGQUEUE
        [RLIMIT_MSGQUEUE] = "Max msgqueue size",
#endif
#ifdef RLIMIT_NICE
        [RLIMIT_NICE] = "Max nice priority",
#endif
#ifdef RLIMIT_RTPRIO
        [RLIMIT_RTPRIO] = "Max realtime priority",
#endif
#ifdef RLIMIT_RTTIME
        [RLIMIT_RTTIME] = "Max realtime timeout",
#endif
};

static int str2rlimit(char *name) {
    int i;
    if (!name || *name == '\0')
        return -1;
    for(i = 0; i < RLIM_NLIMITS; i++) {
        if (strcmp(name, lnames[i]) == 0) return i;
    }
    return -1;
}

static rlim_t str2rlim_t(char *value) {
    unsigned long long rlimit = 0;

    if (!value) return (rlim_t)rlimit;
    if (strcmp(value, "unlimited") == 0) {
        return RLIM_INFINITY;
    }
    rlimit = strtoull(value, NULL, 10);
    return (rlim_t)rlimit;
}

#define LIMITS_SKIP_WHITESPACE { \
        /* step backwards over spaces */ \
        pos--; \
        while (pos && line[pos] == ' ') pos--; \
        if (!pos) continue; \
        line[pos+1] = '\0'; \
}
#define LIMITS_MARK_ITEM(item) { \
        /* step backwards over non-spaces */ \
        pos--; \
        while (pos && line[pos] != ' ') pos--; \
        if (!pos) continue; \
        item = line + pos + 1; \
}

static void parse_kernel_limits(pam_handle_t *pamh, struct pam_limit_s *pl, int ctrl)
{
    int i, maxlen = 0;
    FILE *limitsfile;
    const char *proclimits = "/proc/1/limits";
    char line[256];
    char *units, *hard, *soft, *name;

    if (!(limitsfile = fopen(proclimits, "r"))) {
        pam_syslog(pamh, LOG_WARNING, "Could not read %s (%s), using PAM defaults", proclimits, strerror(errno));
        return;
    }

    while (fgets(line, 256, limitsfile)) {
        int pos = strlen(line);
        if (pos < 2) continue;

        /* drop trailing newline */
        if (line[pos-1] == '\n') {
            pos--;
            line[pos] = '\0';
        }

        /* determine formatting boundry of limits report */
        if (!maxlen && strncmp(line, "Limit", 5) == 0) {
            maxlen = pos;
            continue;
        }

        if (pos == maxlen) {
            /* step backwards over "Units" name */
            LIMITS_SKIP_WHITESPACE;
            LIMITS_MARK_ITEM(units);
        }
        else {
            units = "";
        }

        /* step backwards over "Hard Limit" value */
        LIMITS_SKIP_WHITESPACE;
        LIMITS_MARK_ITEM(hard);

        /* step backwards over "Soft Limit" value */
        LIMITS_SKIP_WHITESPACE;
        LIMITS_MARK_ITEM(soft);

        /* step backwards over name of limit */
        LIMITS_SKIP_WHITESPACE;
        name = line;

        i = str2rlimit(name);
        if (i < 0 || i >= RLIM_NLIMITS) {
            if (ctrl & PAM_DEBUG_ARG)
                pam_syslog(pamh, LOG_DEBUG, "Unknown kernel rlimit '%s' ignored", name);
            continue;
        }
        pl->limits[i].limit.rlim_cur = str2rlim_t(soft);
        pl->limits[i].limit.rlim_max = str2rlim_t(hard);
        pl->limits[i].src_soft = LIMITS_DEF_KERNEL;
        pl->limits[i].src_hard = LIMITS_DEF_KERNEL;
    }
    fclose(limitsfile);
}

static int init_limits(pam_handle_t *pamh, struct pam_limit_s *pl, int ctrl)
{
    int i;
    int retval = PAM_SUCCESS;

    D(("called."));

    for(i = 0; i < RLIM_NLIMITS; i++) {
	int r = getrlimit(i, &pl->limits[i].limit);
	if (r == -1) {
	    pl->limits[i].supported = 0;
	    if (errno != EINVAL) {
		retval = !PAM_SUCCESS;
	    }
	} else {
	    pl->limits[i].supported = 1;
	    pl->limits[i].src_soft = LIMITS_DEF_NONE;
	    pl->limits[i].src_hard = LIMITS_DEF_NONE;
	}
    }

#ifdef __linux__
    if (ctrl & PAM_SET_ALL) {
      parse_kernel_limits(pamh, pl, ctrl);

      for(i = 0; i < RLIM_NLIMITS; i++) {
	if (pl->limits[i].supported &&
	    (pl->limits[i].src_soft == LIMITS_DEF_NONE ||
	     pl->limits[i].src_hard == LIMITS_DEF_NONE)) {
	  pam_syslog(pamh, LOG_WARNING, "Did not find kernel RLIMIT for %s, using PAM default", rlimit2str(i));
	}
      }
    }
#endif

    errno = 0;
    pl->priority = getpriority (PRIO_PROCESS, 0);
    if (pl->priority == -1 && errno != 0)
      retval = !PAM_SUCCESS;
    pl->login_limit = -2;
    pl->login_limit_def = LIMITS_DEF_NONE;

    return retval;
}

static void
process_limit (const pam_handle_t *pamh, int source, const char *lim_type,
	       const char *lim_item, const char *lim_value,
	       int ctrl, struct pam_limit_s *pl)
{
    int limit_item;
    int limit_type = 0;
    int int_value = 0;
    rlim_t rlimit_value = 0;
    char *endptr;
    const char *value_orig = lim_value;

    if (ctrl & PAM_DEBUG_ARG)
	 pam_syslog(pamh, LOG_DEBUG, "%s: processing %s %s %s for %s",
		    __FUNCTION__, lim_type, lim_item, lim_value,
		    limits_def_names[source]);

    if (strcmp(lim_item, "cpu") == 0)
        limit_item = RLIMIT_CPU;
    else if (strcmp(lim_item, "fsize") == 0)
        limit_item = RLIMIT_FSIZE;
    else if (strcmp(lim_item, "data") == 0)
	limit_item = RLIMIT_DATA;
    else if (strcmp(lim_item, "stack") == 0)
	limit_item = RLIMIT_STACK;
    else if (strcmp(lim_item, "core") == 0)
	limit_item = RLIMIT_CORE;
    else if (strcmp(lim_item, "rss") == 0)
	limit_item = RLIMIT_RSS;
    else if (strcmp(lim_item, "nproc") == 0)
	limit_item = RLIMIT_NPROC;
    else if (strcmp(lim_item, "nofile") == 0)
	limit_item = RLIMIT_NOFILE;
    else if (strcmp(lim_item, "memlock") == 0)
	limit_item = RLIMIT_MEMLOCK;
#ifdef RLIMIT_AS
    else if (strcmp(lim_item, "as") == 0)
	limit_item = RLIMIT_AS;
#endif /*RLIMIT_AS*/
#ifdef RLIMIT_LOCKS
    else if (strcmp(lim_item, "locks") == 0)
	limit_item = RLIMIT_LOCKS;
#endif
#ifdef RLIMIT_SIGPENDING
    else if (strcmp(lim_item, "sigpending") == 0)
	limit_item = RLIMIT_SIGPENDING;
#endif
#ifdef RLIMIT_MSGQUEUE
    else if (strcmp(lim_item, "msgqueue") == 0)
	limit_item = RLIMIT_MSGQUEUE;
#endif
#ifdef RLIMIT_NICE
    else if (strcmp(lim_item, "nice") == 0)
	limit_item = RLIMIT_NICE;
#endif
#ifdef RLIMIT_RTPRIO
    else if (strcmp(lim_item, "rtprio") == 0)
	limit_item = RLIMIT_RTPRIO;
#endif
    else if (strcmp(lim_item, "maxlogins") == 0) {
	limit_item = LIMIT_LOGIN;
	pl->flag_numsyslogins = 0;
    } else if (strcmp(lim_item, "maxsyslogins") == 0) {
	limit_item = LIMIT_NUMSYSLOGINS;
	pl->flag_numsyslogins = 1;
    } else if (strcmp(lim_item, "priority") == 0) {
	limit_item = LIMIT_PRI;
    } else {
        pam_syslog(pamh, LOG_DEBUG, "unknown limit item '%s'", lim_item);
        return;
    }

    if (strcmp(lim_type,"soft")==0)
	limit_type=LIMIT_SOFT;
    else if (strcmp(lim_type, "hard")==0)
	limit_type=LIMIT_HARD;
    else if (strcmp(lim_type,"-")==0)
	limit_type=LIMIT_SOFT | LIMIT_HARD;
    else if (limit_item != LIMIT_LOGIN && limit_item != LIMIT_NUMSYSLOGINS) {
        pam_syslog(pamh, LOG_DEBUG, "unknown limit type '%s'", lim_type);
        return;
    }
	if (limit_item != LIMIT_PRI
#ifdef RLIMIT_NICE
	    && limit_item != RLIMIT_NICE
#endif
	    && (strcmp(lim_value, "-1") == 0
		|| strcmp(lim_value, "-") == 0 || strcmp(lim_value, "unlimited") == 0
		|| strcmp(lim_value, "infinity") == 0)) {
		int_value = -1;
		rlimit_value = RLIM_INFINITY;
	} else if (limit_item == LIMIT_PRI || limit_item == LIMIT_LOGIN ||
#ifdef RLIMIT_NICE
		limit_item == RLIMIT_NICE ||
#endif
		limit_item == LIMIT_NUMSYSLOGINS) {
		long temp;
		temp = strtol (lim_value, &endptr, 10);
		temp = temp < INT_MAX ? temp : INT_MAX;
		int_value = temp > INT_MIN ? temp : INT_MIN;
		if (int_value == 0 && value_orig == endptr) {
			pam_syslog(pamh, LOG_DEBUG,
				   "wrong limit value '%s' for limit type '%s'",
				   lim_value, lim_type);
            return;
		}
	} else {
#ifdef __USE_FILE_OFFSET64
		rlimit_value = strtoull (lim_value, &endptr, 10);
#else
		rlimit_value = strtoul (lim_value, &endptr, 10);
#endif
		if (rlimit_value == 0 && value_orig == endptr) {
			pam_syslog(pamh, LOG_DEBUG,
				   "wrong limit value '%s' for limit type '%s'",
				   lim_value, lim_type);
			return;
		}
	}

    /* one more special case when limiting logins */
    if ((source == LIMITS_DEF_ALL || source == LIMITS_DEF_ALLGROUP)
		&& (limit_item != LIMIT_LOGIN)) {
	if (ctrl & PAM_DEBUG_ARG)
	    pam_syslog(pamh, LOG_DEBUG,
		       "'%%' domain valid for maxlogins type only");
	return;
    }

    switch(limit_item) {
        case RLIMIT_CPU:
	  if (rlimit_value != RLIM_INFINITY)
	    {
	      if (rlimit_value >= RLIM_INFINITY/60)
		rlimit_value = RLIM_INFINITY;
	      else
		rlimit_value *= 60;
	    }
         break;
        case RLIMIT_FSIZE:
        case RLIMIT_DATA:
        case RLIMIT_STACK:
        case RLIMIT_CORE:
        case RLIMIT_RSS:
        case RLIMIT_MEMLOCK:
#ifdef RLIMIT_AS
        case RLIMIT_AS:
#endif
         if (rlimit_value != RLIM_INFINITY)
	   {
	     if (rlimit_value >= RLIM_INFINITY/1024)
	       rlimit_value = RLIM_INFINITY;
	     else
	       rlimit_value *= 1024;
	   }
	 break;
#ifdef RLIMIT_NICE
	case RLIMIT_NICE:
	 if (int_value > 19)
	    int_value = 19;
	 if (int_value < -20)
	   int_value = -20;
	 rlimit_value = 20 - int_value;
         break;
#endif
    }

    if ( (limit_item != LIMIT_LOGIN)
	 && (limit_item != LIMIT_NUMSYSLOGINS)
	 && (limit_item != LIMIT_PRI) ) {
        if (limit_type & LIMIT_SOFT) {
	    if (pl->limits[limit_item].src_soft < source) {
                return;
	    } else {
                pl->limits[limit_item].limit.rlim_cur = rlimit_value;
                pl->limits[limit_item].src_soft = source;
            }
	}
        if (limit_type & LIMIT_HARD) {
	    if (pl->limits[limit_item].src_hard < source) {
                return;
            } else {
                pl->limits[limit_item].limit.rlim_max = rlimit_value;
                pl->limits[limit_item].src_hard = source;
            }
	}
    } else {
	/* recent kernels support negative priority limits (=raise priority) */

	if (limit_item == LIMIT_PRI) {
		pl->priority = int_value;
	} else {
	        if (pl->login_limit_def < source) {
	            return;
	        } else {
	            pl->login_limit = int_value;
	            pl->login_limit_def = source;
		}
	}
    }
    return;
}

static int
parse_uid_range(pam_handle_t *pamh, const char *domain,
		uid_t *min_uid, uid_t *max_uid)
{
    const char *range = domain;
    char *pmax;
    char *endptr;
    int rv = LIMIT_RANGE_MM;

    if ((pmax=strchr(range, ':')) == NULL)
	return LIMIT_RANGE_NONE;
    ++pmax;

    if (range[0] == '@' || range[0] == '%')
	++range;

    if (range[0] == ':')
	rv = LIMIT_RANGE_ONE;
    else {
	    errno = 0;
	    *min_uid = strtoul (range, &endptr, 10);
	    if (errno != 0 || (range == endptr) || *endptr != ':') {
		pam_syslog(pamh, LOG_DEBUG,
			   "wrong min_uid/gid value in '%s'", domain);
		return LIMIT_RANGE_ERR;
	    }
    }

    if (*pmax == '\0') {
	if (rv == LIMIT_RANGE_ONE)
	    return LIMIT_RANGE_ERR;
	else
	    return LIMIT_RANGE_MIN;
    }

    errno = 0;
    *max_uid = strtoul (pmax, &endptr, 10);
    if (errno != 0 || (pmax == endptr) || *endptr != '\0') {
	pam_syslog(pamh, LOG_DEBUG,
		   "wrong max_uid/gid value in '%s'", domain);
	return LIMIT_RANGE_ERR;
    }

    if (rv == LIMIT_RANGE_ONE)
	*min_uid = *max_uid;
    return rv;
}

static int
parse_config_file(pam_handle_t *pamh, const char *uname, uid_t uid, gid_t gid,
			     int ctrl, struct pam_limit_s *pl)
{
    FILE *fil;
    char buf[LINE_LENGTH];

    /* check for the LIMITS_FILE */
    if (ctrl & PAM_DEBUG_ARG)
        pam_syslog(pamh, LOG_DEBUG, "reading settings from '%s'", CONF_FILE);
    fil = fopen(CONF_FILE, "r");
    if (fil == NULL) {
        pam_syslog (pamh, LOG_WARNING,
		    "cannot read settings from %s: %m", CONF_FILE);
        return PAM_SERVICE_ERR;
    }

    /* start the show */
    while (fgets(buf, LINE_LENGTH, fil) != NULL) {
        char domain[LINE_LENGTH];
        char ltype[LINE_LENGTH];
        char item[LINE_LENGTH];
        char value[LINE_LENGTH];
        int i;
        int rngtype;
        size_t j;
        char *tptr,*line;
        uid_t min_uid = (uid_t)-1, max_uid = (uid_t)-1;

        line = buf;
        /* skip the leading white space */
        while (*line && isspace(*line))
            line++;

        /* Rip off the comments */
        tptr = strchr(line,'#');
        if (tptr)
            *tptr = '\0';
        /* Rip off the newline char */
        tptr = strchr(line,'\n');
        if (tptr)
            *tptr = '\0';
        /* Anything left ? */
        if (!strlen(line))
            continue;

	domain[0] = ltype[0] = item[0] = value[0] = '\0';

	i = sscanf(line,"%s%s%s%s", domain, ltype, item, value);
	D(("scanned line[%d]: domain[%s], ltype[%s], item[%s], value[%s]",
	   i, domain, ltype, item, value));

        for(j=0; j < strlen(ltype); j++)
            ltype[j]=tolower(ltype[j]);

	if ((rngtype=parse_uid_range(pamh, domain, &min_uid, &max_uid)) < 0) {
	    pam_syslog(pamh, LOG_WARNING, "invalid uid range '%s' - skipped", domain);
	    continue;
	}

        if (i == 4) { /* a complete line */
	    for(j=0; j < strlen(item); j++)
		item[j]=tolower(item[j]);
	    for(j=0; j < strlen(value); j++)
		value[j]=tolower(value[j]);

            if (strcmp(uname, domain) == 0) /* this user have a limit */
                process_limit(pamh, LIMITS_DEF_USER, ltype, item, value, ctrl, pl);
            else if (domain[0]=='@') {
		if (ctrl & PAM_DEBUG_ARG) {
			pam_syslog(pamh, LOG_DEBUG,
				   "checking if %s is in group %s",
				   uname, domain + 1);
		}
		switch(rngtype) {
		    case LIMIT_RANGE_NONE:
			if (pam_modutil_user_in_group_nam_nam(pamh, uname, domain+1))
			    process_limit(pamh, LIMITS_DEF_GROUP, ltype, item, value, ctrl,
					  pl);
			break;
		    case LIMIT_RANGE_ONE:
			if (pam_modutil_user_in_group_nam_gid(pamh, uname, (gid_t)max_uid))
			    process_limit(pamh, LIMITS_DEF_GROUP, ltype, item, value, ctrl,
				  pl);
			break;
		    case LIMIT_RANGE_MM:
			if (gid > (gid_t)max_uid)
			    break;
			/* fallthrough */
		    case LIMIT_RANGE_MIN:
			if (gid >= (gid_t)min_uid)
			    process_limit(pamh, LIMITS_DEF_GROUP, ltype, item, value, ctrl,
					  pl);
		}
            } else if (domain[0]=='%') {
		if (ctrl & PAM_DEBUG_ARG) {
			pam_syslog(pamh, LOG_DEBUG,
				   "checking if %s is in group %s",
				   uname, domain + 1);
		}
		switch(rngtype) {
		    case LIMIT_RANGE_NONE:
			if (strcmp(domain,"%") == 0)
			    process_limit(pamh, LIMITS_DEF_ALL, ltype, item, value, ctrl,
					  pl);
			else if (pam_modutil_user_in_group_nam_nam(pamh, uname, domain+1)) {
			    strcpy(pl->login_group, domain+1);
			    process_limit(pamh, LIMITS_DEF_ALLGROUP, ltype, item, value, ctrl,
					  pl);
			}
			break;
		    case LIMIT_RANGE_ONE:
			if (pam_modutil_user_in_group_nam_gid(pamh, uname, (gid_t)max_uid)) {
			    struct group *grp;
			    grp = pam_modutil_getgrgid(pamh, (gid_t)max_uid);
			    strncpy(pl->login_group, grp->gr_name, sizeof(pl->login_group));
			    pl->login_group[sizeof(pl->login_group)-1] = '\0';
			    process_limit(pamh, LIMITS_DEF_ALLGROUP, ltype, item, value, ctrl,
					  pl);
			}
			break;
		    case LIMIT_RANGE_MIN:
		    case LIMIT_RANGE_MM:
			pam_syslog(pamh, LOG_WARNING, "range unsupported for %%group matching - ignored");
		}
            } else {
		switch(rngtype) {
		    case LIMIT_RANGE_NONE:
			if (strcmp(domain, "*") == 0)
			    process_limit(pamh, LIMITS_DEF_DEFAULT, ltype, item, value, ctrl,
					  pl);
			break;
		    case LIMIT_RANGE_ONE:
			if (uid != max_uid)
			    break;
			/* fallthrough */
		    case LIMIT_RANGE_MM:
			if (uid > max_uid)
			    break;
			/* fallthrough */
		    case LIMIT_RANGE_MIN:
			if (uid >= min_uid)
			    process_limit(pamh, LIMITS_DEF_USER, ltype, item, value, ctrl, pl);
		}
	    }
	} else if (i == 2 && ltype[0] == '-') { /* Probably a no-limit line */
	    if (strcmp(uname, domain) == 0) {
		if (ctrl & PAM_DEBUG_ARG) {
		    pam_syslog(pamh, LOG_DEBUG, "no limits for '%s'", uname);
		}
	    } else if (domain[0] == '@') {
		switch(rngtype) {
		    case LIMIT_RANGE_NONE:
			if (!pam_modutil_user_in_group_nam_nam(pamh, uname, domain+1))
			    continue; /* next line */
			break;
		    case LIMIT_RANGE_ONE:
			if (!pam_modutil_user_in_group_nam_gid(pamh, uname, (gid_t)max_uid))
			    continue; /* next line */
			break;
		    case LIMIT_RANGE_MM:
			if (gid > (gid_t)max_uid)
			    continue;  /* next line */
			/* fallthrough */
		    case LIMIT_RANGE_MIN:
			if (gid < (gid_t)min_uid)
			    continue;  /* next line */
		}
		if (ctrl & PAM_DEBUG_ARG) {
		    pam_syslog(pamh, LOG_DEBUG,
			       "no limits for '%s' in group '%s'",
			       uname, domain+1);
		}
	    } else {
		switch(rngtype) {
		    case LIMIT_RANGE_NONE:
			continue;  /* next line */
		    case LIMIT_RANGE_ONE:
			if (uid != max_uid)
			    continue;  /* next line */
			break;
		    case LIMIT_RANGE_MM:
			if (uid > max_uid)
			    continue;  /* next line */
			/* fallthrough */
		    case LIMIT_RANGE_MIN:
			if (uid >= min_uid)
			    break;
			continue;  /* next line */
		}
		if (ctrl & PAM_DEBUG_ARG) {
		    pam_syslog(pamh, LOG_DEBUG, "no limits for '%s'", uname);
		}
	    }
	    fclose(fil);
	    return PAM_IGNORE;
        } else {
            pam_syslog(pamh, LOG_WARNING, "invalid line '%s' - skipped", line);
	}
    }
    fclose(fil);
    return PAM_SUCCESS;
}

static int setup_limits(pam_handle_t *pamh,
			const char *uname, uid_t uid, int ctrl,
			struct pam_limit_s *pl)
{
    int i;
    int status;
    int retval = LIMITED_OK;

    for (i=0, status=LIMITED_OK; i<RLIM_NLIMITS; i++) {
      int res;

	if (!pl->limits[i].supported) {
	    /* skip it if its not known to the system */
	    continue;
	}
	if (pl->limits[i].src_soft == LIMITS_DEF_NONE &&
	    pl->limits[i].src_hard == LIMITS_DEF_NONE) {
	    /* skip it if its not initialized */
	    continue;
	}
        if (pl->limits[i].limit.rlim_cur > pl->limits[i].limit.rlim_max)
            pl->limits[i].limit.rlim_cur = pl->limits[i].limit.rlim_max;
	res = setrlimit(i, &pl->limits[i].limit);
	if (res != 0)
	  pam_syslog(pamh, LOG_ERR, "Could not set limit for '%s': %m",
		     rlimit2str(i));
	status |= res;
    }

    if (status) {
        retval = LIMIT_ERR;
    }

    status = setpriority(PRIO_PROCESS, 0, pl->priority);
    if (status != 0) {
        pam_syslog(pamh, LOG_ERR, "Could not set limit for PRIO_PROCESS: %m");
        retval = LIMIT_ERR;
    }

    if (uid == 0) {
	D(("skip login limit check for uid=0"));
    } else if (pl->login_limit > 0) {
        if (check_logins(pamh, uname, pl->login_limit, ctrl, pl) == LOGIN_ERR) {
#ifdef HAVE_LIBAUDIT
	    if (!(ctrl & PAM_NO_AUDIT)) {
		pam_modutil_audit_write(pamh, AUDIT_ANOM_LOGIN_SESSIONS,
		    "pam_limits", PAM_PERM_DENIED);
		/* ignore return value as we fail anyway */
            }
#endif
            retval |= LOGIN_ERR;
	}
    } else if (pl->login_limit == 0) {
        retval |= LOGIN_ERR;
    }

    return retval;
}

/* now the session stuff */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    int retval;
    int i;
    int glob_rc;
    char *user_name;
    struct passwd *pwd;
    int ctrl;
    struct pam_limit_s plstruct;
    struct pam_limit_s *pl = &plstruct;
    glob_t globbuf;
    const char *oldlocale;

    D(("called."));

    memset(pl, 0, sizeof(*pl));
    memset(&globbuf, 0, sizeof(globbuf));

    ctrl = _pam_parse(pamh, argc, argv, pl);
    retval = pam_get_item( pamh, PAM_USER, (void*) &user_name );
    if ( user_name == NULL || retval != PAM_SUCCESS ) {
        pam_syslog(pamh, LOG_CRIT, "open_session - error recovering username");
        return PAM_SESSION_ERR;
     }

    pwd = pam_modutil_getpwnam(pamh, user_name);
    if (!pwd) {
        if (ctrl & PAM_DEBUG_ARG)
            pam_syslog(pamh, LOG_WARNING,
		       "open_session username '%s' does not exist", user_name);
        return PAM_USER_UNKNOWN;
    }

    retval = init_limits(pamh, pl, ctrl);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_WARNING, "cannot initialize");
        return PAM_ABORT;
    }

    retval = parse_config_file(pamh, pwd->pw_name, pwd->pw_uid, pwd->pw_gid, ctrl, pl);
    if (retval == PAM_IGNORE) {
	D(("the configuration file ('%s') has an applicable '<domain> -' entry", CONF_FILE));
	return PAM_SUCCESS;
    }
    if (retval != PAM_SUCCESS || pl->conf_file != NULL)
	/* skip reading limits.d if config file explicitely specified */
	goto out;

    /* Read subsequent *.conf files, if they exist. */

    /* set the LC_COLLATE so the sorting order doesn't depend
	on system locale */

    oldlocale = setlocale(LC_COLLATE, "C");
    glob_rc = glob(LIMITS_CONF_GLOB, GLOB_ERR, NULL, &globbuf);

    if (oldlocale != NULL)
	setlocale (LC_COLLATE, oldlocale);

    if (!glob_rc) {
	/* Parse the *.conf files. */
	for (i = 0; globbuf.gl_pathv[i] != NULL; i++) {
	    pl->conf_file = globbuf.gl_pathv[i];
	    retval = parse_config_file(pamh, pwd->pw_name, pwd->pw_uid, pwd->pw_gid, ctrl, pl);
	    if (retval == PAM_IGNORE) {
		D(("the configuration file ('%s') has an applicable '<domain> -' entry", pl->conf_file));
		globfree(&globbuf);
		return PAM_SUCCESS;
	    }
	    if (retval != PAM_SUCCESS)
		goto out;
        }
    }

out:
    globfree(&globbuf);
    if (retval != PAM_SUCCESS)
    {
	pam_syslog(pamh, LOG_WARNING, "error parsing the configuration file: '%s' ",CONF_FILE);
	return retval;
    }

    retval = setup_limits(pamh, pwd->pw_name, pwd->pw_uid, ctrl, pl);
    if (retval & LOGIN_ERR)
	pam_error(pamh, _("Too many logins for '%s'."), pwd->pw_name);
    if (retval != LIMITED_OK) {
        return PAM_PERM_DENIED;
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
     /* nothing to do */
     return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_limits_modstruct = {
     "pam_limits",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL
};
#endif

/*
 * Copyright (c) Cristian Gafton, 1996-1997, <gafton@redhat.com>
 *                                              All rights reserved.
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
