/* pam_group module */

/*
 * Written by Andrew Morgan <morgan@linux.kernel.org> 1996/7/6
 */

#include "config.h"

#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <string.h>

#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>

#define PAM_GROUP_BUFLEN        1000
#define FIELD_SEPARATOR         ';'   /* this is new as of .02 */

#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

typedef enum { AND, OR } operator;

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

/* --- static functions for checking whether the user should be let in --- */

static void shift_bytes(char *mem, int from, int by)
{
    while (by-- > 0) {
	*mem = mem[from];
	++mem;
    }
}

/* This function should initially be called with buf = NULL. If
 * an error occurs, the file descriptor is closed. Subsequent
 * calls with a closed descriptor will cause buf to be deallocated.
 * Therefore, always check buf after calling this to see if an error
 * occurred.
 */
static int
read_field (const pam_handle_t *pamh, int fd, char **buf, int *from, int *to)
{
    /* is buf set ? */

    if (! *buf) {
	*buf = (char *) malloc(PAM_GROUP_BUFLEN);
	if (! *buf) {
	    pam_syslog(pamh, LOG_ERR, "out of memory");
	    return -1;
	}
	*from = *to = 0;
	fd = open(PAM_GROUP_CONF, O_RDONLY);
    }

    /* do we have a file open ? return error */

    if (fd < 0 && *to <= 0) {
	pam_syslog(pamh, LOG_ERR, "%s not opened", PAM_GROUP_CONF);
	memset(*buf, 0, PAM_GROUP_BUFLEN);
	_pam_drop(*buf);
	return -1;
    }

    /* check if there was a newline last time */

    if ((*to > *from) && (*to > 0)
	&& ((*buf)[*from] == '\0')) {   /* previous line ended */
	(*from)++;
	(*buf)[0] = '\0';
	return fd;
    }

    /* ready for more data: first shift the buffer's remaining data */

    *to -= *from;
    shift_bytes(*buf, *from, *to);
    *from = 0;
    (*buf)[*to] = '\0';

    while (fd >= 0 && *to < PAM_GROUP_BUFLEN) {
	int i;

	/* now try to fill the remainder of the buffer */

	i = read(fd, *to + *buf, PAM_GROUP_BUFLEN - *to);
	if (i < 0) {
	    pam_syslog(pamh, LOG_ERR, "error reading %s: %m", PAM_GROUP_CONF);
	    close(fd);
	    return -1;
	} else if (!i) {
	    close(fd);
	    fd = -1;          /* end of file reached */
	} else
	    *to += i;

	/*
	 * contract the buffer. Delete any comments, and replace all
	 * multiple spaces with single commas
	 */

	i = 0;
#ifdef DEBUG_DUMP
	D(("buffer=<%s>",*buf));
#endif
	while (i < *to) {
	    if ((*buf)[i] == ',') {
		int j;

		for (j=++i; j<*to && (*buf)[j] == ','; ++j);
		if (j!=i) {
		    shift_bytes(i + (*buf), j-i, (*to) - j);
		    *to -= j-i;
		}
	    }
	    switch ((*buf)[i]) {
		int j, c;
	    case '#':
	        c = 0;
		for (j=i; j < *to && (c = (*buf)[j]) != '\n'; ++j);
		if (j >= *to) {
		    (*buf)[*to = ++i] = '\0';
		} else if (c == '\n') {
		    shift_bytes(i + (*buf), j-i, (*to) - j);
		    *to -= j-i;
		    ++i;
		} else {
		    pam_syslog(pamh, LOG_CRIT,
			       "internal error in file %s at line %d",
			       __FILE__, __LINE__);
	            close(fd);
		    return -1;
		}
		break;
	    case '\\':
		if ((*buf)[i+1] == '\n') {
		    shift_bytes(i + *buf, 2, *to - (i+2));
		    *to -= 2;
		} else {
		    ++i;   /* we don't escape non-newline characters */
		}
		break;
	    case '!':
	    case ' ':
	    case '\t':
		if ((*buf)[i] != '!')
		    (*buf)[i] = ',';
		/* delete any trailing spaces */
		for (j=++i; j < *to && ( (c = (*buf)[j]) == ' '
					 || c == '\t' ); ++j);
		shift_bytes(i + *buf, j-i, (*to)-j );
		*to -= j-i;
		break;
	    default:
		++i;
	    }
	}
    }

    (*buf)[*to] = '\0';

    /* now return the next field (set the from/to markers) */
    {
	int i;

	for (i=0; i<*to; ++i) {
	    switch ((*buf)[i]) {
	    case '#':
	    case '\n':               /* end of the line/file */
		(*buf)[i] = '\0';
		*from = i;
		return fd;
	    case FIELD_SEPARATOR:    /* end of the field */
		(*buf)[i] = '\0';
	    *from = ++i;
	    return fd;
	    }
	}
	*from = i;
	(*buf)[*from] = '\0';
    }

    if (*to <= 0) {
	D(("[end of text]"));
	*buf = NULL;
    }
    return fd;
}

/* read a member from a field */

static int logic_member(const char *string, int *at)
{
     int c,to;
     int done=0;
     int token=0;

     to=*at;
     do {
	  c = string[to++];

	  switch (c) {

	  case '\0':
	       --to;
	       done = 1;
	       break;

	  case '&':
	  case '|':
	  case '!':
	       if (token) {
		    --to;
	       }
	       done = 1;
	       break;

	  default:
	       if (isalpha(c) || c == '*' || isdigit(c) || c == '_'
		    || c == '-' || c == '.' || c == '/' || c == ':') {
		    token = 1;
	       } else if (token) {
		    --to;
		    done = 1;
	       } else {
		    ++*at;
	       }
	  }
     } while (!done);

     return to - *at;
}

typedef enum { VAL, OP } expect;

static int
logic_field (const pam_handle_t *pamh, const void *me,
             const char *x, int rule,
             int (*agrees)(const pam_handle_t *pamh, const void *,
                               const char *, int, int))
{
     int left=FALSE, right, not=FALSE;
     operator oper=OR;
     int at=0, l;
     expect next=VAL;

     while ((l = logic_member(x,&at))) {
	  int c = x[at];

	  if (next == VAL) {
	       if (c == '!')
		    not = !not;
	       else if (isalpha(c) || c == '*' || isdigit(c) || c == '_'
                    || c == '-' || c == '.' || c == '/' || c == ':') {
		    right = not ^ agrees(pamh, me, x+at, l, rule);
		    if (oper == AND)
			 left &= right;
		    else
			 left |= right;
		    next = OP;
	       } else {
		    pam_syslog(pamh, LOG_ERR,
			       "garbled syntax; expected name (rule #%d)",
			       rule);
		    return FALSE;
	       }
	  } else {   /* OP */
	       switch (c) {
	       case '&':
		    oper = AND;
		    break;
	       case '|':
		    oper = OR;
		    break;
	       default:
		    pam_syslog(pamh, LOG_ERR,
			       "garbled syntax; expected & or | (rule #%d)",
			       rule);
		    D(("%c at %d",c,at));
		    return FALSE;
	       }
	       next = VAL;
	  }
	  at += l;
     }

     return left;
}

static int
is_same (const pam_handle_t *pamh UNUSED,
         const void *A, const char *b, int len, int rule UNUSED)
{
     int i;
     const char *a;

     a = A;
     for (i=0; len > 0; ++i, --len) {
	  if (b[i] != a[i]) {
	       if (b[i++] == '*') {
		    return (!--len || !strncmp(b+i,a+strlen(a)-len,len));
	       } else
		    return FALSE;
	  }
     }

     /* Ok, we know that b is a substring from A and does not contain
        wildcards, but now the length of both strings must be the same,
        too. In this case it means, a[i] has to be the end of the string. */
     if (a[i] != '\0')
          return FALSE;

     return ( !len );
}

typedef struct {
     int day;             /* array of 7 bits, one set for today */
     int minute;            /* integer, hour*100+minute for now */
} TIME;

static struct day {
     const char *d;
     int bit;
} const days[11] = {
     { "su", 01 },
     { "mo", 02 },
     { "tu", 04 },
     { "we", 010 },
     { "th", 020 },
     { "fr", 040 },
     { "sa", 0100 },
     { "wk", 076 },
     { "wd", 0101 },
     { "al", 0177 },
     { NULL, 0 }
};

static TIME time_now(void)
{
     struct tm *local;
     time_t the_time;
     TIME this;

     the_time = time((time_t *)0);                /* get the current time */
     local = localtime(&the_time);
     this.day = days[local->tm_wday].bit;
     this.minute = local->tm_hour*100 + local->tm_min;

     D(("day: 0%o, time: %.4d", this.day, this.minute));
     return this;
}

/* take the current date and see if the range "date" passes it */
static int
check_time (const pam_handle_t *pamh, const void *AT,
            const char *times, int len, int rule)
{
     int not,pass;
     int marked_day, time_start, time_end;
     const TIME *at;
     int i,j=0;

     at = AT;
     D(("checking: 0%o/%.4d vs. %s", at->day, at->minute, times));

     if (times == NULL) {
	  /* this should not happen */
	  pam_syslog(pamh, LOG_CRIT, "internal error in file %s at line %d",
		     __FILE__, __LINE__);
	  return FALSE;
     }

     if (times[j] == '!') {
	  ++j;
	  not = TRUE;
     } else {
	  not = FALSE;
     }

     for (marked_day = 0; len > 0 && isalpha(times[j]); --len) {
	  int this_day=-1;

	  D(("%c%c ?", times[j], times[j+1]));
	  for (i=0; days[i].d != NULL; ++i) {
	       if (tolower(times[j]) == days[i].d[0]
		   && tolower(times[j+1]) == days[i].d[1] ) {
		    this_day = days[i].bit;
		    break;
	       }
	  }
	  j += 2;
	  if (this_day == -1) {
	       pam_syslog(pamh, LOG_ERR, "bad day specified (rule #%d)", rule);
	       return FALSE;
	  }
	  marked_day ^= this_day;
     }
     if (marked_day == 0) {
	  pam_syslog(pamh, LOG_ERR, "no day specified");
	  return FALSE;
     }
     D(("day range = 0%o", marked_day));

     time_start = 0;
     for (i=0; len > 0 && i < 4 && isdigit(times[i+j]); ++i, --len) {
	  time_start *= 10;
	  time_start += times[i+j]-'0';       /* is this portable? */
     }
     j += i;

     if (times[j] == '-') {
	  time_end = 0;
	  for (i=1; len > 0 && i < 5 && isdigit(times[i+j]); ++i, --len) {
	       time_end *= 10;
	       time_end += times[i+j]-'0';    /* is this portable? */
	  }
	  j += i;
     } else
	  time_end = -1;

     D(("i=%d, time_end=%d, times[j]='%c'", i, time_end, times[j]));
     if (i != 5 || time_end == -1) {
	  pam_syslog(pamh, LOG_ERR, "no/bad times specified (rule #%d)", rule);
	  return TRUE;
     }
     D(("times(%d to %d)", time_start,time_end));
     D(("marked_day = 0%o", marked_day));

     /* compare with the actual time now */

     pass = FALSE;
     if (time_start < time_end) {    /* start < end ? --> same day */
	  if ((at->day & marked_day) && (at->minute >= time_start)
	      && (at->minute < time_end)) {
	       D(("time is listed"));
	       pass = TRUE;
	  }
     } else {                                    /* spans two days */
	  if ((at->day & marked_day) && (at->minute >= time_start)) {
	       D(("caught on first day"));
	       pass = TRUE;
	  } else {
	       marked_day <<= 1;
	       marked_day |= (marked_day & 0200) ? 1:0;
	       D(("next day = 0%o", marked_day));
	       if ((at->day & marked_day) && (at->minute <= time_end)) {
		    D(("caught on second day"));
		    pass = TRUE;
	       }
	  }
     }

     return (not ^ pass);
}

static int find_member(const char *string, int *at)
{
     int c,to;
     int done=0;
     int token=0;

     to=*at;
     do {
          c = string[to++];

          switch (c) {

          case '\0':
               --to;
               done = 1;
               break;

          case '&':
          case '|':
	  case '!':
               if (token) {
                    --to;
               }
               done = 1;
               break;

          default:
               if (isalpha(c) || isdigit(c) || c == '_' || c == '*'
                    || c == '-') {
                    token = 1;
               } else if (token) {
                    --to;
                    done = 1;
               } else {
                    ++*at;
               }
          }
     } while (!done);

     return to - *at;
}

#define GROUP_BLK 10
#define blk_size(len) (((len-1 + GROUP_BLK)/GROUP_BLK)*GROUP_BLK)

static int mkgrplist(pam_handle_t *pamh, char *buf, gid_t **list, int len)
{
     int l,at=0;
     int blks;

     blks = blk_size(len);
     D(("cf. blks=%d and len=%d", blks,len));

     while ((l = find_member(buf,&at))) {
	  int edge;

	  if (len >= blks) {
	       gid_t *tmp;

	       D(("allocating new block"));
	       tmp = (gid_t *) realloc((*list)
				       , sizeof(gid_t) * (blks += GROUP_BLK));
	       if (tmp != NULL) {
		    (*list) = tmp;
	       } else {
		    pam_syslog(pamh, LOG_ERR, "out of memory for group list");
		    free(*list);
		    (*list) = NULL;
		    return -1;
	       }
	  }

	  /* '\0' terminate the entry */

	  edge = (buf[at+l]) ? 1:0;
	  buf[at+l] = '\0';
	  D(("found group: %s",buf+at));

	  /* this is where we convert a group name to a gid_t */
	  {
	      const struct group *grp;

	      grp = pam_modutil_getgrnam(pamh, buf+at);
	      if (grp == NULL) {
		  pam_syslog(pamh, LOG_ERR, "bad group: %s", buf+at);
	      } else {
		  D(("group %s exists", buf+at));
		  (*list)[len++] = grp->gr_gid;
	      }
	  }

	  /* next entry along */

	  at += l + edge;
     }
     D(("returning with [%p/len=%d]->%p",list,len,*list));
     return len;
}


static int check_account(pam_handle_t *pamh, const char *service,
			 const char *tty, const char *user)
{
    int from=0,to=0,fd=-1;
    char *buffer=NULL;
    int count=0;
    TIME here_and_now;
    int retval=PAM_SUCCESS;
    gid_t *grps;
    int no_grps;

    /*
     * first we get the current list of groups - the application
     * will have previously done an initgroups(), or equivalent.
     */

    D(("counting supplementary groups"));
    no_grps = getgroups(0, NULL);      /* find the current number of groups */
    if (no_grps > 0) {
	grps = calloc( blk_size(no_grps) , sizeof(gid_t) );
	D(("copying current list into grps [%d big]",blk_size(no_grps)));
	if (getgroups(no_grps, grps) < 0) {
	    D(("getgroups call failed"));
	    no_grps = 0;
	    _pam_drop(grps);
	}
#ifdef PAM_DEBUG
	{
	    int z;
	    for (z=0; z<no_grps; ++z) {
		D(("gid[%d]=%d", z, grps[z]));
	    }
	}
#endif
    } else {
	D(("no supplementary groups known"));
	no_grps = 0;
	grps = NULL;
    }

    here_and_now = time_now();                         /* find current time */

    /* parse the rules in the configuration file */
    do {
	int good=TRUE;

	/* here we get the service name field */

	fd = read_field(pamh,fd,&buffer,&from,&to);
	if (!buffer || !buffer[0]) {
	    /* empty line .. ? */
	    continue;
	}
	++count;
	D(("working on rule #%d",count));

	good = logic_field(pamh,service, buffer, count, is_same);
	D(("with service: %s", good ? "passes":"fails" ));

	/* here we get the terminal name field */

	fd = read_field(pamh,fd,&buffer,&from,&to);
	if (!buffer || !buffer[0]) {
	    pam_syslog(pamh, LOG_ERR,
		       "%s: no tty entry #%d", PAM_GROUP_CONF, count);
	    continue;
	}
	good &= logic_field(pamh,tty, buffer, count, is_same);
	D(("with tty: %s", good ? "passes":"fails" ));

	/* here we get the username field */

	fd = read_field(pamh,fd,&buffer,&from,&to);
	if (!buffer || !buffer[0]) {
	    pam_syslog(pamh, LOG_ERR,
		       "%s: no user entry #%d", PAM_GROUP_CONF, count);
	    continue;
	}
	/* If buffer starts with @, we are using netgroups */
	if (buffer[0] == '@')
	  good &= innetgr (&buffer[1], NULL, user, NULL);
	/* otherwise, if the buffer starts with %, it's a UNIX group */
	else if (buffer[0] == '%')
          good &= pam_modutil_user_in_group_nam_nam(pamh, user, &buffer[1]);
	else
	  good &= logic_field(pamh,user, buffer, count, is_same);
	D(("with user: %s", good ? "passes":"fails" ));

	/* here we get the time field */

	fd = read_field(pamh,fd,&buffer,&from,&to);
	if (!buffer || !buffer[0]) {
	    pam_syslog(pamh, LOG_ERR,
		       "%s: no time entry #%d", PAM_GROUP_CONF, count);
	    continue;
	}

	good &= logic_field(pamh,&here_and_now, buffer, count, check_time);
	D(("with time: %s", good ? "passes":"fails" ));

	fd = read_field(pamh,fd,&buffer,&from,&to);
	if (!buffer || !buffer[0]) {
	    pam_syslog(pamh, LOG_ERR,
		       "%s: no listed groups for rule #%d", PAM_GROUP_CONF, count);
	    continue;
	}

	/*
	 * so we have a list of groups, we need to turn it into
	 * something to send to setgroups(2)
	 */

	if (good) {
	    D(("adding %s to gid list", buffer));
	    good = mkgrplist(pamh, buffer, &grps, no_grps);
	    if (good < 0) {
		no_grps = 0;
	    } else {
		no_grps = good;
	    }
	}

	/* check the line is terminated correctly */

	fd = read_field(pamh,fd,&buffer,&from,&to);
	if (buffer && buffer[0]) {
	    pam_syslog(pamh, LOG_ERR,
                       "%s: poorly terminated rule #%d", PAM_GROUP_CONF, count);
	}

	if (good > 0) {
	    D(("rule #%d passed, added %d groups", count, good));
	} else if (good < 0) {
	    retval = PAM_BUF_ERR;
	} else {
	    D(("rule #%d failed", count));
	}

    } while (buffer);

    /* now set the groups for the user */

    if (no_grps > 0) {
#ifdef PAM_DEBUG
	int err;
#endif
	D(("trying to set %d groups", no_grps));
#ifdef PAM_DEBUG
	for (err=0; err<no_grps; ++err) {
	    D(("gid[%d]=%d", err, grps[err]));
	}
#endif
	if (setgroups(no_grps, grps) != 0) {
	    D(("but couldn't set groups %m"));
	    pam_syslog(pamh, LOG_ERR,
		       "unable to set the group membership for user: %m");
	    retval = PAM_CRED_ERR;
	}
    }

    if (grps) {                                          /* tidy up */
	memset(grps, 0, sizeof(gid_t) * blk_size(no_grps));
	_pam_drop(grps);
	no_grps = 0;
    }

    return retval;
}

/* --- public authentication management functions --- */

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
    return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh, int flags,
		int argc UNUSED, const char **argv UNUSED)
{
    const void *service=NULL, *void_tty=NULL;
    const char *user=NULL;
    const char *tty;
    int retval;
    unsigned setting;

    /* only interested in establishing credentials */

    setting = flags;
    if (!(setting & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED))) {
	D(("ignoring call - not for establishing credentials"));
	return PAM_SUCCESS;            /* don't fail because of this */
    }

    /* set service name */

    if (pam_get_item(pamh, PAM_SERVICE, &service)
	!= PAM_SUCCESS || service == NULL) {
	pam_syslog(pamh, LOG_ERR, "cannot find the current service name");
	return PAM_ABORT;
    }

    /* set username */

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL
	|| *user == '\0') {
	pam_syslog(pamh, LOG_ERR, "cannot determine the user's name");
	return PAM_USER_UNKNOWN;
    }

    /* set tty name */

    if (pam_get_item(pamh, PAM_TTY, &void_tty) != PAM_SUCCESS
	|| void_tty == NULL) {
	D(("PAM_TTY not set, probing stdin"));
	tty = ttyname(STDIN_FILENO);
	if (tty == NULL) {
	    tty = "";
	}
	if (pam_set_item(pamh, PAM_TTY, tty) != PAM_SUCCESS) {
	    pam_syslog(pamh, LOG_ERR, "couldn't set tty name");
	    return PAM_ABORT;
	}
    }
    else
      tty = (const char *) void_tty;

    if (tty[0] == '/') {   /* full path */
	const char *t;
        tty++;
        if ((t = strchr(tty, '/')) != NULL) {
	    tty = t + 1;
	}
    }

    /* good, now we have the service name, the user and the terminal name */

    D(("service=%s", service));
    D(("user=%s", user));
    D(("tty=%s", tty));

    retval = check_account(pamh,service,tty,user);          /* get groups */

    return retval;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_group_modstruct = {
    "pam_group",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL
};
#endif
