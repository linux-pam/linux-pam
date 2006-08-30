/* pam_access module */

/*
 * Written by Alexei Nogin <alexei@nogin.dnttm.ru> 1997/06/15
 * (I took login_access from logdaemon-5.6 and converted it to PAM
 * using parts of pam_time code.)
 *
 ************************************************************************
 * Copyright message from logdaemon-5.6 (original file name DISCLAIMER)
 ************************************************************************
 * Copyright 1995 by Wietse Venema. All rights reserved. Individual files
 * may be covered by other copyrights (as noted in the file itself.)
 *
 * This material was originally written and compiled by Wietse Venema at
 * Eindhoven University of Technology, The Netherlands, in 1990, 1991,
 * 1992, 1993, 1994 and 1995.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this entire copyright notice is duplicated in all such
 * copies.
 *
 * This software is provided "as is" and without any expressed or implied
 * warranties, including, without limitation, the implied warranties of
 * merchantibility and fitness for any particular purpose.
 *************************************************************************
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <rpcsvc/ypclnt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

/* login_access.c from logdaemon-5.6 with several changes by A.Nogin: */

 /*
  * This module implements a simple but effective form of login access
  * control based on login names and on host (or domain) names, internet
  * addresses (or network numbers), or on terminal line names in case of
  * non-networked logins. Diagnostics are reported through syslog(3).
  *
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 64)
#undef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

 /* Delimiters for fields and for lists of users, ttys or hosts. */

static const char *fs = ":";			/* field separator */
static const char *sep = ", \t";		/* list-element separator */

 /* Constants to be used in assignments only, not in comparisons... */

#define YES             1
#define NO              0

 /*
  * A structure to bundle up all login-related information to keep the
  * functional interfaces as generic as possible.
  */
struct login_info {
    const struct passwd *user;
    const char *from;
    const char *config_file;
};

/* Print debugging messages.
   Default is NO which means don't print debugging messages.  */
static char pam_access_debug = NO;

/* Parse module config arguments */

static int
parse_args(pam_handle_t *pamh, struct login_info *loginfo,
           int argc, const char **argv)
{
    int i;

    for (i=0; i<argc; ++i) {
	if (!strncmp("fieldsep=", argv[i], 9)) {

	    /* the admin wants to override the default field separators */
	    fs = argv[i]+9;

	} else if (!strncmp("listsep=", argv[i], 8)) {

	    /* the admin wants to override the default list separators */
	    sep = argv[i]+8;

	} else if (!strncmp("accessfile=", argv[i], 11)) {
	    FILE *fp = fopen(11 + argv[i], "r");

	    if (fp) {
		loginfo->config_file = 11 + argv[i];
		fclose(fp);
	    } else {
		pam_syslog(pamh, LOG_ERR,
			   "failed to open accessfile=[%s]: %m", 11 + argv[i]);
		return 0;
	    }

	} else if (strcmp (argv[i], "debug") == 0) {
	    pam_access_debug = YES;
	} else {
	    pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", argv[i]);
	}
    }

    return 1;  /* OK */
}

/* --- static functions for checking whether the user should be let in --- */

typedef int match_func (pam_handle_t *, char *, struct login_info *);

static int list_match (pam_handle_t *, char *, struct login_info *,
		       match_func *);
static int user_match (pam_handle_t *, char *, struct login_info *);
static int from_match (pam_handle_t *, char *, struct login_info *);
static int string_match (pam_handle_t *, const char *, const char *);
static int network_netmask_match (pam_handle_t *, const char *, const char *);


/* isipaddr - find out if string provided is an IP address or not */

static int
isipaddr (const char *string, int *addr_type,
	  struct sockaddr_storage *addr)
{
  struct sockaddr_storage local_addr;
  int is_ip;

  /* We use struct sockaddr_storage addr because
   * struct in_addr/in6_addr is an integral part
   * of struct sockaddr and we doesn't want to
   * use its value.
   */

  if (addr == NULL)
    addr = &local_addr;

  memset(addr, 0, sizeof(struct sockaddr_storage));

  /* first ipv4 */
  if (inet_pton(AF_INET, string, addr) > 0)
    {
      if (addr_type != NULL)
	*addr_type = AF_INET;

      is_ip = YES;
    }
  else if (inet_pton(AF_INET6, string, addr) > 0)
    { /* then ipv6 */
      if (addr_type != NULL) {
	*addr_type = AF_INET6;
      }
      is_ip = YES;
    }
  else
    is_ip = NO;

  return is_ip;
}


/* are_addresses_equal - translate IP address strings to real IP
 * addresses and compare them to find out if they are equal.
 * If netmask was provided it will be used to focus comparation to
 * relevant bits.
 */
static int
are_addresses_equal (const char *ipaddr0, const char *ipaddr1,
		     const char *netmask)
{
  struct sockaddr_storage addr0;
  struct sockaddr_storage addr1;
  int addr_type0 = 0;
  int addr_type1 = 0;

  if (isipaddr (ipaddr0, &addr_type0, &addr0) == NO)
    return NO;

  if (isipaddr (ipaddr1, &addr_type1, &addr1) == NO)
    return NO;

  if (addr_type0 != addr_type1)
    /* different address types */
    return NO;

  if (netmask != NULL) {
    /* Got a netmask, so normalize addresses? */
    struct sockaddr_storage nmask;
    unsigned char *byte_a, *byte_nm;

    memset(&nmask, 0, sizeof(struct sockaddr_storage));
    if (inet_pton(addr_type0, netmask, (void *)&nmask) > 0) {
      unsigned int i;
      byte_a = (unsigned char *)(&addr0);
      byte_nm = (unsigned char *)(&nmask);
      for (i=0; i<sizeof(struct sockaddr_storage); i++) {
        byte_a[i] = byte_a[i] & byte_nm[i];
      }

      byte_a = (unsigned char *)(&addr1);
      byte_nm = (unsigned char *)(&nmask);
      for (i=0; i<sizeof(struct sockaddr_storage); i++) {
        byte_a[i] = byte_a[i] & byte_nm[i];
      }
    }
  }


  /* Are the two addresses equal? */
  if (memcmp((void *)&addr0, (void *)&addr1,
              sizeof(struct sockaddr_storage)) == 0) {
    return(YES);
  }

  return(NO);
}

static char *
number_to_netmask (long netmask, int addr_type,
		   char *ipaddr_buf, size_t ipaddr_buf_len)
{
  /* We use struct sockaddr_storage addr because
   * struct in_addr/in6_addr is an integral part
   * of struct sockaddr and we doesn't want to
   * use its value.
   */
  struct sockaddr_storage nmask;
  unsigned char *byte_nm;
  const char *ipaddr_dst = NULL;
  int i, ip_bytes;

  if (netmask == 0) {
    /* mask 0 is the same like no mask */
    return(NULL);
  }

  memset(&nmask, 0, sizeof(struct sockaddr_storage));
  if (addr_type == AF_INET6) {
    /* ipv6 address mask */
    ip_bytes = 16;
  } else {
    /* default might be an ipv4 address mask */
    addr_type = AF_INET;
    ip_bytes = 4;
  }

  byte_nm = (unsigned char *)(&nmask);
  /* translate number to mask */
  for (i=0; i<ip_bytes; i++) {
    if (netmask >= 8) {
      byte_nm[i] = 0xff;
      netmask -= 8;
    } else
    if (netmask > 0) {
      byte_nm[i] = 0xff << (8 - netmask);
      break;
    } else
    if (netmask <= 0) {
      break;
    }
  }

  /* now generate netmask address string */
  ipaddr_dst = inet_ntop(addr_type, &nmask, ipaddr_buf, ipaddr_buf_len);
  if (ipaddr_dst == ipaddr_buf) {
    return (ipaddr_buf);
  }

  return (NULL);
}

/* login_access - match username/group and host/tty with access control file */

static int
login_access (pam_handle_t *pamh, struct login_info *item)
{
    FILE   *fp;
    char    line[BUFSIZ];
    char   *perm;		/* becomes permission field */
    char   *users;		/* becomes list of login names */
    char   *froms;		/* becomes list of terminals or hosts */
    int     match = NO;
    int     end;
    int     lineno = 0;		/* for diagnostics */

    if (pam_access_debug)
      pam_syslog (pamh, LOG_DEBUG,
		  "login_access: user=%s, from=%s, file=%s",
		  item->user->pw_name,
		  item->from, item->config_file);

    /*
     * Process the table one line at a time and stop at the first match.
     * Blank lines and lines that begin with a '#' character are ignored.
     * Non-comment lines are broken at the ':' character. All fields are
     * mandatory. The first field should be a "+" or "-" character. A
     * non-existing table means no access control.
     */

    if ((fp = fopen(item->config_file, "r"))!=NULL) {
	while (!match && fgets(line, sizeof(line), fp)) {
	    lineno++;
	    if (line[end = strlen(line) - 1] != '\n') {
		pam_syslog(pamh, LOG_ERR,
                           "%s: line %d: missing newline or line too long",
		           item->config_file, lineno);
		continue;
	    }
	    if (line[0] == '#')
		continue;			/* comment line */
	    while (end > 0 && isspace(line[end - 1]))
		end--;
	    line[end] = 0;			/* strip trailing whitespace */
	    if (line[0] == 0)			/* skip blank lines */
		continue;

	    /* Allow field seperator in last field of froms */
	    if (!(perm = strtok(line, fs))
		|| !(users = strtok((char *) 0, fs))
  	        || !(froms = strtok((char *) 0, "\n"))) {
		pam_syslog(pamh, LOG_ERR, "%s: line %d: bad field count",
			   item->config_file, lineno);
		continue;
	    }
	    if (perm[0] != '+' && perm[0] != '-') {
		pam_syslog(pamh, LOG_ERR, "%s: line %d: bad first field",
			   item->config_file, lineno);
		continue;
	    }
	    if (pam_access_debug)
	      pam_syslog (pamh, LOG_DEBUG,
			  "line %d: %s : %s : %s", lineno, perm, users, froms);
	    match = list_match(pamh, froms, item, from_match);
	    if (pam_access_debug)
	      pam_syslog (pamh, LOG_DEBUG,
			  "from_match=%d, \"%s\"", match, item->from);
	    match = match && list_match (pamh, users, item, user_match);
	    if (pam_access_debug)
	      pam_syslog (pamh, LOG_DEBUG, "user_match=%d, \"%s\"",
			  match, item->user->pw_name);
	}
	(void) fclose(fp);
    } else if (errno == ENOENT) {
        /* This is no error.  */
	pam_syslog(pamh, LOG_WARNING, "warning: cannot open %s: %m",
	           item->config_file);
    } else {
        pam_syslog(pamh, LOG_ERR, "cannot open %s: %m", item->config_file);
	return NO;
    }
    return (match == NO || (line[0] == '+'));
}


/* list_match - match an item against a list of tokens with exceptions */

static int list_match(pam_handle_t *pamh,
		      char *list, struct login_info *item, match_func *match_fn)
{
    char   *tok;
    int     match = NO;

    /*
     * Process tokens one at a time. We have exhausted all possible matches
     * when we reach an "EXCEPT" token or the end of the list. If we do find
     * a match, look for an "EXCEPT" list and recurse to determine whether
     * the match is affected by any exceptions.
     */

    for (tok = strtok(list, sep); tok != 0; tok = strtok((char *) 0, sep)) {
	if (strcasecmp(tok, "EXCEPT") == 0)	/* EXCEPT: give up */
	    break;
	if ((match = (*match_fn) (pamh, tok, item)))	/* YES */
	    break;
    }
    /* Process exceptions to matches. */

    if (match != NO) {
	while ((tok = strtok((char *) 0, sep)) && strcasecmp(tok, "EXCEPT"))
	     /* VOID */ ;
	if (tok == 0 || list_match(pamh, (char *) 0, item, match_fn) == NO)
	    return (match);
    }
    return (NO);
}

/* myhostname - figure out local machine name */

static char * myhostname(void)
{
    static char name[MAXHOSTNAMELEN + 1];

    if (gethostname(name, MAXHOSTNAMELEN) == 0) {
      name[MAXHOSTNAMELEN] = 0;
      return (name);
    }
    return NULL;
}

/* netgroup_match - match group against machine or user */

static int
netgroup_match (pam_handle_t *pamh, const char *group,
		const char *machine, const char *user)
{
  char *mydomain = NULL;
  int retval;

  yp_get_default_domain(&mydomain);


  retval = innetgr (group, machine, user, mydomain);
  if (pam_access_debug == YES)
    pam_syslog (pamh, LOG_DEBUG,
		"netgroup_match: %d (group=%s, machine=%s, user=%s, domain=%s)",
		retval, group ? group : "NULL",  machine ? machine : "NULL",
		user ? user : "NULL", mydomain ? mydomain : "NULL");
  return retval;

}

/* user_match - match a username against one token */

static int
user_match (pam_handle_t *pamh, char *tok, struct login_info *item)
{
    char   *string = item->user->pw_name;
    struct login_info fake_item;
    char   *at;

    if (pam_access_debug)
      pam_syslog (pamh, LOG_DEBUG,
		  "user_match: tok=%s, item=%s", tok, string);

    /*
     * If a token has the magic value "ALL" the match always succeeds.
     * Otherwise, return YES if the token fully matches the username, if the
     * token is a group that contains the username, or if the token is the
     * name of the user's primary group.
     */

    if ((at = strchr(tok + 1, '@')) != 0) {	/* split user@host pattern */
	*at = 0;
	fake_item.from = myhostname();
	if (fake_item.from == NULL)
	  return NO;
	return (user_match (pamh, tok, item) &&
		from_match (pamh, at + 1, &fake_item));
    } else if (tok[0] == '@') /* netgroup */
      return (netgroup_match (pamh, tok + 1, (char *) 0, string));
    else if (string_match (pamh, tok, string)) /* ALL or exact match */
	return YES;
    else if (pam_modutil_user_in_group_nam_nam (pamh, item->user->pw_name, tok))
      /* try group membership */
      return YES;

    return NO;
}

/* from_match - match a host or tty against a list of tokens */

static int
from_match (pam_handle_t *pamh UNUSED, char *tok, struct login_info *item)
{
    const char *string = item->from;
    int        tok_len;
    int        str_len;

    if (pam_access_debug)
      pam_syslog (pamh, LOG_DEBUG,
		  "from_match: tok=%s, item=%s", tok, string);

    /*
     * If a token has the magic value "ALL" the match always succeeds. Return
     * YES if the token fully matches the string. If the token is a domain
     * name, return YES if it matches the last fields of the string. If the
     * token has the magic value "LOCAL", return YES if the string does not
     * contain a "." character. If the token is a network number, return YES
     * if it matches the head of the string.
     */

    if (string == NULL) {
	return NO;
    } else if (tok[0] == '@') {			/* netgroup */
        return (netgroup_match (pamh, tok + 1, string, (char *) 0));
    } else if (string_match(pamh, tok, string)) {
        /* ALL or exact match */
	return (YES);
    } else if (tok[0] == '.') {			/* domain: match last fields */
	if ((str_len = strlen(string)) > (tok_len = strlen(tok))
	    && strcasecmp(tok, string + str_len - tok_len) == 0)
	    return (YES);
    } else if (strcasecmp(tok, "LOCAL") == 0) {	/* local: no dots */
	if (strchr(string, '.') == 0)
	    return (YES);
    } else if (tok[(tok_len = strlen(tok)) - 1] == '.') {
      struct addrinfo *res;
      struct addrinfo hint;

      memset (&hint, '\0', sizeof (hint));
      hint.ai_flags = AI_CANONNAME;
      hint.ai_family = AF_INET;

      if (getaddrinfo (string, NULL, &hint, &res) != 0)
	return NO;
      else
	{
	  struct addrinfo *runp = res;

          while (runp != NULL)
	    {
	      char buf[INET_ADDRSTRLEN+2];

	      if (runp->ai_family == AF_INET)
		{
		  inet_ntop (runp->ai_family,
			     &((struct sockaddr_in *) runp->ai_addr)->sin_addr,
			     buf, sizeof (buf));

		  strcat (buf, ".");

		  if (strncmp(tok, buf, tok_len) == 0)
		    {
		      freeaddrinfo (res);
		      return YES;
		    }
		}
	      runp = runp->ai_next;
	    }
	  freeaddrinfo (res);
	}
    } else  if (isipaddr(string, NULL, NULL) == YES) {
      /* Assume network/netmask with a IP of a host.  */
      if (network_netmask_match(pamh, tok, string))
	return YES;
    } else {
      /* Assume network/netmask with a name of a host.  */
      struct addrinfo *res;
      struct addrinfo hint;

      memset (&hint, '\0', sizeof (hint));
      hint.ai_flags = AI_CANONNAME;
      hint.ai_family = AF_UNSPEC;

      if (getaddrinfo (string, NULL, &hint, &res) != 0)
	return NO;
      else
	{
	  struct addrinfo *runp = res;

          while (runp != NULL)
	    {
	      char buf[INET6_ADDRSTRLEN];

	      inet_ntop (runp->ai_family,
			 runp->ai_family == AF_INET
			 ? (void *) &((struct sockaddr_in *) runp->ai_addr)->sin_addr
			 : (void *) &((struct sockaddr_in6 *) runp->ai_addr)->sin6_addr,
			 buf, sizeof (buf));

	      if (network_netmask_match(pamh, tok, buf))
		{
		  freeaddrinfo (res);
		  return YES;
		}
	      runp = runp->ai_next;
	    }
	  freeaddrinfo (res);
	}
    }

    return NO;
}

/* string_match - match a string against one token */

static int
string_match (pam_handle_t *pamh, const char *tok, const char *string)
{

    if (pam_access_debug)
        pam_syslog (pamh, LOG_DEBUG,
		    "string_match: tok=%s, item=%s", tok, string);

    /*
     * If the token has the magic value "ALL" the match always succeeds.
     * Otherwise, return YES if the token fully matches the string.
	 * "NONE" token matches NULL string.
     */

    if (strcasecmp(tok, "ALL") == 0) {		/* all: always matches */
	return (YES);
    } else if (string != NULL) {
	if (strcasecmp(tok, string) == 0) {	/* try exact match */
	    return (YES);
	}
    } else if (strcasecmp(tok, "NONE") == 0) {
	return (YES);
    }
    return (NO);
}


/* network_netmask_match - match a string against one token
 * where string is an ip (v4,v6) address and tok represents
 * whether a single ip (v4,v6) address or a network/netmask
 */
static int
network_netmask_match (pam_handle_t *pamh,
		       const char *tok, const char *string)
{
  if (pam_access_debug)
    pam_syslog (pamh, LOG_DEBUG,
		"network_netmask_match: tok=%s, item=%s", tok, string);

  if (isipaddr(string, NULL, NULL) == YES)
    {
      char *netmask_ptr = NULL;
      static char netmask_string[MAXHOSTNAMELEN + 1] = "";
      int addr_type;

      /* OK, check if tok is of type addr/mask */
      if ((netmask_ptr = strchr(tok, '/')) != NULL)
	{
	  long netmask = 0;

	  /* YES */
	  *netmask_ptr = 0;
	  netmask_ptr++;

	  if (isipaddr(tok, &addr_type, NULL) == NO)
	    { /* no netaddr */
	      return(NO);
	    }

	  /* check netmask */
	  if (isipaddr(netmask_ptr, NULL, NULL) == NO)
	    { /* netmask as integre value */
	      char *endptr = NULL;
	      netmask = strtol(netmask_ptr, &endptr, 0);
	      if ((endptr == NULL) || (*endptr != '\0'))
		{ /* invalid netmask value */
		  return(NO);
		}
	      if ((netmask < 0) || (netmask >= 128))
		{ /* netmask value out of range */
		  return(NO);
		}

	      netmask_ptr = number_to_netmask(netmask, addr_type,
					      netmask_string, MAXHOSTNAMELEN);
	    }

	  /* Netmask is now an ipv4/ipv6 address.
	   * This works also if netmask_ptr is NULL.
	   */
	  return (are_addresses_equal(string, tok, netmask_ptr));
	}
      else
	/* NO, then check if it is only an addr */
	if (isipaddr(tok, NULL, NULL) == YES)
	  { /* check if they are the same, no netmask */
	    return(are_addresses_equal(string, tok, NULL));
	  }
    }

  return (NO);
}


/* --- public PAM management functions --- */

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    struct login_info loginfo;
    const char *user=NULL;
    const void *void_from=NULL;
    const char *from;
    struct passwd *user_pw;

    /* set username */

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL
	|| *user == '\0') {
	pam_syslog(pamh, LOG_ERR, "cannot determine the user's name");
	return PAM_USER_UNKNOWN;
    }

    /* remote host name */

    if (pam_get_item(pamh, PAM_RHOST, &void_from)
	!= PAM_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "cannot find the remote host name");
	return PAM_ABORT;
    }
    from = void_from;

    if ((from==NULL) || (*from=='\0')) {

        /* local login, set tty name */

        if (pam_get_item(pamh, PAM_TTY, &void_from) != PAM_SUCCESS
            || void_from == NULL) {
            D(("PAM_TTY not set, probing stdin"));
	    from = ttyname(STDIN_FILENO);
	    if (from != NULL) {
	        if (pam_set_item(pamh, PAM_TTY, from) != PAM_SUCCESS)
	            pam_syslog(pamh, LOG_WARNING, "couldn't set tty name");
	    } else {
	      if (pam_get_item(pamh, PAM_SERVICE, &void_from) != PAM_SUCCESS
		  || void_from == NULL) {
		pam_syslog (pamh, LOG_ERR,
		     "cannot determine remote host, tty or service name");
		return PAM_ABORT;
	      }
	      from = void_from;
	      if (pam_access_debug)
		pam_syslog (pamh, LOG_DEBUG,
			    "cannot determine tty or remote hostname, using service %s",
			    from);
	    }
        }
	else
	  from = void_from;

	if (from[0] == '/') {   /* full path, remove device path.  */
	    const char *f;
	    from++;
	    if ((f = strchr(from, '/')) != NULL) {
		from = f + 1;
	    }
	}
    }

    if ((user_pw=pam_modutil_getpwnam(pamh, user))==NULL)
      return (PAM_USER_UNKNOWN);

    /*
     * Bundle up the arguments to avoid unnecessary clumsiness later on.
     */
    loginfo.user = user_pw;
    loginfo.from = from;
    loginfo.config_file = PAM_ACCESS_CONFIG;

    /* parse the argument list */

    if (!parse_args(pamh, &loginfo, argc, argv)) {
	pam_syslog(pamh, LOG_ERR, "failed to parse the module arguments");
	return PAM_ABORT;
    }

    if (login_access(pamh, &loginfo)) {
	return (PAM_SUCCESS);
    } else {
	pam_syslog(pamh, LOG_ERR,
                   "access denied for user `%s' from `%s'",user,from);
	return (PAM_PERM_DENIED);
    }
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
  return pam_sm_authenticate (pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
  return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
  return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
  return pam_sm_authenticate(pamh, flags, argc, argv);
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_access_modstruct = {
    "pam_access",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};
#endif
