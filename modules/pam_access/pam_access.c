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
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#ifdef HAVE_RPCSVC_YPCLNT_H
#include <rpcsvc/ypclnt.h>
#endif
#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#endif

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


#define ALL             2
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
    const char *hostname;
    int debug;				/* Print debugging messages. */
    int only_new_group_syntax;		/* Only allow group entries of the form "(xyz)" */
    int noaudit;			/* Do not audit denials */
    const char *fs;			/* field separator */
    const char *sep;			/* list-element separator */
    int from_remote_host;               /* If PAM_RHOST was used for from */
    struct addrinfo *res;		/* Cached DNS resolution of from */
    int gai_rv;				/* Cached retval of getaddrinfo */
};

/* Parse module config arguments */

static int
parse_args(pam_handle_t *pamh, struct login_info *loginfo,
           int argc, const char **argv)
{
    int i;

    loginfo->noaudit = NO;
    loginfo->debug = NO;
    loginfo->only_new_group_syntax = NO;
    loginfo->fs = ":";
    loginfo->sep = ", \t";
    for (i=0; i<argc; ++i) {
	if (!strncmp("fieldsep=", argv[i], 9)) {

	    /* the admin wants to override the default field separators */
	    loginfo->fs = argv[i]+9;

	} else if (!strncmp("listsep=", argv[i], 8)) {

	    /* the admin wants to override the default list separators */
	    loginfo->sep = argv[i]+8;

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
	    loginfo->debug = YES;
	} else if (strcmp (argv[i], "nodefgroup") == 0) {
	    loginfo->only_new_group_syntax = YES;
	} else if (strcmp (argv[i], "noaudit") == 0) {
	    loginfo->noaudit = YES;
	} else {
	    pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", argv[i]);
	}
    }

    return 1;  /* OK */
}

/* --- static functions for checking whether the user should be let in --- */

typedef int match_func (pam_handle_t *, char *, struct login_info *);

static int list_match (pam_handle_t *, char *, char *, struct login_info *,
		       match_func *);
static int user_match (pam_handle_t *, char *, struct login_info *);
static int group_match (pam_handle_t *, const char *, const char *, int);
static int from_match (pam_handle_t *, char *, struct login_info *);
static int string_match (pam_handle_t *, const char *, const char *, int);
static int network_netmask_match (pam_handle_t *, const char *, const char *, struct login_info *);


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
    int     nonall_match = NO;
    int     end;
    int     lineno = 0;		/* for diagnostics */
    char   *sptr;

    if (item->debug)
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
	    if (!(perm = strtok_r(line, item->fs, &sptr))
		|| !(users = strtok_r(NULL, item->fs, &sptr))
		|| !(froms = strtok_r(NULL, "\n", &sptr))) {
		pam_syslog(pamh, LOG_ERR, "%s: line %d: bad field count",
			   item->config_file, lineno);
		continue;
	    }
	    if (perm[0] != '+' && perm[0] != '-') {
		pam_syslog(pamh, LOG_ERR, "%s: line %d: bad first field",
			   item->config_file, lineno);
		continue;
	    }
	    if (item->debug)
	      pam_syslog (pamh, LOG_DEBUG,
			  "line %d: %s : %s : %s", lineno, perm, users, froms);
	    match = list_match(pamh, users, NULL, item, user_match);
	    if (item->debug)
	      pam_syslog (pamh, LOG_DEBUG, "user_match=%d, \"%s\"",
			  match, item->user->pw_name);
	    if (match) {
		match = list_match(pamh, froms, NULL, item, from_match);
		if (!match && perm[0] == '+') {
		    nonall_match = YES;
		}
		if (item->debug)
		    pam_syslog (pamh, LOG_DEBUG,
				"from_match=%d, \"%s\"", match, item->from);
	    }
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
#ifdef HAVE_LIBAUDIT
    if (!item->noaudit && line[0] == '-' && (match == YES || (match == ALL &&
	nonall_match == YES))) {
	pam_modutil_audit_write(pamh, AUDIT_ANOM_LOGIN_LOCATION,
	    "pam_access", 0);
    }
#endif
    return (match == NO || (line[0] == '+'));
}


/* list_match - match an item against a list of tokens with exceptions */

static int
list_match(pam_handle_t *pamh, char *list, char *sptr,
	   struct login_info *item, match_func *match_fn)
{
    char   *tok;
    int     match = NO;

    if (item->debug && list != NULL)
      pam_syslog (pamh, LOG_DEBUG,
		  "list_match: list=%s, item=%s", list, item->user->pw_name);

    /*
     * Process tokens one at a time. We have exhausted all possible matches
     * when we reach an "EXCEPT" token or the end of the list. If we do find
     * a match, look for an "EXCEPT" list and recurse to determine whether
     * the match is affected by any exceptions.
     */

    for (tok = strtok_r(list, item->sep, &sptr); tok != 0;
	 tok = strtok_r(NULL, item->sep, &sptr)) {
	if (strcasecmp(tok, "EXCEPT") == 0)	/* EXCEPT: give up */
	    break;
	if ((match = (*match_fn) (pamh, tok, item)))	/* YES */
	    break;
    }
    /* Process exceptions to matches. */

    if (match != NO) {
	while ((tok = strtok_r(NULL, item->sep, &sptr)) && strcasecmp(tok, "EXCEPT"))
	     /* VOID */ ;
	if (tok == 0)
	    return match;
	if (list_match(pamh, NULL, sptr, item, match_fn) == NO)
	    return YES; /* drop special meaning of ALL */
    }
    return (NO);
}

/* netgroup_match - match group against machine or user */

static int
netgroup_match (pam_handle_t *pamh, const char *netgroup,
		const char *machine, const char *user, int debug)
{
  int retval;
  char *mydomain = NULL;

#if defined(HAVE_GETDOMAINNAME)
  char domainname_res[256];

  if (getdomainname (domainname_res, sizeof (domainname_res)) == 0)
    {
      if (domainname_res[0] != '\0' && strcmp (domainname_res, "(none)") != 0)
        {
          mydomain = domainname_res;
        }
    }
#elif defined(HAVE_YP_GET_DEFAULT_DOMAIN)
  yp_get_default_domain(&mydomain);
#endif

#ifdef HAVE_INNETGR
  retval = innetgr (netgroup, machine, user, mydomain);
#else
  retval = 0;
  pam_syslog (pamh, LOG_ERR, "pam_access does not have netgroup support");
#endif
  if (debug == YES)
    pam_syslog (pamh, LOG_DEBUG,
		"netgroup_match: %d (netgroup=%s, machine=%s, user=%s, domain=%s)",
		retval, netgroup ? netgroup : "NULL",
		machine ? machine : "NULL",
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
    int    rv;

    if (item->debug)
      pam_syslog (pamh, LOG_DEBUG,
		  "user_match: tok=%s, item=%s", tok, string);

    /*
     * If a token has the magic value "ALL" the match always succeeds.
     * Otherwise, return YES if the token fully matches the username, if the
     * token is a group that contains the username, or if the token is the
     * name of the user's primary group.
     */

    /* Try to split on a pattern (@*[^@]+)(@+.*) */
    for (at = tok; *at == '@'; ++at);

    if ((at = strchr(at, '@')) != NULL) {
        /* split user@host pattern */
	if (item->hostname == NULL)
	    return NO;
	memcpy (&fake_item, item, sizeof(fake_item));
	fake_item.from = item->hostname;
	fake_item.gai_rv = 0;
	fake_item.res = NULL;
	fake_item.from_remote_host = 1; /* hostname should be resolvable */
	*at = 0;
	if (!user_match (pamh, tok, item))
		return NO;
	rv = from_match (pamh, at + 1, &fake_item);
	if (fake_item.gai_rv == 0 && fake_item.res)
		freeaddrinfo(fake_item.res);
	return rv;
    } else if (tok[0] == '@') {			/* netgroup */
	const char *hostname = NULL;
	if (tok[1] == '@') {			/* add hostname to netgroup match */
		if (item->hostname == NULL)
		    return NO;
		++tok;
		hostname = item->hostname;
	}
        return (netgroup_match (pamh, tok + 1, hostname, string, item->debug));
    } else if (tok[0] == '(' && tok[strlen(tok) - 1] == ')')
      return (group_match (pamh, tok, string, item->debug));
    else if ((rv=string_match (pamh, tok, string, item->debug)) != NO) /* ALL or exact match */
      return rv;
    else if (item->only_new_group_syntax == NO &&
	     pam_modutil_user_in_group_nam_nam (pamh,
						item->user->pw_name, tok))
      /* try group membership */
      return YES;

    return NO;
}


/* group_match - match a username against token named group */

static int
group_match (pam_handle_t *pamh, const char *tok, const char* usr,
    int debug)
{
    char grptok[BUFSIZ];

    if (debug)
        pam_syslog (pamh, LOG_DEBUG,
		    "group_match: grp=%s, user=%s", grptok, usr);

    if (strlen(tok) < 3)
        return NO;

    /* token is recieved under the format '(...)' */
    memset(grptok, 0, BUFSIZ);
    strncpy(grptok, tok + 1, strlen(tok) - 2);

    if (pam_modutil_user_in_group_nam_nam(pamh, usr, grptok))
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
    int        rv;

    if (item->debug)
      pam_syslog (pamh, LOG_DEBUG,
		  "from_match: tok=%s, item=%s", tok, string);

    /*
     * If a token has the magic value "ALL" the match always succeeds. Return
     * YES if the token fully matches the string. If the token is a domain
     * name, return YES if it matches the last fields of the string. If the
     * token has the magic value "LOCAL", return YES if the from field was
     * not taken by PAM_RHOST. If the token is a network number, return YES
     * if it matches the head of the string.
     */

    if (string == NULL) {
	return NO;
    } else if (tok[0] == '@') {			/* netgroup */
        return (netgroup_match (pamh, tok + 1, string, (char *) 0, item->debug));
    } else if ((rv = string_match(pamh, tok, string, item->debug)) != NO) {
        /* ALL or exact match */
	return rv;
    } else if (tok[0] == '.') {			/* domain: match last fields */
	if ((str_len = strlen(string)) > (tok_len = strlen(tok))
	    && strcasecmp(tok, string + str_len - tok_len) == 0)
	    return (YES);
    } else if (item->from_remote_host == 0) {	/* local: no PAM_RHOSTS */
	if (strcasecmp(tok, "LOCAL") == 0)
	    return (YES);
    } else if (tok[(tok_len = strlen(tok)) - 1] == '.') {
      struct addrinfo hint;

      memset (&hint, '\0', sizeof (hint));
      hint.ai_flags = AI_CANONNAME;
      hint.ai_family = AF_INET;

      if (item->gai_rv != 0)
	return NO;
      else if (!item->res &&
		(item->gai_rv = getaddrinfo (string, NULL, &hint, &item->res)) != 0)
	return NO;
      else
	{
	  struct addrinfo *runp = item->res;

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
		      return YES;
		    }
		}
	      runp = runp->ai_next;
	    }
	}
    } else {
      /* Assume network/netmask with a IP of a host.  */
      if (network_netmask_match(pamh, tok, string, item))
	return YES;
    }

    return NO;
}

/* string_match - match a string against one token */

static int
string_match (pam_handle_t *pamh, const char *tok, const char *string,
    int debug)
{

    if (debug)
        pam_syslog (pamh, LOG_DEBUG,
		    "string_match: tok=%s, item=%s", tok, string);

    /*
     * If the token has the magic value "ALL" the match always succeeds.
     * Otherwise, return YES if the token fully matches the string.
	 * "NONE" token matches NULL string.
     */

    if (strcasecmp(tok, "ALL") == 0) {		/* all: always matches */
	return (ALL);
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
 * where string is a hostname or ip (v4,v6) address and tok
 * represents either a single ip (v4,v6) address or a network/netmask
 */
static int
network_netmask_match (pam_handle_t *pamh,
		       const char *tok, const char *string, struct login_info *item)
{
    char *netmask_ptr;
    char netmask_string[MAXHOSTNAMELEN + 1];
    int addr_type;

    if (item->debug)
    pam_syslog (pamh, LOG_DEBUG,
		"network_netmask_match: tok=%s, item=%s", tok, string);
    /* OK, check if tok is of type addr/mask */
    if ((netmask_ptr = strchr(tok, '/')) != NULL)
      {
	long netmask = 0;

	/* YES */
	*netmask_ptr = 0;
	netmask_ptr++;

	if (isipaddr(tok, &addr_type, NULL) == NO)
	  { /* no netaddr */
	    return NO;
	  }

	/* check netmask */
	if (isipaddr(netmask_ptr, NULL, NULL) == NO)
	  { /* netmask as integre value */
	    char *endptr = NULL;
	    netmask = strtol(netmask_ptr, &endptr, 0);
	    if ((endptr == NULL) || (*endptr != '\0'))
		{ /* invalid netmask value */
		  return NO;
		}
	    if ((netmask < 0) || (netmask >= 128))
		{ /* netmask value out of range */
		  return NO;
		}

	    netmask_ptr = number_to_netmask(netmask, addr_type,
		netmask_string, MAXHOSTNAMELEN);
	  }
	}
    else
	/* NO, then check if it is only an addr */
	if (isipaddr(tok, NULL, NULL) != YES)
	  {
	    return NO;
	  }

    if (isipaddr(string, NULL, NULL) != YES)
      {
	/* Assume network/netmask with a name of a host.  */
	struct addrinfo hint;

	memset (&hint, '\0', sizeof (hint));
	hint.ai_flags = AI_CANONNAME;
	hint.ai_family = AF_UNSPEC;

	if (item->gai_rv != 0)
	    return NO;
	else if (!item->res &&
		(item->gai_rv = getaddrinfo (string, NULL, &hint, &item->res)) != 0)
	    return NO;
        else
	  {
	    struct addrinfo *runp = item->res;

	    while (runp != NULL)
	      {
		char buf[INET6_ADDRSTRLEN];

		inet_ntop (runp->ai_family,
			runp->ai_family == AF_INET
			? (void *) &((struct sockaddr_in *) runp->ai_addr)->sin_addr
			: (void *) &((struct sockaddr_in6 *) runp->ai_addr)->sin6_addr,
			buf, sizeof (buf));

		if (are_addresses_equal(buf, tok, netmask_ptr))
		  {
		    return YES;
		  }
		runp = runp->ai_next;
	      }
	  }
      }
    else
      return (are_addresses_equal(string, tok, netmask_ptr));

  return NO;
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
    char hostname[MAXHOSTNAMELEN + 1];
    int rv;


    /* set username */

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL
	|| *user == '\0') {
	pam_syslog(pamh, LOG_ERR, "cannot determine the user's name");
	return PAM_USER_UNKNOWN;
    }

    if ((user_pw=pam_modutil_getpwnam(pamh, user))==NULL)
      return (PAM_USER_UNKNOWN);

    /*
     * Bundle up the arguments to avoid unnecessary clumsiness later on.
     */
    memset(&loginfo, '\0', sizeof(loginfo));
    loginfo.user = user_pw;
    loginfo.config_file = PAM_ACCESS_CONFIG;

    /* parse the argument list */

    if (!parse_args(pamh, &loginfo, argc, argv)) {
	pam_syslog(pamh, LOG_ERR, "failed to parse the module arguments");
	return PAM_ABORT;
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

        loginfo.from_remote_host = 0;

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
	      if (loginfo.debug)
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
    else
      loginfo.from_remote_host = 1;

    loginfo.from = from;

    hostname[sizeof(hostname)-1] = '\0';
    if (gethostname(hostname, sizeof(hostname)-1) == 0)
	loginfo.hostname = hostname;
    else {
	pam_syslog (pamh, LOG_ERR, "gethostname failed: %m");
	loginfo.hostname = NULL;
    }

    rv = login_access(pamh, &loginfo);

    if (loginfo.gai_rv == 0 && loginfo.res)
	freeaddrinfo(loginfo.res);

    if (rv) {
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
