/* pam_userdb module */

/*
 * $Id$
 * Written by Cristian Gafton <gafton@redhat.com> 1996/09/10
 * See the end of the file for Copyright Information
 */

#include <security/_pam_aconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "pam_userdb.h"

#ifdef HAVE_NDBM_H
# include <ndbm.h>
#else
# ifdef HAVE_DB_H
#  define DB_DBM_HSEARCH    1 /* use the dbm interface */
#  include <db.h>
# else
#  error "failed to find a libdb or equivalent"
# endif
#endif

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>

/* some syslogging */

static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog(MODULE_NAME, LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

static int
_pam_parse (int argc, const char **argv,
	    char **database, char **cryptmode)
{
  int ctrl;

  *database = NULL;
  *cryptmode = NULL;

  /* step through arguments */
  for (ctrl = 0; argc-- > 0; ++argv)
    {
      /* generic options */

      if (!strcmp(*argv,"debug"))
	ctrl |= PAM_DEBUG_ARG;
      else if (!strcasecmp(*argv, "icase"))
	ctrl |= PAM_ICASE_ARG;
      else if (!strcasecmp(*argv, "dump"))
	ctrl |= PAM_DUMP_ARG;
      else if (!strcasecmp(*argv, "unknown_ok"))
	ctrl |= PAM_UNKNOWN_OK_ARG;
      else if (!strcasecmp(*argv, "key_only"))
	ctrl |= PAM_KEY_ONLY_ARG;
      else if (!strncasecmp(*argv,"db=", 3))
	{
	  *database = strdup((*argv) + 3);
	  if ((*database == NULL) || (strlen (*database) == 0))
	    _pam_log(LOG_ERR,
		     "pam_parse: could not parse argument \"%s\"",
		     *argv);
	}
      else if (!strncasecmp(*argv,"crypt=", 6))
	{
	  *cryptmode = strdup((*argv) + 6);
	  if ((*cryptmode == NULL) || (strlen (*cryptmode) == 0))
	    _pam_log(LOG_ERR,
		     "pam_parse: could not parse argument \"%s\"",
		     *argv);
	}
      else
	{
	  _pam_log(LOG_ERR, "pam_parse: unknown option; %s", *argv);
	}
    }

  return ctrl;
}


/*
 * Looks up an user name in a database and checks the password
 *
 * return values:
 *	 1  = User not found
 *	 0  = OK
 * 	-1  = Password incorrect
 *	-2  = System error
 */
static int
user_lookup (const char *database, const char *cryptmode,
	     const char *user, const char *pass, int ctrl)
{
    DBM *dbm;
    datum key, data;

    /* Open the DB file. */
    dbm = dbm_open(database, O_RDONLY, 0644);
    if (dbm == NULL) {
	_pam_log(LOG_ERR, "user_lookup: could not open database `%s'",
		 database);
	return -2;
    }

    /* dump out the database contents for debugging */
    if (ctrl & PAM_DUMP_ARG) {
	_pam_log(LOG_INFO, "Database dump:");
	for (key = dbm_firstkey(dbm);  key.dptr != NULL;
	     key = dbm_nextkey(dbm)) {
	    data = dbm_fetch(dbm, key);
	    _pam_log(LOG_INFO, "key[len=%d] = `%s', data[len=%d] = `%s'",
		     key.dsize, key.dptr, data.dsize, data.dptr);
	}
    }

    /* do some more init work */
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    if (ctrl & PAM_KEY_ONLY_ARG) {
        key.dptr = malloc(strlen(user) + 1 + strlen(pass) + 1);
        sprintf(key.dptr, "%s-%s", user, pass);
        key.dsize = strlen(key.dptr);
    } else {
        key.dptr = x_strdup(user);
        key.dsize = strlen(user);
    }

    if (key.dptr) {
	data = dbm_fetch(dbm, key);
	memset(key.dptr, 0, key.dsize);
	free(key.dptr);
    }

    if (ctrl & PAM_DEBUG_ARG) {
	_pam_log(LOG_INFO, "password in database is [%p]`%s', len is %d",
		 data.dptr, (char *) data.dptr, data.dsize);
    }

    if (data.dptr != NULL) {
	int compare = 0;

	if (ctrl & PAM_KEY_ONLY_ARG)
	  {
	    dbm_close (dbm);
	    return 0; /* found it, data contents don't matter */
	}

	if (strncasecmp(cryptmode, "crypt", 5) == 0) {

	  /* crypt(3) password storage */

	  char *cryptpw;
	  char salt[2];

	  if (data.dsize != 13) {
	    compare = -2;
	  } else if (ctrl & PAM_ICASE_ARG) {
	    compare = -2;
	  } else {
	    salt[0] = *data.dptr;
	    salt[1] = *(data.dptr + 1);

	    cryptpw = crypt (pass, salt);

	    if (cryptpw) {
	      compare = strncasecmp (data.dptr, cryptpw, data.dsize);
	    } else {
	      compare = -2;
	      if (ctrl & PAM_DEBUG_ARG) {
		_pam_log(LOG_INFO, "crypt() returned NULL");
	      }
	    };

	  };

	} else {

	  /* Unknown password encryption method -
	   * default to plaintext password storage
	   */

	if (strlen(pass) != data.dsize) {
	  compare = 1; /* wrong password len -> wrong password */
	} else if (ctrl & PAM_ICASE_ARG) {
	    compare = strncasecmp(data.dptr, pass, data.dsize);
	} else {
	    compare = strncmp(data.dptr, pass, data.dsize);
	}

	  if (strncasecmp(cryptmode, "none", 4) && ctrl & PAM_DEBUG_ARG) {
	    _pam_log(LOG_INFO, "invalid value for crypt parameter: %s",
		     cryptmode);
	    _pam_log(LOG_INFO, "defaulting to plaintext password mode");
	  }

	}

	dbm_close(dbm);
	if (compare == 0)
	    return 0; /* match */
	else
	    return -1; /* wrong */
    } else {
        int saw_user = 0;

	if (ctrl & PAM_DEBUG_ARG) {
	    _pam_log(LOG_INFO, "error returned by dbm_fetch: %s",
		     strerror(errno));
	}

	/* probably we should check dbm_error() here */

        if ((ctrl & PAM_KEY_ONLY_ARG) == 0) {
	    dbm_close(dbm);
            return 1; /* not key_only, so no entry => no entry for the user */
        }

        /* now handle the key_only case */
        for (key = dbm_firstkey(dbm);
             key.dptr != NULL;
             key = dbm_nextkey(dbm)) {
            int compare;
            /* first compare the user portion (case sensitive) */
            compare = strncmp(key.dptr, user, strlen(user));
            if (compare == 0) {
                /* assume failure */
                compare = -1;
                /* if we have the divider where we expect it to be... */
                if (key.dptr[strlen(user)] == '-') {
		    saw_user = 1;
		    if (key.dsize == strlen(user) + 1 + strlen(pass)) {
		        if (ctrl & PAM_ICASE_ARG) {
			    /* compare the password portion (case insensitive)*/
                            compare = strncasecmp(key.dptr + strlen(user) + 1,
                                                  pass,
                                                  strlen(pass));
		        } else {
                            /* compare the password portion (case sensitive) */
                            compare = strncmp(key.dptr + strlen(user) + 1,
                                              pass,
                                              strlen(pass));
		        }
		    }
                }
                if (compare == 0) {
                    dbm_close(dbm);
                    return 0; /* match */
                }
            }
        }
        dbm_close(dbm);
	if (saw_user)
	    return -1; /* saw the user, but password mismatch */
	else
	    return 1; /* not found */
    }

    /* NOT REACHED */
    return -2;
}

/* --- authentication management functions (only) --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
     const char *username;
     const char *password;
     char *database = NULL;
     char *cryptmode = NULL;
     int retval = PAM_AUTH_ERR, ctrl;

     /* parse arguments */
     ctrl = _pam_parse(argc, argv, &database, &cryptmode);
     if ((database == NULL) || (strlen(database) == 0)) {
        if (ctrl & PAM_DEBUG_ARG)
            _pam_log(LOG_DEBUG,"can not get the database name");
        return PAM_SERVICE_ERR;
     }

     /* Get the username */
     retval = pam_get_user(pamh, &username, NULL);
     if ((retval != PAM_SUCCESS) || (!username)) {
        if (ctrl & PAM_DEBUG_ARG)
            _pam_log(LOG_DEBUG,"can not get the username");
        return PAM_SERVICE_ERR;
     }

     /* Converse just to be sure we have a password */
     retval = conversation(pamh);
     if (retval != PAM_SUCCESS) {
	 _pam_log(LOG_ERR, "could not obtain password for `%s'",
		  username);
	 return PAM_CONV_ERR;
     }

     /* Check if we got a password.  The docs say that if we didn't have one,
      * and use_authtok was specified as an argument, that we converse with the
      * user anyway, so check for one and handle a failure for that case.  If
      * use_authtok wasn't specified, then we've already asked once and needn't
      * do so again. */
     retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password);
     if ((retval != PAM_SUCCESS) && ((ctrl & PAM_USE_AUTHTOK_ARG) != 0)) {
        retval = conversation(pamh);
        if (retval != PAM_SUCCESS) {
           _pam_log(LOG_ERR, "could not obtain password for `%s'",
                    username);
           return PAM_CONV_ERR;
        }
     }

     /* Get the password */
     retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
     if (retval != PAM_SUCCESS) {
	 _pam_log(LOG_ERR, "Could not retrieve user's password");
	 return -2;
     }

     if (ctrl & PAM_DEBUG_ARG)
	 _pam_log(LOG_INFO, "Verify user `%s' with password `%s'",
		  username, password);

     /* Now use the username to look up password in the database file */
     retval = user_lookup(database, cryptmode, username, password, ctrl);
     switch (retval) {
	 case -2:
	     /* some sort of system error. The log was already printed */
	     return PAM_SERVICE_ERR;
	 case -1:
	     /* incorrect password */
	     _pam_log(LOG_WARNING,
		      "user `%s' denied access (incorrect password)",
		      username);
	     return PAM_AUTH_ERR;
	 case 1:
	     /* the user does not exist in the database */
	     if (ctrl & PAM_DEBUG_ARG)
		 _pam_log(LOG_NOTICE, "user `%s' not found in the database",
			  username);
	     return PAM_USER_UNKNOWN;
	 case 0:
	     /* Otherwise, the authentication looked good */
	     _pam_log(LOG_NOTICE, "user '%s' granted acces", username);
	     return PAM_SUCCESS;
	 default:
	     /* we don't know anything about this return value */
	     _pam_log(LOG_ERR,
		      "internal module error (retval = %d, user = `%s'",
		      retval, username);
	     return PAM_SERVICE_ERR;
     }

     /* should not be reached */
     return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *username;
    char *database = NULL;
    char *cryptmode = NULL;
    int retval = PAM_AUTH_ERR, ctrl;

    /* parse arguments */
    ctrl = _pam_parse(argc, argv, &database, &cryptmode);

    /* Get the username */
    retval = pam_get_user(pamh, &username, NULL);
    if ((retval != PAM_SUCCESS) || (!username)) {
        if (ctrl & PAM_DEBUG_ARG)
            _pam_log(LOG_DEBUG,"can not get the username");
        return PAM_SERVICE_ERR;
    }

    /* Now use the username to look up password in the database file */
    retval = user_lookup(database, cryptmode, username, "", ctrl);
    switch (retval) {
        case -2:
	    /* some sort of system error. The log was already printed */
	    return PAM_SERVICE_ERR;
	case -1:
	    /* incorrect password, but we don't care */
	    /* FALL THROUGH */
	case 0:
	    /* authentication succeeded. dumbest password ever. */
	    return PAM_SUCCESS;
	case 1:
	    /* the user does not exist in the database */
	    return PAM_USER_UNKNOWN;
        default:
	    /* we don't know anything about this return value */
	    _pam_log(LOG_ERR,
		     "internal module error (retval = %d, user = `%s'",
		     retval, username);
        return PAM_SERVICE_ERR;
    }

    return PAM_SUCCESS;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_userdb_modstruct = {
     "pam_userdb",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     NULL,
};

#endif

/*
 * Copyright (c) Cristian Gafton <gafton@redhat.com>, 1999
 *                                              All rights reserved
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
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
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
