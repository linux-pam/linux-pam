/*
 * pam_userdb module
 *
 * Written by Cristian Gafton <gafton@redhat.com> 1996/09/10
 * See the end of the file for Copyright Information
 */

#include "config.h"

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
#ifdef HAVE_LIBXCRYPT
#include <xcrypt.h>
#elif defined(HAVE_CRYPT_H)
#include <crypt.h>
#endif

#include "pam_userdb.h"

#ifdef HAVE_NDBM_H
# include <ndbm.h>
#else
# ifdef HAVE_DB_H
#  define DB_DBM_HSEARCH    1 /* use the dbm interface */
#  define HAVE_DBM	      /* for BerkDB 5.0 and later */
#  include <db.h>
# else
#  error "failed to find a libdb or equivalent"
# endif
#endif

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>
#include "pam_inline.h"

/*
 * Conversation function to obtain the user's password
 */
static int
obtain_authtok(pam_handle_t *pamh)
{
    char *resp;
    const void *item;
    int retval;

    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, _("Password: "));

    if (retval != PAM_SUCCESS)
	return retval;

    if (resp == NULL)
	return PAM_CONV_ERR;

    /* set the auth token */
    retval = pam_set_item(pamh, PAM_AUTHTOK, resp);

    /* clean it up */
    _pam_overwrite(resp);
    _pam_drop(resp);

    if ( (retval != PAM_SUCCESS) ||
	 (retval = pam_get_item(pamh, PAM_AUTHTOK, &item))
	 != PAM_SUCCESS ) {
	return retval;
    }

    return retval;
}

static int
_pam_parse (pam_handle_t *pamh, int argc, const char **argv,
	    const char **database, const char **cryptmode)
{
  int ctrl;

  *database = NULL;
  *cryptmode = NULL;

  /* step through arguments */
  for (ctrl = 0; argc-- > 0; ++argv)
    {
      const char *str;

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
      else if (!strcasecmp(*argv, "use_first_pass"))
	ctrl |= PAM_USE_FPASS_ARG;
      else if (!strcasecmp(*argv, "try_first_pass"))
	ctrl |= PAM_TRY_FPASS_ARG;
      else if ((str = pam_str_skip_icase_prefix(*argv, "db=")) != NULL)
	{
	  *database = str;
	  if (**database == '\0') {
	    *database = NULL;
	    pam_syslog(pamh, LOG_ERR,
		       "db= specification missing argument - ignored");
	  }
	}
      else if ((str = pam_str_skip_icase_prefix(*argv, "crypt=")) != NULL)
	{
	  *cryptmode = str;
	  if (**cryptmode == '\0')
	    pam_syslog(pamh, LOG_ERR,
		       "crypt= specification missing argument - ignored");
	}
      else
	{
	  pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
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
 *	-1  = Password incorrect
 *	-2  = System error
 */
static int
user_lookup (pam_handle_t *pamh, const char *database, const char *cryptmode,
	     const char *user, const char *pass, int ctrl)
{
    DBM *dbm;
    datum key, data;

    /* Open the DB file. */
    dbm = dbm_open(database, O_RDONLY, 0644);
    if (dbm == NULL) {
	pam_syslog(pamh, LOG_ERR,
		   "user_lookup: could not open database `%s': %m", database);
	return -2;
    }

    /* dump out the database contents for debugging */
    if (ctrl & PAM_DUMP_ARG) {
	pam_syslog(pamh, LOG_INFO, "Database dump:");
	for (key = dbm_firstkey(dbm);  key.dptr != NULL;
	     key = dbm_nextkey(dbm)) {
	    data = dbm_fetch(dbm, key);
	    pam_syslog(pamh, LOG_INFO,
		       "key[len=%d] = `%s', data[len=%d] = `%s'",
		       key.dsize, key.dptr, data.dsize, data.dptr);
	}
    }

    /* do some more init work */
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    if (ctrl & PAM_KEY_ONLY_ARG) {
	if (asprintf(&key.dptr, "%s-%s", user, pass) < 0)
	    key.dptr = NULL;
	else
	    key.dsize = strlen(key.dptr);
    } else {
        key.dptr = strdup(user);
        key.dsize = strlen(user);
    }

    if (key.dptr) {
	data = dbm_fetch(dbm, key);
	memset(key.dptr, 0, key.dsize);
	free(key.dptr);
    }

    if (ctrl & PAM_DEBUG_ARG) {
	pam_syslog(pamh, LOG_INFO,
		   "password in database is [%p]`%.*s', len is %d",
		   data.dptr, data.dsize, (char *) data.dptr, data.dsize);
    }

    if (data.dptr != NULL) {
	int compare = 0;

	if (ctrl & PAM_KEY_ONLY_ARG)
	  {
	    dbm_close (dbm);
	    return 0; /* found it, data contents don't matter */
	}

	if (cryptmode && pam_str_skip_icase_prefix(cryptmode, "crypt") != NULL) {

	  /* crypt(3) password storage */

	  char *cryptpw = NULL;

	  if (data.dsize < 13) {
	    compare = -2;
	  } else if (ctrl & PAM_ICASE_ARG) {
	    compare = -2;
	  } else {
#ifdef HAVE_CRYPT_R
	    struct crypt_data *cdata = NULL;
	    cdata = malloc(sizeof(*cdata));
	    if (cdata != NULL) {
		cdata->initialized = 0;
		cryptpw = crypt_r(pass, data.dptr, cdata);
	    }
#else
	    cryptpw = crypt (pass, data.dptr);
#endif
	    if (cryptpw && strlen(cryptpw) == (size_t)data.dsize) {
	      compare = memcmp(data.dptr, cryptpw, data.dsize);
	    } else {
	      compare = -2;
	      if (ctrl & PAM_DEBUG_ARG) {
		if (cryptpw)
		  pam_syslog(pamh, LOG_INFO, "lengths of computed and stored hashes differ");
		else
		  pam_syslog(pamh, LOG_INFO, "crypt() returned NULL");
	      }
	    }
#ifdef HAVE_CRYPT_R
	    free(cdata);
#endif
	  }

	} else {

	  /* Unknown password encryption method -
	   * default to plaintext password storage
	   */

	  if (strlen(pass) != (size_t)data.dsize) {
	    compare = 1; /* wrong password len -> wrong password */
	  } else if (ctrl & PAM_ICASE_ARG) {
	    compare = strncasecmp(data.dptr, pass, data.dsize);
	  } else {
	    compare = strncmp(data.dptr, pass, data.dsize);
	  }

	  if (cryptmode && pam_str_skip_icase_prefix(cryptmode, "none") == NULL
		&& (ctrl & PAM_DEBUG_ARG)) {
	    pam_syslog(pamh, LOG_INFO, "invalid value for crypt parameter: %s",
		       cryptmode);
	    pam_syslog(pamh, LOG_INFO, "defaulting to plaintext password mode");
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
	    pam_syslog(pamh, LOG_INFO, "error returned by dbm_fetch: %m");
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
		    if ((size_t)key.dsize == strlen(user) + 1 + strlen(pass)) {
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

int
pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
     const char *username;
     const void *password;
     const char *database = NULL;
     const char *cryptmode = NULL;
     int retval = PAM_AUTH_ERR, ctrl;

     /* parse arguments */
     ctrl = _pam_parse(pamh, argc, argv, &database, &cryptmode);
     if (database == NULL) {
        pam_syslog(pamh, LOG_ERR, "can not get the database name");
        return PAM_SERVICE_ERR;
     }

     /* Get the username */
     retval = pam_get_user(pamh, &username, NULL);
     if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "cannot determine user name: %s",
                   pam_strerror(pamh, retval));
        return PAM_SERVICE_ERR;
     }

     if ((ctrl & PAM_USE_FPASS_ARG) == 0 && (ctrl & PAM_TRY_FPASS_ARG) == 0) {
        /* Converse to obtain a password */
        retval = obtain_authtok(pamh);
        if (retval != PAM_SUCCESS) {
	    pam_syslog(pamh, LOG_ERR, "can not obtain password from user");
	    return retval;
        }
     }

     /* Check if we got a password */
     retval = pam_get_item(pamh, PAM_AUTHTOK, &password);
     if (retval != PAM_SUCCESS || password == NULL) {
        if ((ctrl & PAM_TRY_FPASS_ARG) != 0) {
	    /* Converse to obtain a password */
	    retval = obtain_authtok(pamh);
	    if (retval != PAM_SUCCESS) {
	        pam_syslog(pamh, LOG_ERR, "can not obtain password from user");
		return retval;
	    }
	    retval = pam_get_item(pamh, PAM_AUTHTOK, &password);
	}
	if (retval != PAM_SUCCESS || password == NULL) {
	    pam_syslog(pamh, LOG_ERR, "can not recover user password");
	    return PAM_AUTHTOK_RECOVERY_ERR;
	}
     }

     if (ctrl & PAM_DEBUG_ARG)
	 pam_syslog(pamh, LOG_INFO, "Verify user `%s' with a password",
		    username);

     /* Now use the username to look up password in the database file */
     retval = user_lookup(pamh, database, cryptmode, username, password, ctrl);
     switch (retval) {
	 case -2:
	     /* some sort of system error. The log was already printed */
	     return PAM_SERVICE_ERR;
	 case -1:
	     /* incorrect password */
	     pam_syslog(pamh, LOG_NOTICE,
			"user `%s' denied access (incorrect password)",
			username);
	     return PAM_AUTH_ERR;
	 case 1:
	     /* the user does not exist in the database */
	     if (ctrl & PAM_DEBUG_ARG)
		 pam_syslog(pamh, LOG_NOTICE,
			    "user `%s' not found in the database", username);
	     return PAM_USER_UNKNOWN;
	 case 0:
	     /* Otherwise, the authentication looked good */
	     pam_syslog(pamh, LOG_NOTICE, "user '%s' granted access", username);
	     return PAM_SUCCESS;
	 default:
	     /* we don't know anything about this return value */
	     pam_syslog(pamh, LOG_ERR,
		      "internal module error (retval = %d, user = `%s'",
		      retval, username);
	     return PAM_SERVICE_ERR;
     }

     /* should not be reached */
     return PAM_IGNORE;
}

int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		 int argc, const char **argv)
{
    const char *username;
    const char *database = NULL;
    const char *cryptmode = NULL;
    int retval = PAM_AUTH_ERR, ctrl;

    /* parse arguments */
    ctrl = _pam_parse(pamh, argc, argv, &database, &cryptmode);

    /* Get the username */
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "cannot determine user name: %s",
                   pam_strerror(pamh, retval));
        return PAM_SERVICE_ERR;
    }

    /* Now use the username to look up password in the database file */
    retval = user_lookup(pamh, database, cryptmode, username, "", ctrl);
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
	    pam_syslog(pamh, LOG_ERR,
		       "internal module error (retval = %d, user = `%s'",
		       retval, username);
            return PAM_SERVICE_ERR;
    }

    return PAM_SUCCESS;
}

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
