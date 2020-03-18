/* pam_userdb module */

/*
 * Written by Cristian Gafton <gafton@redhat.com> 1996/09/10
 * With additions by Alan Mizrahi <lameventanas@gmail.com> 2017/05/16
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

#ifdef HAVE_DB_H
# include <db.h>
#else
# error "failed to find a libdb or equivalent"
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
#include <security/pam_ext.h>
#include <security/_pam_macros.h>

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
	    const char **database, e_hashmode *hashmode)
{
  int ctrl;

  *database = NULL;
  *hashmode = NONE;

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
      else if (!strcasecmp(*argv, "use_first_pass"))
	ctrl |= PAM_USE_FPASS_ARG;
      else if (!strcasecmp(*argv, "try_first_pass"))
	ctrl |= PAM_TRY_FPASS_ARG;
      else if (!strncasecmp(*argv,"db=", 3))
	{
	  *database = (*argv) + 3;
	  if (**database == '\0') {
	    *database = NULL;
	    pam_syslog(pamh, LOG_ERR,
		       "db= specification missing argument - ignored");
	  }
	}
      else if (!strncasecmp(*argv, "hash=", 5))
	{
		const char *algo = (*argv) + 5;
		if (! strcmp(algo, "crypt")) {
			ctrl |= PAM_HASH_ARG;
			*hashmode = CRYPT;
		} else if (! strcmp(algo, "none")) {
			*hashmode = NONE;
		} else {
			pam_syslog(pamh, LOG_ERR, "Invalid hash argument: `%s' - ignored", algo);
		}
	}
      else
	{
	  pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
	}
    }
    if ( (ctrl & PAM_HASH_ARG) && (ctrl & PAM_ICASE_ARG) )
	pam_syslog(pamh, LOG_ERR, "Warning: icase doesn't work with hashed passwords");
  return ctrl;
}

/* crypt-compare string with stored password
 * returns 0 if equal
 */
static int cmp_hash_crypt(const char *stored, const char *str) {
	char *cryptpw = NULL;
	int compare = -2;

#ifdef HAVE_CRYPT_R
	struct crypt_data cdata;
	memset(&cdata, 0, sizeof(cdata));
	cryptpw = crypt_r(str, stored, &cdata);
#else
	cryptpw = crypt (str, stored);
#endif
	if (cryptpw != NULL && strlen(cryptpw) == strlen(stored))
		compare = strncmp(stored, cryptpw, strlen(cryptpw));

	return compare;
}

static int cmp_password(const char *stored, const char *str, const int ctrl, const e_hashmode hashmode) {
	int compare = -1;

	if (ctrl & PAM_HASH_ARG) {
		switch(hashmode) {
			case CRYPT:
				compare = cmp_hash_crypt(stored, str);
				break;
			default:
				break;
		}
	} else {
		if (ctrl & PAM_ICASE_ARG)
			compare = strcasecmp(stored, str);
		else
			compare = strcmp(stored, str);
	}
	return compare;
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
user_lookup (pam_handle_t *pamh, const char *database, e_hashmode hashmode, const char *user, const char *pass, int ctrl) {
	DB *dbp;
	DBT key, data;
	DBC *cur;
	int err;

	if (ctrl & PAM_DEBUG_ARG) {
#define ARG_ACTIVE(a) ((ctrl & a) == a)
		pam_syslog(pamh, LOG_INFO, "user_lookup key_only:%d icase:%d hash:%d unknown_ok:%d use_fpass:%d try_fpass:%d hashmode:%d database:`%s'", ARG_ACTIVE(PAM_KEY_ONLY_ARG), ARG_ACTIVE(PAM_ICASE_ARG), ARG_ACTIVE(PAM_HASH_ARG), ARG_ACTIVE(PAM_UNKNOWN_OK_ARG), ARG_ACTIVE(PAM_USE_FPASS_ARG), ARG_ACTIVE(PAM_TRY_FPASS_ARG), hashmode, database);
	}

	err = db_create(&dbp, NULL, 0);
	if (err != 0) {
		pam_syslog(pamh, LOG_ERR, "user_lookup: could not create database handle: %s", db_strerror(err));
		return -2;
	}

	/* Open the DB file. */
	err = dbp->open(dbp, NULL, database, NULL, DB_UNKNOWN, 0, 0644);
	if (err != 0 ) {
		pam_syslog(pamh, LOG_ERR,
			"user_lookup: could not open database `%s': %s", database, db_strerror(err));
		return -2;
	}

	/* dump database contents for debugging */
	if (ctrl & PAM_DUMP_ARG) {
		err = dbp->cursor(dbp, NULL, &cur, 0);
		if (err != 0) {
			pam_syslog(pamh, LOG_ERR, "user_lookup: could not create cursor for database `%s': %s", database, strerror(err));
		} else {
			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));
			key.flags  = DB_DBT_REALLOC;
			data.flags = DB_DBT_REALLOC;
			pam_syslog(pamh, LOG_INFO, "user_lookup: database dump:");
			while (0 == (err = cur->get(cur, &key, &data, DB_NEXT))) {
				*((char *)key.data + key.size) = 0;
				*((char *)data.data + data.size) = 0;
				pam_syslog(pamh, LOG_INFO, "key[len=%d] = `%s', data[len=%d] = `%s'\n", key.size, (char *)key.data, data.size, (char *)data.data);
			}
			if (err != DB_NOTFOUND)
				pam_syslog(pamh, LOG_ERR, "error getting next value: %s\n", db_strerror(err));
			free(key.data);
			free(data.data);
			cur->close(cur);
		}
	}

	if (ctrl & PAM_KEY_ONLY_ARG) { // key_only
		err = dbp->cursor(dbp, NULL, &cur, 0);
		if (err != 0) {
			pam_syslog(pamh, LOG_ERR, "user_lookup: could not create cursor for database `%s': %s", database, strerror(err));
			cur->close(cur);
			dbp->close(dbp, 0);
			return -2;
		}
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		key.flags  = DB_DBT_REALLOC;

		int saw_user = 0;
		int compare = -1;

		while (0 == (err = cur->get(cur, &key, &data, DB_NEXT))) {
			if (ctrl & PAM_DEBUG_ARG)
				pam_syslog(pamh, LOG_INFO, "checking db entry `%.*s' len %d", key.size, (char *)key.data, key.size);

			*((char *)key.data + key.size) = 0;
			if ((key.size > strlen(user)) && (*((char *)key.data + strlen(user)) == '-') && (0 == strncmp(key.data, user, strlen(user)))) {
				/* username matched and divider was in right position */
				saw_user = 1;
				const char *dbpass = (char *)key.data + strlen(user) + 1;

				compare = cmp_password(dbpass, pass, ctrl, hashmode);
			}
			if (compare == 0)
				break; /* match */
		}
		if (err != 0 && err != DB_NOTFOUND)
			pam_syslog(pamh, LOG_ERR, "error getting next value: %s\n", db_strerror(err));
		free(key.data);
		cur->close(cur);
		dbp->close(dbp, 0);
		if (compare == 0) {
			return 0; /* password match */
		} else {
			if (saw_user)
				return -1; /* saw the user, but password mismatch */
			else
				return 1; /* not found */
		}

	} else { // not key_only: can do a db->get
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		data.flags = DB_DBT_REALLOC;

		key.data = user;
		key.size = strlen(user);

		err = dbp->get(dbp, NULL, &key, &data, 0);
		if (err != 0) {
			if ((ctrl & PAM_DEBUG_ARG) || (err != DB_NOTFOUND))
				pam_syslog(pamh, LOG_INFO, "couldn't find `%.*s': %s", key.size, (char *)key.data, db_strerror(err));
			dbp->close(dbp, 0);
			return 1;
		}

		/* found user */

		*((char *)data.data + data.size) = 0;

		/* now check password considering all cases: normal, icase or hash  */
		int compare = cmp_password(data.data, pass, ctrl, hashmode);

		dbp->close(dbp, 0);

		return (compare == 0) ? 0 : -1;
	}

	return -2; /* not reached */
}

/* --- authentication management functions (only) --- */

int
pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
     const char *username;
     const void *password;
     const char *database = NULL;
     e_hashmode hashmode;
     int retval = PAM_AUTH_ERR, ctrl;

     /* parse arguments */
     ctrl = _pam_parse(pamh, argc, argv, &database, &hashmode);
     if (database == NULL) {
        pam_syslog(pamh, LOG_ERR, "can not get the database name");
        return PAM_SERVICE_ERR;
     }

     /* Get the username */
     retval = pam_get_user(pamh, &username, NULL);
     if ((retval != PAM_SUCCESS) || (!username)) {
        pam_syslog(pamh, LOG_ERR, "can not get the username");
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
     retval = user_lookup(pamh, database, hashmode, username, password, ctrl);
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
    e_hashmode hashmode;
    int retval = PAM_AUTH_ERR, ctrl;

    /* parse arguments */
    ctrl = _pam_parse(pamh, argc, argv, &database, &hashmode);

    /* Get the username */
    retval = pam_get_user(pamh, &username, NULL);
    if ((retval != PAM_SUCCESS) || (!username)) {
        pam_syslog(pamh, LOG_ERR,"can not get the username");
        return PAM_SERVICE_ERR;
    }

    /* Now use the username to look up password in the database file */
    retval = user_lookup(pamh, database, hashmode, username, "", ctrl);
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
