/*
 * Copyright information at end of file.
 */
#include "config.h"
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include "support.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <syslog.h>
#include <stdarg.h>

#include "md5.h"
#include "bigcrypt.h"
#include "passverify.h"

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED is_selinux_enabled()>0
#else
#define SELINUX_ENABLED 0
#endif

#ifdef HELPER_COMPILE
#define pam_modutil_getpwnam(h,n) getpwnam(n)
#define pam_modutil_getspnam(h,n) getspnam(n)
#else
#include <security/pam_modutil.h>
#endif

int
verify_pwd_hash(const char *p, const char *hash, unsigned int nullok)
{
	size_t hash_len = strlen(hash);
	char *pp = NULL;
	int retval;
	D(("called"));

	if (!hash_len) {
		/* the stored password is NULL */
		if (nullok) { /* this means we've succeeded */
			D(("user has empty password - access granted"));
			retval = PAM_SUCCESS;
		} else {
			D(("user has empty password - access denied"));
			retval = PAM_AUTH_ERR;
		}
	} else if (!p || *hash == '*' || *hash == '!') {
		retval = PAM_AUTH_ERR;
	} else {
		if (!strncmp(hash, "$1$", 3)) {
			pp = Goodcrypt_md5(p, hash);
		    	if (pp && strcmp(pp, hash) != 0) {
				_pam_delete(pp);
				pp = Brokencrypt_md5(p, hash);
		    	}
		} else if (*hash != '$' && hash_len >= 13) {
		    	pp = bigcrypt(p, hash);
		    	if (pp && hash_len == 13 && strlen(pp) > hash_len) {
				_pam_overwrite(pp + hash_len);
		    	}
		} else {
                	/*
			 * Ok, we don't know the crypt algorithm, but maybe
			 * libcrypt nows about it? We should try it.
			 */
			pp = x_strdup(crypt(p, hash));
		}
		p = NULL;		/* no longer needed here */

		/* the moment of truth -- do we agree with the password? */
		D(("comparing state of pp[%s] and salt[%s]", pp, salt));

		if (pp && strcmp(pp, hash) == 0) {
			retval = PAM_SUCCESS;
		} else {
			retval = PAM_AUTH_ERR;
		}
	}
	
	if (pp)
		_pam_delete(pp);
	D(("done [%d].", retval));

	return retval;
}

int
is_pwd_shadowed(const struct passwd *pwd)
{
	if (pwd != NULL) {
		if (strcmp(pwd->pw_passwd, "x") == 0) {
			return 1;
		}
		if ((pwd->pw_passwd[0] == '#') &&
		    (pwd->pw_passwd[1] == '#') &&
		    (strcmp(pwd->pw_name, pwd->pw_passwd + 2) == 0)) {
			return 1;
		}
	}
	return 0;
}

#ifdef HELPER_COMPILE
int
get_pwd_hash(const char *name,
	struct passwd **pwd, char **hash)
#else
int
get_pwd_hash(pam_handle_t *pamh, const char *name,
	struct passwd **pwd, char **hash)
#endif
{
	struct spwd *spwdent = NULL;

	/* UNIX passwords area */
	*pwd = pam_modutil_getpwnam(pamh, name);	/* Get password file entry... */
	*hash = NULL;

	if (*pwd != NULL) {
		if (strcmp((*pwd)->pw_passwd, "*NP*") == 0)
		{ /* NIS+ */
#ifdef HELPER_COMPILE
			uid_t save_euid, save_uid;

			save_euid = geteuid();
			save_uid = getuid();
			if (save_uid == (*pwd)->pw_uid)
				setreuid(save_euid, save_uid);
			else  {
				setreuid(0, -1);
				if (setreuid(-1, (*pwd)->pw_uid) == -1) {
					setreuid(-1, 0);
					setreuid(0, -1);
					if(setreuid(-1, (*pwd)->pw_uid) == -1)
						return PAM_CRED_INSUFFICIENT;
				}
			}

			spwdent = pam_modutil_getspnam(pamh, name);
			if (save_uid == (*pwd)->pw_uid)
				setreuid(save_uid, save_euid);
			else {
				setreuid(-1, 0);
				setreuid(save_uid, -1);
				setreuid(-1, save_euid);
			}

			if (spwdent == NULL || spwdent->sp_pwdp == NULL)
				return PAM_AUTHINFO_UNAVAIL;
#else
			/* we must run helper for NIS+ passwords */
			return PAM_UNIX_RUN_HELPER;
#endif
		} else if (is_pwd_shadowed(*pwd)) {
			/*
			 * ...and shadow password file entry for this user,
			 * if shadowing is enabled
			 */
#ifndef HELPER_COMPILE
			if (geteuid() || SELINUX_ENABLED)
				return PAM_UNIX_RUN_HELPER;
#endif
			spwdent = pam_modutil_getspnam(pamh, name);
			if (spwdent == NULL || spwdent->sp_pwdp == NULL)
				return PAM_AUTHINFO_UNAVAIL;
		}
		if (spwdent)
			*hash = x_strdup(spwdent->sp_pwdp);
		else
			*hash = x_strdup((*pwd)->pw_passwd);
		if (*hash == NULL)
			return PAM_BUF_ERR;
	} else {
		return PAM_USER_UNKNOWN;
	}
	return PAM_SUCCESS;
}

#ifdef HELPER_COMPILE

int
helper_verify_password(const char *name, const char *p, int nullok)
{
	struct passwd *pwd = NULL;
	char *salt = NULL;
	int retval;

	retval = get_pwd_hash(name, &pwd, &salt);

	if (pwd == NULL || salt == NULL) {
		helper_log_err(LOG_WARNING, "check pass; user unknown");
		retval = PAM_USER_UNKNOWN;
	} else {
		retval = verify_pwd_hash(p, salt, nullok);
	}

	if (salt) {
		_pam_overwrite(salt);
		_pam_drop(salt);
	}

	p = NULL;		/* no longer needed here */

	return retval;
}

void
helper_log_err(int err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	openlog(HELPER_COMPILE, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

#endif
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
