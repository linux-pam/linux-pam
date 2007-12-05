/*
 * Copyright information at end of file.
 */
#include "config.h"
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include "support.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "md5.h"
#include "bigcrypt.h"
#include "passverify.h"

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

int _unix_shadowed(const struct passwd *pwd)
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
