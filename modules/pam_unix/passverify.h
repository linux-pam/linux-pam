/*
 * Copyright information at end of file.
 */

#include <sys/types.h>
#include <pwd.h>
#include <security/pam_modules.h>

#define PAM_UNIX_RUN_HELPER PAM_CRED_INSUFFICIENT

#define MAXPASS		200	/* the maximum length of a password */

#define OLD_PASSWORDS_FILE      "/etc/security/opasswd"

int
verify_pwd_hash(const char *p, char *hash, unsigned int nullok);

int
is_pwd_shadowed(const struct passwd *pwd);

char *
crypt_md5_wrapper(const char *pass_new);

char *
create_password_hash(const char *password, unsigned int ctrl, int rounds);

int
unix_selinux_confined(void);

int
lock_pwdf(void);

void
unlock_pwdf(void);

int
save_old_password(const char *forwho, const char *oldpass,
		  int howmany);

#ifdef HELPER_COMPILE
void
helper_log_err(int err, const char *format,...);

int
helper_verify_password(const char *name, const char *p, int nullok);

void
setup_signals(void);

char *
getuidname(uid_t uid);

int
read_passwords(int fd, int npass, char **passwords);

int
get_account_info(const char *name,
	struct passwd **pwd, struct spwd **spwdent);

int
get_pwd_hash(const char *name,
	struct passwd **pwd, char **hash);

int
check_shadow_expiry(struct spwd *spent, int *daysleft);

int
unix_update_passwd(const char *forwho, const char *towhat);

int
unix_update_shadow(const char *forwho, char *towhat);
#else
int
get_account_info(pam_handle_t *pamh, const char *name,
	struct passwd **pwd,  struct spwd **spwdent);

int
get_pwd_hash(pam_handle_t *pamh, const char *name,
	struct passwd **pwd, char **hash);

int
check_shadow_expiry(pam_handle_t *pamh, struct spwd *spent, int *daysleft);

int
unix_update_passwd(pam_handle_t *pamh, const char *forwho, const char *towhat);

int
unix_update_shadow(pam_handle_t *pamh, const char *forwho, char *towhat);
#endif

/* ****************************************************************** *
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
