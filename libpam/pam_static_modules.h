/*
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

/* Pointers to static module data.  */

extern struct pam_module _pam_access_modstruct;
extern struct pam_module _pam_cracklib_modstruct;
extern struct pam_module _pam_debug_modstruct;
extern struct pam_module _pam_deny_modstruct;
extern struct pam_module _pam_echo_modstruct;
extern struct pam_module _pam_env_modstruct;
extern struct pam_module _pam_exec_modstruct;
extern struct pam_module _pam_faildelay_modstruct;
extern struct pam_module _pam_filter_modstruct;
extern struct pam_module _pam_ftp_modstruct;
extern struct pam_module _pam_group_modstruct;
extern struct pam_module _pam_issue_modstruct;
#ifdef HAVE_KEY_MANAGEMENT
extern struct pam_module _pam_keyinit_modstruct;
#endif
extern struct pam_module _pam_lastlog_modstruct;
extern struct pam_module _pam_limits_modstruct;
extern struct pam_module _pam_listfile_modstruct;
extern struct pam_module _pam_localuser_modstruct;
extern struct pam_module _pam_loginuid_modstruct;
extern struct pam_module _pam_mail_modstruct;
extern struct pam_module _pam_mkhomedir_modstruct;
extern struct pam_module _pam_motd_modstruct;
#ifdef HAVE_UNSHARE
extern struct pam_module _pam_namespace_modstruct;
#endif
extern struct pam_module _pam_nologin_modstruct;
extern struct pam_module _pam_permit_modstruct;
extern struct pam_module _pam_pwhistory_modstruct;
extern struct pam_module _pam_rhosts_modstruct;
extern struct pam_module _pam_rootok_modstruct;
extern struct pam_module _pam_securetty_modstruct;
#ifdef WITH_SELINUX
extern struct pam_module _pam_selinux_modstruct;
extern struct pam_module _pam_sepermit_modstruct;
#endif
extern struct pam_module _pam_shells_modstruct;
extern struct pam_module _pam_stress_modstruct;
extern struct pam_module _pam_succeed_if_modstruct;
extern struct pam_module _pam_tally_modstruct;
extern struct pam_module _pam_tally2_modstruct;
extern struct pam_module _pam_time_modstruct;
extern struct pam_module _pam_timestamp_modstruct;
#ifdef HAVE_AUDIT_TTY_STATUS
extern struct pam_module _pam_tty_audit_modstruct;
#endif
extern struct pam_module _pam_umask_modstruct;
extern struct pam_module _pam_unix_modstruct;
extern struct pam_module _pam_userdb_modstruct;
extern struct pam_module _pam_warn_modstruct;
extern struct pam_module _pam_wheel_modstruct;
extern struct pam_module _pam_xauth_modstruct;

/* and here is a structure that connects libpam to the above static
   modules.  */

static struct pam_module *static_modules[] = {
  &_pam_access_modstruct,
#ifdef HAVE_LIBCRACK
  &_pam_cracklib_modstruct,
#endif
  &_pam_debug_modstruct,
  &_pam_deny_modstruct,
  &_pam_echo_modstruct,
  &_pam_env_modstruct,
  &_pam_exec_modstruct,
  &_pam_faildelay_modstruct,
  &_pam_filter_modstruct,
  &_pam_ftp_modstruct,
  &_pam_group_modstruct,
  &_pam_issue_modstruct,
#ifdef HAVE_KEY_MANAGEMENT
  &_pam_keyinit_modstruct,
#endif
  &_pam_lastlog_modstruct,
  &_pam_limits_modstruct,
  &_pam_listfile_modstruct,
  &_pam_localuser_modstruct,
  &_pam_loginuid_modstruct,
  &_pam_mail_modstruct,
  &_pam_mkhomedir_modstruct,
  &_pam_motd_modstruct,
#ifdef HAVE_UNSHARE
  &_pam_namespace_modstruct,
#endif
  &_pam_nologin_modstruct,
  &_pam_permit_modstruct,
  &_pam_pwhistory_modstruct,
  &_pam_rhosts_modstruct,
  &_pam_rootok_modstruct,
  &_pam_securetty_modstruct,
#ifdef WITH_SELINUX
  &_pam_selinux_modstruct,
  &_pam_sepermit_modstruct,
#endif
  &_pam_shells_modstruct,
  &_pam_stress_modstruct,
  &_pam_succeed_if_modstruct,
  &_pam_tally_modstruct,
  &_pam_tally2_modstruct,
  &_pam_time_modstruct,
  &_pam_timestamp_modstruct,
#ifdef HAVE_AUDIT_TTY_STATUS
  &_pam_tty_audit_modstruct,
#endif
  &_pam_umask_modstruct,
  &_pam_unix_modstruct,
  &_pam_userdb_modstruct,
  &_pam_warn_modstruct,
  &_pam_wheel_modstruct,
  &_pam_xauth_modstruct,
  NULL
};
