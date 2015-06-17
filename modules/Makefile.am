#
# Copyright (c) 2005, 2006, 2008 Thorsten Kukuk <kukuk@thkukuk.de>
#

if COND_BUILD_PAM_RHOSTS
	MAYBE_PAM_RHOSTS = pam_rhosts
endif

if COND_BUILD_PAM_LASTLOG
	MAYBE_PAM_LASTLOG = pam_lastlog
endif

SUBDIRS := pam_access pam_cracklib pam_debug pam_deny pam_echo \
	pam_env pam_exec pam_faildelay pam_filter pam_ftp \
	pam_group pam_issue pam_keyinit pam_limits \
	pam_listfile pam_localuser pam_loginuid pam_mail \
	pam_mkhomedir pam_motd pam_namespace pam_nologin \
	pam_permit pam_pwhistory pam_rootok pam_securetty \
	pam_selinux pam_sepermit pam_shells pam_stress \
	pam_succeed_if pam_tally pam_tally2 pam_time pam_timestamp \
	pam_tty_audit pam_umask \
	pam_unix pam_userdb pam_warn pam_wheel pam_xauth \
	$(MAYBE_PAM_RHOSTS) $(MAYBE_PAM_LASTLOG)

CLEANFILES = *~

EXTRA_DIST = modules.map
