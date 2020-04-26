#
# Copyright (c) 2005, 2006, 2008 Thorsten Kukuk <kukuk@thkukuk.de>
#

if COND_BUILD_PAM_LASTLOG
 MAYBE_PAM_LASTLOG = pam_lastlog
endif

if COND_BUILD_PAM_RHOSTS
 MAYBE_PAM_RHOSTS = pam_rhosts
endif

if COND_BUILD_PAM_SETQUOTA
 MAYBE_PAM_SETQUOTA = pam_setquota
endif

if COND_BUILD_PAM_TTY_AUDIT
 MAYBE_PAM_TTY_AUDIT = pam_tty_audit
endif

SUBDIRS := \
	pam_access \
	pam_cracklib \
	pam_debug \
	pam_deny \
	pam_echo \
	pam_env \
	pam_exec \
	pam_faildelay \
	pam_filter \
	pam_ftp \
	pam_group \
	pam_issue \
	pam_keyinit \
	$(MAYBE_PAM_LASTLOG) \
	pam_limits \
	pam_listfile \
	pam_localuser \
	pam_loginuid \
	pam_mail \
	pam_mkhomedir \
	pam_motd \
	pam_namespace \
	pam_nologin \
	pam_permit \
	pam_pwhistory \
	$(MAYBE_PAM_RHOSTS) \
	pam_rootok \
	pam_securetty \
	pam_selinux \
	pam_sepermit \
	$(MAYBE_PAM_SETQUOTA) \
	pam_shells \
	pam_stress \
	pam_succeed_if \
	pam_tally \
	pam_tally2 \
	pam_time \
	pam_timestamp \
	$(MAYBE_PAM_TTY_AUDIT) \
	pam_umask \
	pam_unix \
	pam_userdb \
	pam_usertype \
	pam_warn \
	pam_wheel \
	pam_xauth \
	#

CLEANFILES = *~

EXTRA_DIST = modules.map
