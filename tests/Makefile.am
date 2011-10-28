#
# Copyright (c) 2006, 2009 Thorsten Kukuk <kukuk@suse.de>
#

AM_CFLAGS = -DLIBPAM_COMPILE -I$(top_srcdir)/libpam/include \
		-I$(top_srcdir)/libpam
LDADD = $(top_builddir)/libpam/libpam.la

CLEANFILES = *~

TESTS = tst-pam_start tst-pam_end tst-pam_fail_delay tst-pam_open_session \
	tst-pam_close_session tst-pam_acct_mgmt tst-pam_authenticate \
	tst-pam_chauthtok tst-pam_setcred tst-pam_get_item tst-pam_set_item \
	tst-pam_getenvlist tst-pam_get_user tst-pam_set_data \
	tst-pam_mkargv

check_PROGRAMS = ${TESTS} tst-dlopen

tst_dlopen_LDADD = -ldl
