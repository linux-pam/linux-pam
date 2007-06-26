#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@suse.de>
#

AM_CFLAGS = -DLIBPAM_COMPILE -I$(top_srcdir)/libpam/include \
	-I$(top_srcdir)/libpamc/include -I$(top_srcdir)/libpam_misc/include
AM_LDFLAGS = -L$(top_builddir)/libpam -lpam \
	-L$(top_builddir)/libpam_misc -lpam_misc

CLEANFILES = *~

EXTRA_DIST = run-xtests.sh tst-pam_dispatch1.pamd tst-pam_dispatch2.pamd \
	tst-pam_dispatch3.pamd tst-pam_dispatch4.pamd \
	tst-pam_cracklib1.pamd tst-pam_cracklib2.pamd \
	tst-pam_unix1.pamd tst-pam_unix2.pamd tst-pam_unix3.pamd \
	tst-pam_unix1.sh tst-pam_unix2.sh tst-pam_unix3.sh \
	access.conf tst-pam_access1.pamd tst-pam_access1.sh \
	tst-pam_access2.pamd tst-pam_access2.sh \
	tst-pam_access3.pamd tst-pam_access3.sh \
	tst-pam_access4.pamd tst-pam_access4.sh \
	limits.conf tst-pam_limits1.pamd tst-pam_limits1.sh

XTESTS = tst-pam_dispatch1 tst-pam_dispatch2 tst-pam_dispatch3 \
	tst-pam_dispatch4 tst-pam_cracklib1 tst-pam_cracklib2 \
	tst-pam_unix1 tst-pam_unix2 tst-pam_unix3 \
	tst-pam_access1 tst-pam_access2 tst-pam_access3 \
	tst-pam_access4 tst-pam_limits1

noinst_PROGRAMS = $(XTESTS)

xtests: $(XTESTS) run-xtests.sh
	"$(srcdir)"/run-xtests.sh "$(srcdir)" ${XTESTS}
