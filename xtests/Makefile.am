#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@suse.de>
#

AM_CFLAGS = -DLIBPAM_COMPILE -I$(top_srcdir)/libpam/include
AM_LDFLAGS = -L$(top_builddir)/libpam -lpam

CLEANFILES = *~

EXTRA_DIST = tst-pam_dispatch1.pamd tst-pam_dispatch2.pamd \
	tst-pam_dispatch3.pamd

XTESTS = tst-pam_dispatch1 tst-pam_dispatch2 tst-pam_dispatch3

noinst_PROGRAMS = $(XTESTS)

tst_pam_dispatch1_LDADD = -L$(top_builddir)/libpam -lpam -ldl -L$(top_builddir)/libpam_misc -lpam_misc
tst_pam_dispatch2_LDADD = -L$(top_builddir)/libpam -lpam -ldl -L$(top_builddir)/libpam_misc -lpam_misc
tst_pam_dispatch3_LDADD = -L$(top_builddir)/libpam -lpam -ldl -L$(top_builddir)/libpam_misc -lpam_misc

xtests: $(XTESTS)
	@failed=0; pass=0; all=0; \
	for testname in $(XTESTS) ; do \
	  install -m 644 $$testname.pamd /etc/pam.d/$$testname ; \
	  ./$$testname > /dev/null ; \
	  if test $$? -ne 0 ; then \
	    echo "FAIL: $$testname" ; \
	    failed=`expr $$failed + 1`; \
          else \
	    echo "PASS: $$testname" ; \
	    pass=`expr $$pass + 1`; \
          fi ; \
	  all=`expr $$all + 1` ; \
	  rm -f /etc/pam.d/$$testname ; \
	done ; \
	if test "$$failed" -ne 0; then \
	  echo "===================" ; \
	  echo "$$failed of $$all tests failed" ; \
	  echo "===================" ; \
	  exit 1 ; \
	else \
	  echo "==================" ; \
	  echo "All $$all tests passed" ; \
	  echo "==================" ; \
	fi
