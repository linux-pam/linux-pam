#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README tst-pam_stress

TESTS = tst-pam_stress

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif
securelib_LTLIBRARIES = pam_stress.la
pam_stress_la_LIBADD = $(top_builddir)/libpam/libpam.la
