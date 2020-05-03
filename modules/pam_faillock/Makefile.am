#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2008, 2018, 2020 Red Hat, Inc.
# Copyright (c) 2010 Tomas Mraz <tmraz@redhat.com>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = pam_faillock.8 faillock.8 faillock.conf.5
endif
XMLS = README.xml pam_faillock.8.xml faillock.8.xml faillock.conf.5.xml

dist_check_SCRIPTS = tst-pam_faillock
TESTS = $(dist_check_SCRIPTS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = faillock.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)

faillock_CFLAGS = $(AM_CFLAGS) @PIE_CFLAGS@

pam_faillock_la_LDFLAGS = -no-undefined -avoid-version -module
pam_faillock_la_LIBADD = $(top_builddir)/libpam/libpam.la $(LIBAUDIT)
if HAVE_VERSIONING
  pam_faillock_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

faillock_LDFLAGS = @PIE_LDFLAGS@
faillock_LDADD = $(top_builddir)/libpam/libpam.la $(LIBAUDIT)

dist_secureconf_DATA = faillock.conf

securelib_LTLIBRARIES = pam_faillock.la
sbin_PROGRAMS = faillock

pam_faillock_la_SOURCES = pam_faillock.c faillock.c
faillock_SOURCES = main.c faillock.c

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
