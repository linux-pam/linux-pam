#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2008, 2018 Red Hat, Inc.
# Copyright (c) 2010 Tomas Mraz <tmraz@redhat.com>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) faillock.conf tst-pam_faillock

man_MANS = pam_faillock.8 faillock.8 faillock.conf.5
XMLS = README.xml pam_faillock.8.xml faillock.8.xml faillock.conf.5.xml

TESTS = tst-pam_faillock

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = faillock.h

faillock_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include @PIE_CFLAGS@
pam_faillock_la_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include

pam_faillock_la_LDFLAGS = -no-undefined -avoid-version -module
pam_faillock_la_LIBADD = -L$(top_builddir)/libpam -lpam $(LIBAUDIT)
if HAVE_VERSIONING
  pam_faillock_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

faillock_LDFLAGS = -Wl,-z,now @PIE_LDFLAGS@
faillock_LDADD = -L$(top_builddir)/libpam -lpam $(LIBAUDIT)

secureconf_DATA = faillock.conf

securelib_LTLIBRARIES = pam_faillock.la
sbin_PROGRAMS = faillock

pam_faillock_la_SOURCES = pam_faillock.c faillock.c
faillock_SOURCES = main.c faillock.c

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_faillock.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
