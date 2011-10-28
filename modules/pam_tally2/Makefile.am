#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2008 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) tst-pam_tally2

man_MANS = pam_tally2.8
XMLS = README.xml pam_tally2.8.xml

TESTS = tst-pam_tally2

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = tallylog.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include

pam_tally2_la_LDFLAGS = -no-undefined -avoid-version -module
pam_tally2_la_LIBADD = $(top_builddir)/libpam/libpam.la $(LIBAUDIT)
if HAVE_VERSIONING
  pam_tally2_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

pam_tally2_LDADD = $(top_builddir)/libpam/libpam.la $(LIBAUDIT)

securelib_LTLIBRARIES = pam_tally2.la
sbin_PROGRAMS = pam_tally2

pam_tally2_la_SOURCES = pam_tally2.c
pam_tally2_SOURCES = pam_tally2_app.c

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_tally2.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
