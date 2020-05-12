#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2008 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = pam_tally2.8
endif
XMLS = README.xml pam_tally2.8.xml
dist_check_SCRIPTS = tst-pam_tally2
TESTS = $(dist_check_SCRIPTS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = tallylog.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)

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
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
