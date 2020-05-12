#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = pam_tally.8
endif
XMLS = README.xml pam_tally.8.xml
dist_check_SCRIPTS = tst-pam_tally
TESTS = $(dist_check_SCRIPTS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = faillog.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)

pam_tally_la_LDFLAGS = -no-undefined -avoid-version -module
pam_tally_la_LIBADD = $(top_builddir)/libpam/libpam.la
if HAVE_VERSIONING
  pam_tally_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_tally.la
sbin_PROGRAMS = pam_tally

pam_tally_SOURCES = pam_tally_app.c

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
