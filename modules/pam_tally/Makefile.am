#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) tst-pam_tally

man_MANS = pam_tally.8
XMLS = README.xml pam_tally.8.xml

TESTS = tst-pam_tally

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = faillog.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include

pam_tally_la_LDFLAGS = -no-undefined -avoid-version -module
pam_tally_la_LIBADD = $(top_builddir)/libpam/libpam.la
if HAVE_VERSIONING
  pam_tally_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_tally.la
sbin_PROGRAMS = pam_tally

pam_tally_SOURCES = pam_tally_app.c

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_tally.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
