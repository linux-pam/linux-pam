#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

SUBDIRS = upperLOWER

CLEANFILES = *~

EXTRA_DIST = README $(MANS) $(XMLS) tst-pam_filter

man_MANS = pam_filter.8
XMLS = README.xml pam_filter.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

include_HEADERS=pam_filter.h

securelib_LTLIBRARIES = pam_filter.la
TESTS = tst-pam_filter

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_filter.8.xml
-include $(top_srcdir)/Make.xml.rules
endif

