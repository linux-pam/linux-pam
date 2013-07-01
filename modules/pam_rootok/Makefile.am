#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) tst-pam_rootok

man_MANS = pam_rootok.8
XMLS = README.xml pam_rootok.8.xml

TESTS = tst-pam_rootok

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
if HAVE_LIBSELINUX
AM_CFLAGS += -DWITH_SELINUX
endif
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_rootok.la
pam_rootok_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBSELINUX@ @LIBAUDIT@

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_rootok.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
