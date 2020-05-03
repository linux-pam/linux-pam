#
# Copyright (c) 2008, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = pam_pwhistory.8
endif
XMLS = README.xml pam_pwhistory.8.xml
dist_check_SCRIPTS = tst-pam_pwhistory
TESTS = $(dist_check_SCRIPTS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

noinst_HEADERS = opasswd.h

securelib_LTLIBRARIES = pam_pwhistory.la
pam_pwhistory_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBCRYPT@
pam_pwhistory_la_SOURCES = pam_pwhistory.c opasswd.c

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
