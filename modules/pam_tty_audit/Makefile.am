#
# Copyright (c) 2005, 2006, 2009, 2010 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README pam_tty_audit.8 $(XMLS) tst-pam_tty_audit

if HAVE_AUDIT_TTY_STATUS
  TESTS = tst-pam_tty_audit
  man_MANS = pam_tty_audit.8
endif
XMLS = README.xml pam_tty_audit.8.xml

securelibdir = $(SECUREDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

if HAVE_AUDIT_TTY_STATUS
  pam_tty_audit_la_LIBADD = $(top_builddir)/libpam/libpam.la
  securelib_LTLIBRARIES = pam_tty_audit.la
endif

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_tty_audit.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
