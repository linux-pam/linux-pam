#
# Copyright (c) 2006, 2009 David Howells <dhowells@redhat.com>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(XMLS) pam_keyinit.8 tst-pam_keyinit
XMLS = README.xml pam_keyinit.8.xml

if HAVE_KEY_MANAGEMENT
  man_MANS =  pam_keyinit.8
  TESTS = tst-pam_keyinit
endif

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_keyinit.8.xml
-include $(top_srcdir)/Make.xml.rules
endif

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

if HAVE_KEY_MANAGEMENT
  securelib_LTLIBRARIES = pam_keyinit.la
endif
pam_keyinit_la_LIBADD = $(top_builddir)/libpam/libpam.la
