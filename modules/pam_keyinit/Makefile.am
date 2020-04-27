#
# Copyright (c) 2006, 2009 David Howells <dhowells@redhat.com>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(DATA) $(MANS) $(XMLS) $(TESTS)

if HAVE_DOC
man_MANS =  pam_keyinit.8
endif
XMLS = README.xml pam_keyinit.8.xml
TESTS = tst-pam_keyinit

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_keyinit.la
pam_keyinit_la_LIBADD = $(top_builddir)/libpam/libpam.la

if ENABLE_REGENERATE_MAN
noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
