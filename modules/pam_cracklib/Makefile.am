#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(XMLS) pam_cracklib.8 tst-pam_cracklib

if HAVE_LIBCRACK
  TESTS = tst-pam_cracklib
  man_MANS = pam_cracklib.8
endif

XMLS = README.xml pam_cracklib.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif
pam_cracklib_la_LIBADD = $(top_builddir)/libpam/libpam.la \
	@LIBCRACK@ @LIBCRYPT@
if HAVE_LIBCRACK
  securelib_LTLIBRARIES = pam_cracklib.la
endif

if ENABLE_REGENERATE_MAN
noinst_DATA = README pam_cracklib.8
README: pam_cracklib.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
