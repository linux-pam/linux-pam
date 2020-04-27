#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(XMLS) pam_userdb.8 create.pl tst-pam_userdb

if HAVE_DOC
man_MANS = pam_userdb.8
endif
TESTS = tst-pam_userdb

XMLS = README.xml pam_userdb.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module @LIBDB@ @LIBCRYPT@
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_userdb.la
pam_userdb_la_LIBADD = $(top_builddir)/libpam/libpam.la

noinst_HEADERS = pam_userdb.h

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_userdb.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
