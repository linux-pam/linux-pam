#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README $(MANS) $(XMLS) create.pl tst-pam_userdb

man_MANS = pam_userdb.8
XMLS = README.xml pam_userdb.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam @LIBDB@ @LIBCRYPT@
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

if HAVE_LIBDB
  securelib_LTLIBRARIES = pam_userdb.la
  TESTS = tst-pam_userdb
endif

noinst_HEADERS = pam_userdb.h

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_userdb.8.xml
-include $(top_srcdir)/Make.xml.rules
endif

