#
# Copyright (c) 2005, 2009 Thorsten Kukuk <kukuk@suse.de>
# Copyright (c) 2005, 2008 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = pam_timestamp.8 pam_timestamp_check.8
endif
XMLS = README.xml pam_timestamp.8.xml pam_timestamp_check.8.xml
dist_check_SCRIPTS = tst-pam_timestamp
TESTS = $(dist_check_SCRIPTS) $(check_PROGRAMS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = hmacsha1.h sha1.h hmac_openssl_wrapper.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	$(WARN_CFLAGS)

pam_timestamp_la_LDFLAGS = -no-undefined -avoid-version -module $(AM_LDFLAGS) $(CRYPTO_LIBS)
pam_timestamp_la_LIBADD = $(top_builddir)/libpam/libpam.la
if HAVE_VERSIONING
  pam_timestamp_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_timestamp.la
sbin_PROGRAMS = pam_timestamp_check

pam_timestamp_la_SOURCES = pam_timestamp.c
if COND_USE_OPENSSL
pam_timestamp_la_SOURCES += hmac_openssl_wrapper.c
else
pam_timestamp_la_SOURCES += hmacsha1.c sha1.c
endif
pam_timestamp_la_CFLAGS = $(AM_CFLAGS)

pam_timestamp_check_SOURCES = pam_timestamp_check.c
pam_timestamp_check_CFLAGS = $(AM_CFLAGS) @EXE_CFLAGS@
pam_timestamp_check_LDADD = $(top_builddir)/libpam/libpam.la
pam_timestamp_check_LDFLAGS = @EXE_LDFLAGS@

if COND_USE_OPENSSL
hmacfile_SOURCES = hmac_openssl_wrapper.c
else
hmacfile_SOURCES = hmacfile.c hmacsha1.c sha1.c
endif
hmacfile_LDADD = $(top_builddir)/libpam/libpam.la

check_PROGRAMS = hmacfile

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
