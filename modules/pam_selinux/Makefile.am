#
# Copyright (c) 2005, 2006, 2007 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) $(TESTS) pam_selinux_check.8

TESTS = tst-pam_selinux
if HAVE_DOC
man_MANS = pam_selinux.8
endif

XMLS = README.xml pam_selinux.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/libpam_misc/include $(WARN_CFLAGS)

pam_selinux_la_LDFLAGS = -no-undefined -avoid-version -module
pam_selinux_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBSELINUX@ @LIBAUDIT@
if HAVE_VERSIONING
  pam_selinux_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_selinux.la
noinst_PROGRAMS = pam_selinux_check
pam_selinux_check_LDADD = $(top_builddir)/libpam/libpam.la \
			  $(top_builddir)/libpam_misc/libpam_misc.la

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: $(XMLS)
-include $(top_srcdir)/Make.xml.rules
endif
