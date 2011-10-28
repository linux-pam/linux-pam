#
# Copyright (c) 2005, 2006, 2007 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(XMLS) pam_selinux.8 pam_selinux_check.8 \
		tst-pam_selinux

if HAVE_LIBSELINUX
  TESTS = tst-pam_selinux
  man_MANS = pam_selinux.8
endif

XMLS = README.xml pam_selinux.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/libpam_misc/include

pam_selinux_la_LDFLAGS = -no-undefined -avoid-version -module
pam_selinux_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBSELINUX@ @LIBAUDIT@
if HAVE_VERSIONING
  pam_selinux_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

if HAVE_LIBSELINUX
  securelib_LTLIBRARIES = pam_selinux.la
  noinst_PROGRAMS = pam_selinux_check
  pam_selinux_check_LDADD = $(top_builddir)/libpam/libpam.la \
			    $(top_builddir)/libpam_misc/libpam_misc.la
endif
if ENABLE_REGENERATE_MAN
noinst_DATA = README pam_selinux.8
README: pam_selinux.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
