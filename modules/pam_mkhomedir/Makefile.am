#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@suse.de>
# Copyright (c) 2008 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) tst-pam_mkhomedir

man_MANS = pam_mkhomedir.8 mkhomedir_helper.8

XMLS = README.xml pam_mkhomedir.8.xml mkhomedir_helper.8.xml

TESTS = tst-pam_mkhomedir

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	    -DMKHOMEDIR_HELPER=\"$(sbindir)/mkhomedir_helper\"

securelib_LTLIBRARIES = pam_mkhomedir.la
pam_mkhomedir_la_SOURCES = pam_mkhomedir.c
pam_mkhomedir_la_LIBADD = $(top_builddir)/libpam/libpam.la
pam_mkhomedir_la_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  pam_mkhomedir_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

sbin_PROGRAMS = mkhomedir_helper
mkhomedir_helper_SOURCES = mkhomedir_helper.c
mkhomedir_helper_LDADD = $(top_builddir)/libpam/libpam.la

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_mkhomedir.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
