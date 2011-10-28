#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(MANS) $(XMLS) time.conf tst-pam_time

man_MANS = time.conf.5 pam_time.8
XMLS = README.xml time.conf.5.xml pam_time.8.xml

TESTS = tst-pam_time

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DPAM_TIME_CONF=\"$(SCONFIGDIR)/time.conf\"
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif
pam_time_la_LIBADD = $(top_builddir)/libpam/libpam.la

securelib_LTLIBRARIES = pam_time.la
secureconf_DATA = time.conf

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_time.8.xml time.conf.5.xml
-include $(top_srcdir)/Make.xml.rules
endif
