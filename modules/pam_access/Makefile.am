#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README access.conf $(MANS) $(XMLS) tst-pam_access

man_MANS = access.conf.5 pam_access.8

XMLS = README.xml access.conf.5.xml pam_access.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DPAM_ACCESS_CONFIG=\"$(SCONFIGDIR)/access.conf\" \
	-DACCESS_CONF_GLOB=\"$(SCONFIGDIR)/access.d/*.conf\"
AM_LDFLAGS =  -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_access.la
pam_access_la_LIBADD = $(top_builddir)/libpam/libpam.la

secureconf_DATA = access.conf

if ENABLE_REGENERATE_MAN

noinst_DATA = README

README: pam_access.8.xml access.conf.5.xml

-include $(top_srcdir)/Make.xml.rules
endif

TESTS = tst-pam_access
