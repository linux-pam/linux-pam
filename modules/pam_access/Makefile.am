#
# Copyright (c) 2005, 2006, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(MANS) $(XMLS) $(TESTS)

if HAVE_DOC
man_MANS = access.conf.5 pam_access.8
endif
XMLS = README.xml access.conf.5.xml pam_access.8.xml
TESTS = tst-pam_access

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DPAM_ACCESS_CONFIG=\"$(SCONFIGDIR)/access.conf\" \
	-DACCESS_CONF_GLOB=\"$(SCONFIGDIR)/access.d/*.conf\" $(WARN_CFLAGS)
AM_LDFLAGS =  -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_access.la
pam_access_la_LIBADD = $(top_builddir)/libpam/libpam.la

dist_secureconf_DATA = access.conf

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
