#
# Copyright (c) 2005, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README pam_env.conf $(MANS) $(XMLS) tst-pam_env environment

man_MANS = pam_env.conf.5 pam_env.8 environment.5

XMLS = README.xml pam_env.conf.5.xml pam_env.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DDEFAULT_CONF_FILE=\"$(SCONFIGDIR)/pam_env.conf\"
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_env.la
pam_env_la_LIBADD = $(top_builddir)/libpam/libpam.la

secureconf_DATA = pam_env.conf
sysconf_DATA = environment

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_env.8.xml pam_env.conf.5.xml
environment.5: pam_env.conf.5.xml
-include $(top_srcdir)/Make.xml.rules
endif

TESTS = tst-pam_env
