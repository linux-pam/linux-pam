#
# Copyright (c) 2005, 2009 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = pam_env.conf.5 pam_env.8 environment.5
endif
XMLS = README.xml pam_env.conf.5.xml pam_env.8.xml
dist_check_SCRIPTS = tst-pam_env
TESTS = $(dist_check_SCRIPTS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DDEFAULT_CONF_FILE=\"$(SCONFIGDIR)/pam_env.conf\" $(WARN_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_env.la
pam_env_la_LIBADD = $(top_builddir)/libpam/libpam.la

dist_secureconf_DATA = pam_env.conf
dist_sysconf_DATA = environment

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
environment.5: pam_env.conf.5.xml
-include $(top_srcdir)/Make.xml.rules
endif
