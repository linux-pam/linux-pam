#
# Copyright (c) 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2006 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = $(XMLS)

if HAVE_DOC
dist_man_MANS = namespace.conf.5 pam_namespace.8 pam_namespace_helper.8
endif
XMLS = README.xml namespace.conf.5.xml pam_namespace.8.xml pam_namespace_helper.8.xml
dist_check_SCRIPTS = tst-pam_namespace
TESTS = $(dist_check_SCRIPTS)

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)
namespaceddir = $(SCONFIGDIR)/namespace.d
servicedir = $(prefix)/lib/systemd/system

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
        -DSECURECONF_DIR=\"$(SCONFIGDIR)/\" $(WARN_CFLAGS)
AM_LDFLAGS =  -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

noinst_HEADERS = md5.h pam_namespace.h argv_parse.h

securelib_LTLIBRARIES = pam_namespace.la
pam_namespace_la_SOURCES = pam_namespace.c md5.c argv_parse.c
pam_namespace_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBSELINUX@

dist_secureconf_DATA = namespace.conf
dist_secureconf_SCRIPTS = namespace.init
service_DATA = pam_namespace.service

install-data-local:
	mkdir -p $(DESTDIR)$(namespaceddir)

sbin_SCRIPTS = pam_namespace_helper

if ENABLE_REGENERATE_MAN
dist_noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif
