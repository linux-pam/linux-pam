#
# Copyright (c) 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2006 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

if HAVE_DOC
man_MANS = namespace.conf.5 pam_namespace.8 pam_namespace_helper.8
endif

EXTRA_DIST = README namespace.conf namespace.init $(MANS) $(XMLS) $(TESTS)

TESTS = tst-pam_namespace

XMLS = README.xml namespace.conf.5.xml pam_namespace.8.xml pam_namespace_helper.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)
namespaceddir = $(SCONFIGDIR)/namespace.d
servicedir = $(prefix)/lib/systemd

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

secureconf_DATA = namespace.conf
secureconf_SCRIPTS = namespace.init

install-data-local:
	mkdir -p $(DESTDIR)$(namespaceddir)
	mkdir -p $(DESTDIR)$(servicedir)
	$(INSTALL_DATA) pam_namespace.service $(DESTDIR)$(servicedir)

sbin_SCRIPTS = pam_namespace_helper

uninstall-local:
	-rm $(DESTDIR)$(servicedir)/pam_namespace.service


if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_namespace.8.xml namespace.conf.5.xml pam_namespace_helper.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
