#
# Copyright (c) 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2006 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MAN5) $(MAN8) README

MAN5 = namespace.conf.5
MAN8 = pam_namespace.8

EXTRA_DIST = README namespace.conf namespace.init $(MAN5) $(MAN8) $(XMLS) tst-pam_namespace

if HAVE_UNSHARE
  TESTS = tst-pam_namespace
  man_MANS = $(MAN5) $(MAN8)
endif

XMLS = README.xml namespace.conf.5.xml pam_namespace.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)
namespaceddir = $(SCONFIGDIR)/namespace.d

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
        -DSECURECONF_DIR=\"$(SCONFIGDIR)/\"
AM_LDFLAGS =  -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

noinst_HEADERS = md5.h pam_namespace.h argv_parse.h

if HAVE_UNSHARE
  securelib_LTLIBRARIES = pam_namespace.la
  pam_namespace_la_SOURCES = pam_namespace.c md5.c argv_parse.c
  pam_namespace_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBSELINUX@

  secureconf_DATA = namespace.conf
  secureconf_SCRIPTS = namespace.init

install-data-local:
	mkdir -p $(DESTDIR)$(namespaceddir)
endif


if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_namespace.8.xml namespace.conf.5.xml
-include $(top_srcdir)/Make.xml.rules
endif
