#
# Copyright (c) 2006 Red Hat, Inc.
#

CLEANFILES = *~
MAN5 = namespace.conf.5
MAN8 = pam_namespace.8

XMLS = README.xml namespace.conf.5.xml pam_namespace.8.xml

if ENABLE_REGENERATE_MAN
noinst_DATA = README
-include $(top_srcdir)/Make.xml.rules
endif

EXTRA_DIST = README namespace.conf namespace.init $(MAN5) $(MAN8) $(XMLS) tst-pam_namespace

noinst_HEADERS = md5.h

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
        -DPAM_NAMESPACE_CONFIG=\"$(SCONFIGDIR)/namespace.conf\"
AM_LDFLAGS =  -no-undefined -avoid-version -module \
        -L$(top_builddir)/libpam -lpam @LIBSELINUX@
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

if HAVE_UNSHARE
securelib_LTLIBRARIES = pam_namespace.la
pam_namespace_la_SOURCES = pam_namespace.c pam_namespace.h md5.c md5.h

secureconf_DATA = namespace.conf
secureconf_SCRIPTS = namespace.init
TESTS = tst-pam_namespace
man_MANS = $(MAN5) $(MAN8)
endif
