#
# Copyright (c) 2005, 2006, 2007 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2008, 2009 Red Hat, Inc.
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README $(XMLS) pam_sepermit.8 sepermit.conf sepermit.conf.5 tst-pam_sepermit

TESTS = tst-pam_sepermit
if HAVE_DOC
man_MANS = pam_sepermit.8 sepermit.conf.5
endif

XMLS = README.xml pam_sepermit.8.xml sepermit.conf.5.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)
sepermitlockdir = ${localstatedir}/run/sepermit

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/libpam_misc/include \
	-D SEPERMIT_CONF_FILE=\"$(SCONFIGDIR)/sepermit.conf\" \
	-D SEPERMIT_LOCKDIR=\"$(sepermitlockdir)\" $(WARN_CFLAGS)

pam_sepermit_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBSELINUX@
pam_sepermit_la_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  pam_sepermit_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

secureconf_DATA = sepermit.conf
securelib_LTLIBRARIES = pam_sepermit.la

install-data-local:
	mkdir -p $(DESTDIR)$(sepermitlockdir)

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_sepermit.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
