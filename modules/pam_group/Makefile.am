#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README group.conf $(MANS) $(XMLS) tst-pam_group

man_MANS = group.conf.5 pam_group.8
XMLS = README.xml group.conf.5.xml pam_group.8.xml

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DPAM_GROUP_CONF=\"$(SCONFIGDIR)/group.conf\"
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_group.la

secureconf_DATA = group.conf

TESTS = tst-pam_group

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_group.8.xml group.conf.5.xml
-include $(top_srcdir)/Make.xml.rules
endif

