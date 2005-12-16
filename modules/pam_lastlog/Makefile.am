#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

EXTRADIST = README

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam -lutil
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_lastlog.la
