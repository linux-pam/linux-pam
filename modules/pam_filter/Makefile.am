#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

SUBDIRS = upperLOWER

CLEANFILES = *~

EXTRA_DIST = README

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

include_HEADERS=pam_filter.h

securelib_LTLIBRARIES = pam_filter.la
