#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

noinst_HEADERS = faillog.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/modules/pammodutil/include/
AM_LDFLAGS = -L$(top_builddir)/modules/pammodutil -lpammodutil \
	-L$(top_builddir)/libpam -lpam

pam_tally_la_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  pam_tally_la_LDFLAGS += -Wl,--version-script=../modules.map
endif

securelib_LTLIBRARIES = pam_tally.la
sbin_PROGRAMS = pam_tally

pam_tally_SOURCES = pam_tally_app.c
