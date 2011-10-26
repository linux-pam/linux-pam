#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = libpam_misc.map

include_HEADERS = include/security/pam_misc.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include \
	-I$(top_srcdir)/libpamc/include -I$(srcdir)/include

libpam_misc_la_LDFLAGS = -no-undefined -version-info 82:0:82
if HAVE_VERSIONING
  libpam_misc_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libpam_misc.map
endif
libpam_misc_la_LIBADD = $(top_builddir)/libpam/libpam.la

lib_LTLIBRARIES = libpam_misc.la

libpam_misc_la_SOURCES = help_env.c misc_conv.c
