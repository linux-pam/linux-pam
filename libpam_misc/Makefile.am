#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = libpam_misc.map

include_HEADERS = include/security/pam_misc.h

AM_CFLAGS = -I$(top_srcdir)/libpam/include \
	-I$(top_srcdir)/libpamc/include -I$(srcdir)/include

libpam_misc_la_LDFLAGS = -version-info 1:0:0
if HAVE_VERSIONING
  libpam_misc_la_LDFLAGS += -Wl,--version-script=libpam_misc.map
endif

lib_LTLIBRARIES = libpam_misc.la

libpam_misc_la_SOURCES = help_env.c misc_conv.c

