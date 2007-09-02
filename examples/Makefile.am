#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/libpam_misc/include
LDADD = -L$(top_builddir)/libpam -lpam \
	-L$(top_builddir)/libpam_misc -lpam_misc

noinst_PROGRAMS = xsh vpass blank check_user
