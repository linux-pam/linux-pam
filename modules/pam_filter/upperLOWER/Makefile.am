#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

securelibfilterdir = $(SECUREDIR)/pam_filter


AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(srcdir)/.. @PIE_CFLAGS@
AM_LDFLAGS = @PIE_LDFLAGS@
LDADD = -L$(top_builddir)/libpam -lpam

securelibfilter_PROGRAMS = upperLOWER
