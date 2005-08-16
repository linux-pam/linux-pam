#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

securelibfilterdir = $(SECUREDIR)/pam_filter


AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/modules/pammodutil/include/ -I..
AM_LDFLAGS = -L$(top_builddir)/modules/pammodutil -lpammodutil

securelibfilter_PROGRAMS = upperLOWER
