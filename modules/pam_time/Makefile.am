#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README time.conf

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/modules/pammodutil/include/ \
	-DPAM_TIME_CONF=\"$(SCONFIGDIR)/time.conf\"
AM_LDFLAGS =  -avoid-version -module \
	-L$(top_builddir)/modules/pammodutil -lpammodutil \
	-L$(top_builddir)/libpam -lpam

securelib_LTLIBRARIES = pam_time.la
secureconf_DATA = time.conf
