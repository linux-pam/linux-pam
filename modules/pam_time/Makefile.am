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
AM_LDFLAGS = -no-undefined -avoid-version -module \
	$(top_builddir)/modules/pammodutil/libpammodutil.la \
	-L$(top_builddir)/libpam -lpam
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=../modules.map
endif

securelib_LTLIBRARIES = pam_time.la
secureconf_DATA = time.conf
