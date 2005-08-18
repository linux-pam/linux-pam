#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/modules/pammodutil/include/
if HAVE_LIBSELINUX
AM_CFLAGS += -DWITH_SELINUX
endif
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/modules/pammodutil -lpammodutil \
	-L$(top_builddir)/libpam -lpam @LIBSELINUX@
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=../modules.map
endif

securelib_LTLIBRARIES = pam_rootok.la
