#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README pam_env.conf

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/modules/pammodutil/include/ \
	-DDEFAULT_CONF_FILE=\"$(SCONFIGDIR)/pam_env.conf\"
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/modules/pammodutil -lpammodutil \
	-L$(top_builddir)/libpam -lpam
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=../modules.map
endif

securelib_LTLIBRARIES = pam_env.la

secureconf_DATA = pam_env.conf
