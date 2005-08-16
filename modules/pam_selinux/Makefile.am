#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README ${MANS} pam_selinux_check.8

man_MANS = pam_selinux.8 

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-I$(top_srcdir)/libpam_misc/include \
	-I$(top_srcdir)/modules/pammodutil/include/
AM_LDFLAGS =  -avoid-version -module \
	-L$(top_builddir)/modules/pammodutil -lpammodutil \
	-L$(top_builddir)/libpam -lpam @LIBSELINUX@

pam_selinux_check_LDFLAGS  = -L$(top_builddir)/libpam_misc -lpam_misc

if HAVE_LIBSELINUX
  securelib_LTLIBRARIES = pam_selinux.la
  noinst_PROGRAMS = pam_selinux_check
endif
