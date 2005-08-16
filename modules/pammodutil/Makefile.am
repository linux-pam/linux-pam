#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

AM_CFLAGS = -I$(srcdir)/include -I$(top_srcdir)/libpam/include

noinst_HEADERS = pammodutil.h include/security/_pam_modutil.h

noinst_LIBRARIES = libpammodutil.a

libpammodutil_a_SOURCES = modutil_cleanup.c modutil_getgrgid.c \
	modutil_getgrnam.c modutil_getlogin.c modutil_getpwnam.c \
	modutil_getpwuid.c modutil_getspnam.c modutil_ingroup.c \
	modutil_ioloop.c
