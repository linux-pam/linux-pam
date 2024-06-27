noinst_LTLIBRARIES = libpam_internal.la

noinst_HEADERS = include/pam_line.h include/pam_econf.h

AM_CFLAGS = -I$(top_srcdir)/libpam_internal/include \
	    -I$(top_srcdir)/libpam/include $(WARN_CFLAGS) \
	    $(ECONF_CFLAGS)

libpam_internal_la_SOURCES = \
	pam_debug.c \
	pam_line.c \
	pam_econf.c
