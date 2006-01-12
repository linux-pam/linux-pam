#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

AM_CFLAGS = -DDEFAULT_MODULE_PATH=\"$(SECUREDIR)/\" -DLIBPAM_COMPILE \
	-I$(srcdir)/include $(LIBPRELUDE_CFLAGS) -DPAM_VERSION=\"$(VERSION)\"
AM_LDFLAGS = $(LIBPRELUDE_LIBS) @LIBDL@

CLEANFILES = *~

EXTRA_DIST = libpam.map

include_HEADERS = $(addprefix include/security/, _pam_compat.h _pam_macros.h _pam_types.h \
	pam_appl.h pam_malloc.h pam_modules.h pam_ext.h pam_modutil.h)

noinst_HEADERS = pam_dynamic.h pam_prelude.h pam_private.h pam_tokens.h \
		pam_modutil_private.h

libpam_la_LDFLAGS = -no-undefined -version-info 81:2:81 @LIBAUDIT@
if HAVE_VERSIONING
  libpam_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libpam.map
endif

lib_LTLIBRARIES = libpam.la

libpam_la_SOURCES = pam_account.c pam_auth.c pam_data.c pam_delay.c \
	pam_dispatch.c pam_end.c pam_env.c pam_handlers.c pam_item.c \
	pam_malloc.c pam_misc.c pam_password.c pam_prelude.c \
	pam_session.c pam_start.c pam_static.c pam_strerror.c \
	pam_vprompt.c pam_syslog.c pam_dynamic.c pam_audit.c \
	pam_modutil_cleanup.c pam_modutil_getpwnam.c pam_modutil_ioloop.c \
	pam_modutil_getgrgid.c pam_modutil_getpwuid.c pam_modutil_getgrnam.c \
	pam_modutil_getspnam.c pam_modutil_getlogin.c  pam_modutil_ingroup.c
