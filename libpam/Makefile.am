#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
#

AM_CFLAGS = -DDEFAULT_MODULE_PATH=\"$(SECUREDIR)/\" -DLIBPAM_COMPILE \
	-I$(srcdir)/include $(LIBPRELUDE_CFLAGS) -DPAM_VERSION=\"$(VERSION)\"
if HAVE_LIBSELINUX
  AM_CFLAGS += -D"WITH_SELINUX"
endif

CLEANFILES = *~

EXTRA_DIST = libpam.map

include_HEADERS = include/security/_pam_compat.h \
	include/security/_pam_macros.h include/security/_pam_types.h \
	include/security/pam_appl.h include/security/pam_modules.h \
	include/security/pam_ext.h include/security/pam_modutil.h

noinst_HEADERS = pam_prelude.h pam_private.h pam_tokens.h \
		pam_modutil_private.h pam_static_modules.h

libpam_la_LDFLAGS = -no-undefined -version-info 83:1:83
libpam_la_LIBADD = @LIBAUDIT@ $(LIBPRELUDE_LIBS) @LIBDL@

if STATIC_MODULES
  libpam_la_LIBADD += $(shell ls ../modules/pam_*/*.lo) \
	@LIBDB@ @LIBCRYPT@ $(NIS_LIBS) @LIBCRACK@ -lutil
  AM_CFLAGS += $(NIS_CFLAGS)
endif
if HAVE_VERSIONING
  libpam_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libpam.map
endif

lib_LTLIBRARIES = libpam.la

libpam_la_SOURCES = pam_account.c pam_auth.c pam_data.c pam_delay.c \
	pam_dispatch.c pam_end.c pam_env.c pam_get_authtok.c \
	pam_handlers.c pam_item.c \
	pam_misc.c pam_password.c pam_prelude.c \
	pam_session.c pam_start.c pam_static.c pam_strerror.c \
	pam_vprompt.c pam_syslog.c pam_dynamic.c pam_audit.c \
	pam_modutil_cleanup.c pam_modutil_getpwnam.c pam_modutil_ioloop.c \
	pam_modutil_getgrgid.c pam_modutil_getpwuid.c pam_modutil_getgrnam.c \
	pam_modutil_getspnam.c pam_modutil_getlogin.c pam_modutil_ingroup.c \
	pam_modutil_priv.c
