#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

AM_CFLAGS = -DDEFAULT_MODULE_PATH=\"$(SECUREDIR)/\" \
	-I$(srcdir)/include $(LIBPRELUDE_CFLAGS) -DPAM_VERSION=\"$(VERSION)\"
AM_LDFLAGS = $(LIBPRELUDE_LIBS) @LIBDL@

CLEANFILES = *~

EXTRA_DIST = libpam.map

include_HEADERS = $(addprefix include/security/, _pam_compat.h _pam_macros.h _pam_types.h pam_appl.h pam_malloc.h pam_modules.h)

noinst_HEADERS = pam_prelude.h pam_private.h pam_tokens.h

libpam_la_LDFLAGS = -no-undefined -version-info 81:0:81
if HAVE_VERSIONING
  libpam_la_LDFLAGS += -Wl,--version-script=libpam.map
endif

lib_LTLIBRARIES = libpam.la

libpam_la_SOURCES = pam_account.c pam_auth.c pam_data.c pam_delay.c \
	pam_dispatch.c pam_end.c pam_env.c pam_handlers.c pam_item.c \
	pam_log.c pam_malloc.c pam_misc.c pam_password.c \
	pam_prelude.c pam_session.c pam_start.c pam_static.c pam_strerror.c
