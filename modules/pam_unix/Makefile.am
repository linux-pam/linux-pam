#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README md5.c md5_crypt.c lckpwdf.-c $(MANS) CHANGELOG

man_MANS = unix_chkpwd.8

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DCHKPWD_HELPER=\"$(sbindir)/unix_chkpwd\"

AM_LDFLAGS = -L$(top_builddir)/libpam -lpam @LIBCRYPT@ @LIBSELINUX@

if HAVE_LIBSELINUX
  AM_CFLAGS += -D"WITH_SELINUX"
endif
if HAVE_LIBCRACK
  AM_CFLAGS += -D"USE_CRACKLIB"
endif

pam_unix_la_LDFLAGS = -no-undefined -avoid-version -module \
	@LIBCRACK@ @LIBNSL@
if HAVE_VERSIONING
  pam_unix_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_unix.la

noinst_HEADERS = md5.h support.h yppasswd.h

sbin_PROGRAMS = unix_chkpwd

noinst_PROGRAMS = bigcrypt

pam_unix_la_SOURCES = bigcrypt.c pam_unix_acct.c \
	pam_unix_auth.c pam_unix_passwd.c pam_unix_sess.c support.c \
	yppasswd_xdr.c md5_good.c md5_broken.c

bigcrypt_SOURCES = bigcrypt.c bigcrypt_main.c
bigcrypt_CFLAGS = $(AM_CFLAGS)

unix_chkpwd_SOURCES = unix_chkpwd.c md5_good.c md5_broken.c bigcrypt.c
unix_chkpwd_CFLAGS = $(AM_CFLAGS) @PIE_CFLAGS@
unix_chkpwd_LDFLAGS = @PIE_LDFLAGS@
