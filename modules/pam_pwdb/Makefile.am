#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = TODO README md5.c md5_crypt.c bigcrypt.-c pam_unix_acct.-c \
	pam_unix_auth.-c pam_unix_md.-c pam_unix_passwd.-c \
	pam_unix_pwupd.-c pam_unix_sess.-c support.-c BUGS CHANGELOG

noinst_HEADERS = md5.h

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DCHKPWD_HELPER=\"$(sbindir)/$(CHKPWD)\"
AM_LDFLAGS = -no-undefined -avoid-version -module \
	-L$(top_builddir)/libpam -lpam @LIBCRYPT@ @LIBPWDB@
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

if HAVE_LIBPWDB
  securelib_LTLIBRARIES = pam_pwdb.la
  sbin_BINARIES = pwdb_chkpwd
endif

pam_pwdb_la_SOURCES = md5_good.c md5_broken.c pam_pwdb.c
pwdb_checkpwd = md5_good.c md5_broken.c pwdb_chkpwd.c
