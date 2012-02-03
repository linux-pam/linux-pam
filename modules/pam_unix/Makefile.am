#
# Copyright (c) 2005, 2006, 2009, 2011 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

EXTRA_DIST = README md5.c md5_crypt.c lckpwdf.-c $(MANS) CHANGELOG \
		tst-pam_unix $(XMLS)

man_MANS = pam_unix.8 unix_chkpwd.8 unix_update.8
XMLS = README.xml pam_unix.8.xml unix_chkpwd.8.xml unix_update.8.xml

TESTS = tst-pam_unix

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include \
	-DCHKPWD_HELPER=\"$(sbindir)/unix_chkpwd\" \
	-DUPDATE_HELPER=\"$(sbindir)/unix_update\" \
	$(NIS_CFLAGS)

if HAVE_LIBSELINUX
  AM_CFLAGS += -D"WITH_SELINUX"
endif

pam_unix_la_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  pam_unix_la_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif
pam_unix_la_LIBADD = $(top_builddir)/libpam/libpam.la \
	@LIBCRYPT@ @LIBSELINUX@ $(NIS_LIBS)

securelib_LTLIBRARIES = pam_unix.la

noinst_HEADERS = md5.h support.h yppasswd.h bigcrypt.h passverify.h \
		 pam_unix_static.h

sbin_PROGRAMS = unix_chkpwd unix_update

noinst_PROGRAMS = bigcrypt

pam_unix_la_SOURCES = bigcrypt.c pam_unix_acct.c \
	pam_unix_auth.c pam_unix_passwd.c pam_unix_sess.c support.c \
	passverify.c yppasswd_xdr.c md5_good.c md5_broken.c
if STATIC_MODULES
pam_unix_la_SOURCES += pam_unix_static.c
endif

bigcrypt_SOURCES = bigcrypt.c bigcrypt_main.c
bigcrypt_CFLAGS = $(AM_CFLAGS)
bigcrypt_LDADD = @LIBCRYPT@

unix_chkpwd_SOURCES = unix_chkpwd.c md5_good.c md5_broken.c bigcrypt.c \
	passverify.c
unix_chkpwd_CFLAGS = $(AM_CFLAGS) @PIE_CFLAGS@ -DHELPER_COMPILE=\"unix_chkpwd\"
unix_chkpwd_LDFLAGS = @PIE_LDFLAGS@
unix_chkpwd_LDADD = @LIBCRYPT@ @LIBSELINUX@ @LIBAUDIT@

unix_update_SOURCES = unix_update.c md5_good.c md5_broken.c bigcrypt.c \
	passverify.c
unix_update_CFLAGS = $(AM_CFLAGS) @PIE_CFLAGS@ -DHELPER_COMPILE=\"unix_update\"
unix_update_LDFLAGS = @PIE_LDFLAGS@
unix_update_LDADD = @LIBCRYPT@ @LIBSELINUX@

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_unix.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
