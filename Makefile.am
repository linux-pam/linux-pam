#
# Copyright (c) 2005, 2006, 2007 Thorsten Kukuk <kukuk@thkukuk.de>
#

AUTOMAKE_OPTIONS = 1.9 gnu dist-bzip2 check-news

if STATIC_MODULES
SUBDIRS = modules libpam libpamc libpam_misc tests po conf doc examples xtests
else
SUBDIRS = libpam tests libpamc libpam_misc modules po conf doc examples xtests
endif

CLEANFILES = *~

M4_FILES = m4/codeset.m4 m4/gettext.m4 m4/glibc21.m4 m4/glibc2.m4 \
	m4/iconv.m4 m4/intdiv0.m4 m4/intmax.m4 m4/inttypes_h.m4 \
	m4/inttypes-h.m4 m4/inttypes.m4 m4/inttypes-pri.m4 \
	m4/isc-posix.m4 m4/jh_path_xml_catalog.m4 m4/lcmessage.m4 \
	m4/ld-as-needed.m4 m4/ld-O1.m4 m4/lib-ld.m4 m4/lib-link.m4 \
	m4/lib-prefix.m4 m4/libprelude.m4 m4/lock.m4 m4/longdouble.m4 \
	m4/longlong.m4 m4/nls.m4 m4/po.m4 m4/printf-posix.m4 \
	m4/progtest.m4 m4/signed.m4 m4/size_max.m4 m4/stdint_h.m4 \
	m4/uintmax_t.m4 m4/ulonglong.m4 m4/visibility.m4 \
	m4/wchar_t.m4 m4/wint_t.m4 m4/xsize.m4

EXTRA_DIST = config.rpath mkinstalldirs pgp.keys.asc CHANGELOG \
		Copyright $(M4_FILES) Make.xml.rules

ACLOCAL_AMFLAGS = -I m4

release: dist releasedocs

release-docs: releasedocs

releasedocs:
	rm -rf Linux-PAM-$(VERSION)
	mkdir -p Linux-PAM-$(VERSION)/doc
	make -C doc releasedocs
	tar zfc Linux-PAM-$(VERSION)-docs.tar.gz \
		Linux-PAM-$(VERSION)/doc
	tar jfc Linux-PAM-$(VERSION)-docs.tar.bz2 \
		Linux-PAM-$(VERSION)/doc
	rm -rf Linux-PAM-$(VERSION)

xtests:
	make -C xtests xtests

.PHONY: xtests
