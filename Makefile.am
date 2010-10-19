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

M4_FILES = m4/gettext.m4 m4/iconv.m4 m4/intlmacosx.m4 \
	m4/japhar_grep_cflags.m4 m4/jh_path_xml_catalog.m4 \
	m4/ld-as-needed.m4 m4/ld-no-undefined.m4 m4/ld-O1.m4 \
	m4/lib-ld.m4 m4/lib-link.m4 m4/lib-prefix.m4 \
	m4/libprelude.m4 m4/libtool.m4 m4/nls.m4 \
	m4/po.m4 m4/progtest.m4

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
