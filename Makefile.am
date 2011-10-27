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

EXTRA_DIST = config.rpath mkinstalldirs pgp.keys.asc CHANGELOG \
		Copyright Make.xml.rules

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
