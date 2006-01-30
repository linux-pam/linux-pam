#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

AUTOMAKE_OPTIONS = 1.9 gnu dist-bzip2 check-news

if STATIC_MODULES
SUBDIRS = modules libpam libpamc libpam_misc po conf doc examples
else
SUBDIRS = libpam libpamc libpam_misc modules po conf doc examples
endif

CLEANFILES = *~

M4_FILES = $(shell ls $(srcdir)/m4/*.m4)

EXTRA_DIST = config.rpath mkinstalldirs pgp.keys.asc CHANGELOG \
		Copyright $(M4_FILES) Make.xml.rules

ACLOCAL_AMFLAGS = -I m4

release: dist releasedocs

release-docs: releasedocs

releasedocs: 
	make -C doc releasedocs
