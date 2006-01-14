#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

AUTOMAKE_OPTIONS = 1.8 gnu dist-bzip2

SUBDIRS = libpam libpamc libpam_misc modules po conf doc examples

CLEANFILES = *~

M4_FILES = $(shell ls $(srcdir)/m4/*.m4)

EXTRA_DIST = config.rpath mkinstalldirs pgp.keys.asc CHANGELOG \
		Copyright $(M4_FILES)

ACLOCAL_AMFLAGS = -I m4

release: dist releasedocs

release-docs: releasedocs

releasedocs: 
	make -C doc releasedocs
