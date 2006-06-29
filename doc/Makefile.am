#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

SUBDIRS = man specs sag adg mwg

CLEANFILES = *~

EXTRA_DIST = index.html

#######################################################

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/html
	install -m 644 $(srcdir)/index.html $(DESTDIR)$(DOCDIR)/html/

releasedocs: all
	$(mkinstalldirs) $(top_builddir)/Linux-PAM-$(VERSION)/doc/specs
	cp -av specs/draft-morgan-pam-current.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/specs/
	cp -av specs/rfc86.0.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/specs/
	make -C sag releasedocs
	make -C adg releasedocs
	make -C mwg releasedocs
	
