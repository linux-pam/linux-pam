#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

SUBDIRS = man specs sag adg mwg

CLEANFILES = *~

EXTRA_DIST = index.html

#######################################################

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/text
	for file in txts/*.txt; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/text; \
	done
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/pdf
	for file in pdf/*.pdf; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/pdf; \
	done
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/html
	for file in html/*.html; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/html; \
	done

releasedocs: all
	mkdir -p $(top_builddir)/Linux-PAM-$(VERSION)-docs/html
	mkdir -p $(top_builddir)/Linux-PAM-$(VERSION)-docs/pdf
	mkdir -p $(top_builddir)/Linux-PAM-$(VERSION)-docs/txt
	mkdir -p $(top_builddir)/Linux-PAM-$(VERSION)-docs/specs
	cp -av $(srcdir)/index.html \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/html/
	cp -av specs/draft-morgan-pam-current.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/specs/
	cp -av specs/rfc86.0.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/specs/
	make -C sag releasedocs
	make -C adg releasedocs
	make -C mwg releasedocs
	
