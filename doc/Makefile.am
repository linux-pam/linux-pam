#
# Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
#

SUBDIRS = man specs sag adg mwg

CLEANFILES = *~

EXTRA_DIST = pdf/README html/index.html txts/README

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
	tar zvfc ../Linux-PAM-$(VERSION)-docs.tar.gz \
	--exclude CVS --exclude .cvsignore --exclude '.#*' \
	--exclude README html txts pdf \
	specs/draft-morgan-pam-current.txt specs/rfc86.0.txt
	tar jvfc ../Linux-PAM-$(VERSION)-docs.tar.bz2 \
	--exclude CVS --exclude .cvsignore --exclude '.#*' \
	--exclude README html ps txts pdf \
	specs/draft-morgan-pam-current.txt specs/rfc86.0.txt
