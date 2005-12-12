#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

SUBDIRS = specs

FILES=pam pam_appl pam_modules
FSRCS=$(srcdir)/pam_appl.sgml $(srcdir)/pam_modules.sgml

TEXTS=txts/pam.txt txts/pam_appl.txt txts/pam_modules.txt
HTMLS=html/pam.html html/pam_appl.html html/pam_modules.html
PSFILES=ps/pam.ps ps/pam_appl.ps ps/pam_modules.ps
PDFFILES=pdf/pam.pdf pdf/pam_appl.pdf pdf/pam_modules.pdf

MODULES=$(shell ls $(srcdir)/modules/*.sgml)

CLEANFILES = *~ */*~ $(TEXTS) $(PSFILES) $(PDFFILES) html/pam*.html \
	ps/missfont.log MODULES-SGML pam.sgml

EXTRA_DIST = $(FSRCS) CREDITS NOTES figs/pam_orient.txt pdf/README \
	ps/README html/index.html txts/README man/template-man $(MANS) \
	pam_source.sgml $(MODULES) modules/module.sgml-template \
	modules/README

man_MANS = $(addprefix man/, pam.8 pam.conf.5 pam.d.5 pam_authenticate.3 \
	pam_chauthtok.3 pam_close_session.3 pam_end.3 pam_fail_delay.3 \
	pam_get_item.3 pam_open_session.3 pam_set_item.3 pam_setcred.3 \
	pam_start.3 pam_strerror.3)

#######################################################

all: html text postscript pdf

html: $(HTMLS)

$(HTMLS) : $(FSRCS) $(srcdir)/pam.sgml
	@echo 'Building html documentation from files in modules/*.sgml'
if HAVE_SGML2HTML
	@for i in $(FILES) ; do \
	if [ ! -f "html/$$i.html" ] || [ "$(srcdir)/$$i.sgml" -nt "html/$$i.html" ]; \
	then \
		mkdir -p html ; \
		cd html ; sgml2html ../$(srcdir)/$$i ; \
		if [ $$? -ne 0 ]; then exit 1 ; fi ; \
		cd .. ; \
	fi ; \
	done
else
	@echo XXX - you do not have the sgml2html binary installed
endif

text: $(TEXTS)

$(TEXTS) : $(FSRCS) $(srcdir)/pam.sgml
	@echo 'Building text documentation from files in modules/*.sgml'
if HAVE_SGML2TXT
	@for i in $(FILES) ; do \
		if [ ! -f "txts/$$i.txt" ] \
				|| [ "$(srcdir)/$$i.sgml" -nt "txts/$$i.txt" ]; then \
			mkdir -p txts ; \
			cd txts ; sgml2txt ../$(srcdir)/$$i ; cd .. ; \
		fi ; \
	done
else
	@echo XXX - you do not have the sgml2txt binary installed
endif

postscript: $(PSFILES)

$(PSFILES): $(FSRCS) $(srcdir)/pam.sgml
	@echo 'Building postscript documentation from files in modules/*.sgml'
if HAVE_SGML2PS
	@for i in $(FILES) ; do \
	if [ ! -f "ps/$$i.ps" ] || [ "$(srcdir)/$$i.sgml" -nt "ps/$$i.ps" ]; then \
		mkdir -p ps ; \
		cd ps ; $(PSER) ../$(srcdir)/$$i ; cd .. ; \
	fi ; \
	done
else
	@echo XXX - neither sgml2ps nor sgml2latex binaries are installed
endif

pdf: $(PDFFILES)

$(PDFFILES) : $(PSFILES)
	@echo 'Building PDF documentation from files in modules/*.sgml'
if HAVE_SGML2PS
if HAVE_PS2PDF
	@for i in $(FILES) ; do \
	if [ ! -f "pdf/$$i.pdf" ] || [ "ps/$$i.ps" -nt "ps/$$i.pdf" ]; then \
		mkdir -p pdf ; \
		ps2pdf ps/$$i.ps pdf/$$i.pdf ; \
	fi ; \
	done
else
	@echo XXX - ps2pdf is not installed
endif
else
	@echo XXX - neither sgml2ps nor sgml2latex binaries are installed
endif

$(srcdir)/pam.sgml: $(srcdir)/pam_source.sgml MODULES-SGML CREDITS
	@sed -e '/^<!\-\- insert\-file MODULES\-SGML \-\->/r MODULES-SGML' $(srcdir)/pam_source.sgml |\
	  sed -e '/^<!\-\- insert\-file CREDITS \-\->/r CREDITS' > $(srcdir)/pam.sgml

MODULES-SGML: $(MODULES)
	@echo 'Building module text from files in modules/*.sgml'
	@rm -f MODULES-SGML
	@echo '<!-- modules included:' > MODULES-SGML
	@ls $(srcdir)/modules/*.sgml >> MODULES-SGML
	@echo '  and that is all -->' >> MODULES-SGML
	@cat $(srcdir)/modules/*.sgml >> MODULES-SGML

extraclean: clean

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)
if HAVE_SGML2TXT
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/text
	for file in txts/*.txt; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/text; \
	done
endif
if HAVE_SGML2PS
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/ps
	for file in ps/*.ps; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/ps; \
	done
if HAVE_PS2PDF
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/pdf
	for file in pdf/*.pdf; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/pdf; \
	done
endif
endif
if HAVE_SGML2HTML
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/html
	for file in html/*.html; do \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(DOCDIR)/html; \
	done
endif

releasedocs: all
	tar zvfc ../Linux-PAM-$(VERSION)-docs.tar.gz \
	--exclude CVS --exclude .cvsignore --exclude '.#*' \
	--exclude README html ps txts pdf \
	specs/draft-morgan-pam-current.txt specs/rfc86.0.txt
	tar jvfc ../Linux-PAM-$(VERSION)-docs.tar.bz2 \
	--exclude CVS --exclude .cvsignore --exclude '.#*' \
	--exclude README html ps txts pdf \
	specs/draft-morgan-pam-current.txt specs/rfc86.0.txt
