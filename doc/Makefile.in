
### $Id$

TXTER=sgml2txt
HTMLER=sgml2html
# older distributions use, sgml2ps
# newer distributions than the one I use (AGM :^) need the following line:
#PSER=sgml2latex -o ps
# until I upgrade this is the default
PSER=sgml2latex -p

FILES=pam pam_appl pam_modules
FSRCS=pam.sgml pam_appl.sgml pam_modules.sgml

TEXTS=txts/pam.txt txts/pam_appl.txt txts/pam_modules.txt
HTMLS=html/pam.html html/pam_appl.html html/pam_modules.html
PSFILES=ps/pam.ps ps/pam_appl.ps ps/pam_modules.ps

MODULES=$(shell ls modules/*.sgml)

#######################################################

dummy:
	@echo "Making the documentation..."
	@make all

all: htmls texts postscript

htmls: $(HTMLS)

$(HTMLS) : $(FSRCS)
	@for i in $(FILES) ; do \
	if [ ! -f "html/$$i.html" ] || [ "$$i.sgml" -nt "html/$$i.html" ]; \
	then \
		cd html ; $(HTMLER) ../$$i ; \
		if [ $$? -ne 0 ]; then exit 1 ; fi ; \
		cd .. ; \
	fi ; \
	done

texts: $(TEXTS)

$(TEXTS) : $(FSRCS)
	@for i in $(FILES) ; do \
		if [ ! -f "txts/$$i.txt" ] \
				|| [ "$$i.sgml" -nt "txts/$$i.txt" ]; then \
			cd txts ; $(TXTER) ../$$i ; cd .. ; \
		fi ; \
	done

postscript: $(PSFILES)

$(PSFILES): $(FSRCS)
	@for i in $(FILES) ; do \
	if [ ! -f "ps/$$i.ps" ] || [ "$$i.sgml" -nt "ps/$$i.ps" ]; then \
		cd ps ; $(PSER) ../$$i ; cd .. ; \
	fi ; \
	done

pam.sgml: pam_source.sgml MODULES-SGML
	@sed -e '/^<!\-\- insert\-file MODULES\-SGML \-\->/r MODULES-SGML' pam_source.sgml > pam.sgml

MODULES-SGML: $(MODULES)
	@echo 'Building module text from files in modules/*.sgml'
	@rm -f MODULES-SGML
	@echo '<!-- modules included:' > MODULES-SGML
	@ls modules/*.sgml >> MODULES-SGML
	@echo '  and that is all -->' >> MODULES-SGML
	@cat modules/*.sgml >> MODULES-SGML

extraclean: clean

DOCDIR=/usr/doc/Linux-PAM
MANDIR=/usr/man
install: all
	mkdir -p $(FAKEROOT)$(DOCDIR)/{html,ps,text}
	for file in txts/*.txt; do \
	  install -o root -g root -m 644 $$file $(FAKEROOT)$(DOCDIR)/text ; \
	done
	for file in ps/*.ps; do \
	  install -o root -g root -m 644 $$file $(FAKEROOT)$(DOCDIR)/ps  ; \
	done
	for file in html/*.html; do \
	  install -o root -g root -m 644 $$file $(FAKEROOT)$(DOCDIR)/html ; \
	done
	mkdir -p $(FAKEROOT)$(MANDIR)/man{3,8}
	for file in man/*.3 ; do \
	  install -o root -g root -m 644 $$file $(FAKEROOT)$(MANDIR)/man3 ; \
	done
	for file in man/*.8 ; do \
	  install -o root -g root -m 644 $$file $(FAKEROOT)$(MANDIR)/man8 ; \
	done

clean:
	rm -f *~ *.bak
	rm -f html/pam*.html
	rm -f man/*~
	rm -f $(TEXTS)
	rm -f $(PSFILES)
	rm -f MODULES-SGML pam.sgml

