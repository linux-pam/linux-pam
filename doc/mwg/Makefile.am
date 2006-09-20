#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = Linux-PAM_MWG.fo *~

EXTRA_DIST = $(XMLS)

XMLS = Linux-PAM_MWG.xml $(shell ls $(srcdir)/pam_*.xml)
DEP_XMLS = $(shell ls $(top_srcdir)/doc/man/pam_*.xml)

if ENABLE_REGENERATE_MAN
MAINTAINERCLEANFILES = Linux-PAM_MWG.txt Linux-PAM_MWG.pdf html/*.html

all: Linux-PAM_MWG.txt html/Linux-PAM_MWG.html Linux-PAM_MWG.pdf

Linux-PAM_MWG.pdf: $(XMLS) $(DEP_XMLS)
if ENABLE_GENERATE_PDF
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl $< > Linux-PAM_MWG.fo
	$(FO2PDF) Linux-PAM_MWG.fo $@
else
	echo "No fo2pdf processor installed, skip PDF generation"
endif

Linux-PAM_MWG.txt: $(XMLS) $(DEP_XMLS)
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< | $(BROWSER) > $@

html/Linux-PAM_MWG.html: $(XMLS) $(DEP_XMLS)
	@test -d html || mkdir -p html
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam base.dir html/ \
	  --stringparam root.filename Linux-PAM_MWG \
	  --stringparam use.id.as.filename 1 \
	  --stringparam chunk.first.sections 1 \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<

distclean-local:
	-rm -rf html Linux-PAM_MWG.txt Linux-PAM_MWG.pdf

endif

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/txt
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/pdf
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/html
	test -f html/Linux-PAM_MWG.html || exit 0; \
	    $(install_sh_DATA) html/Linux-PAM_MWG.html html/mwg-*.html \
		$(DESTDIR)$(DOCDIR)/html/ || \
	    $(install_sh_DATA) $(srcdir)/html/Linux-PAM_MWG.html \
		$(srcdir)/html/sag-*.html \
		$(DESTDIR)$(DOCDIR)/html/
	test -f Linux-PAM_MWG.txt || exit 0; \
	    $(install_sh_DATA) Linux-PAM_MWG.txt $(DESTDIR)$(DOCDIR)/txt/ || \
	    $(install_sh_DATA) $(srcdir)/Linux-PAM_MWG.txt \
		$(DESTDIR)$(DOCDIR)/txt/
	test -f Linux-PAM_MWG.pdf || exit 0; \
	    $(install_sh_DATA) Linux-PAM_MWG.pdf $(DESTDIR)$(DOCDIR)/pdf/ || \
	    $(install_sh_DATA) $(srcdir)/Linux-PAM_MWG.pdf \
		$(DESTDIR)$(DOCDIR)/pdf/

uninstall-local:
	-rm $(DESTDIR)$(DOCDIR)/html/Linux-PAM_MWG.html
	-rm $(DESTDIR)$(DOCDIR)/html/mwg-*.html
	-rm $(DESTDIR)$(DOCDIR)/txt/Linux-PAM_MWG.txt
	-rm $(DESTDIR)$(DOCDIR)/pdf/Linux-PAM_MWG.pdf

releasedocs: all
	$(mkinstalldirs) $(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/html
	test -f html/Linux-PAM_MWG.html || exit 0; \
	    cp -ap html/Linux-PAM_MWG.html html/mwg-*.html \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/html/ || \
	    cp -ap $(srcdir)/html/Linux-PAM_MWG.html \
		$(srcdir)/html/mwg-*.html \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/html/
	test -f Linux-PAM_MWG.txt || exit 0; \
	    cp -p Linux-PAM_MWG.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/ || \
	    cp -p $(srcdir)/Linux-PAM_MWG.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/
	test -f Linux-PAM_MWG.pdf || exit 0; \
	    cp -p Linux-PAM_MWG.pdf \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/ || \
	    cp -p $(srcdir)/Linux-PAM_MWG.pdf \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/mwg/
