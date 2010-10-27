#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = Linux-PAM_ADG.fo *~

EXTRA_DIST = $(XMLS)

XMLS = Linux-PAM_ADG.xml $(shell ls $(srcdir)/pam_*.xml)
DEP_XMLS = $(shell ls $(top_srcdir)/doc/man/pam_*.xml)

if ENABLE_REGENERATE_MAN
MAINTAINERCLEANFILES = Linux-PAM_ADG.txt Linux-PAM_ADG.pdf html/*.html

all: Linux-PAM_ADG.txt html/Linux-PAM_ADG.html Linux-PAM_ADG.pdf

Linux-PAM_ADG.pdf: $(XMLS) $(DEP_XMLS)
if ENABLE_GENERATE_PDF
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl $< > Linux-PAM_ADG.fo
	$(FO2PDF) Linux-PAM_ADG.fo $@
else
	echo "No fo2pdf processor installed, skip PDF generation"
endif

Linux-PAM_ADG.txt: $(XMLS) $(DEP_XMLS)
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< | $(BROWSER) > $@

html/Linux-PAM_ADG.html: $(XMLS) $(DEP_XMLS)
	@test -d html || mkdir -p html
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam base.dir html/ \
	  --stringparam root.filename Linux-PAM_ADG \
	  --stringparam use.id.as.filename 1 \
	  --stringparam chunk.first.sections 1 \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  --stringparam chunker.output.encoding UTF-8 \
	  http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<

distclean-local:
	-rm -rf html Linux-PAM_ADG.txt Linux-PAM_ADG.pdf

endif

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(docdir)
	$(mkinstalldirs) $(DESTDIR)$(pdfdir)
	$(mkinstalldirs) $(DESTDIR)$(htmldir)
	test -f html/Linux-PAM_ADG.html || exit 0; \
	    $(install_sh_DATA) html/Linux-PAM_ADG.html html/adg-*.html \
		$(DESTDIR)$(htmldir)/ || \
	    $(install_sh_DATA) $(srcdir)/html/Linux-PAM_ADG.html \
		$(srcdir)/html/sag-*.html \
		$(DESTDIR)$(htmldir)/
	test -f Linux-PAM_ADG.txt || exit 0; \
	    $(install_sh_DATA) Linux-PAM_ADG.txt $(DESTDIR)$(docdir)/ || \
	    $(install_sh_DATA) $(srcdir)/Linux-PAM_ADG.txt \
		$(DESTDIR)$(docdir)/
	test -f Linux-PAM_ADG.pdf || exit 0; \
	    $(install_sh_DATA) Linux-PAM_ADG.pdf $(DESTDIR)$(pdfdir)/ || \
	    $(install_sh_DATA) $(srcdir)/Linux-PAM_ADG.pdf \
		$(DESTDIR)$(pdfdir)/

uninstall-local:
	-rm $(DESTDIR)$(htmldir)/Linux-PAM_ADG.html
	-rm $(DESTDIR)$(htmldir)/adg-*.html
	-rm $(DESTDIR)$(docdir)/Linux-PAM_ADG.txt
	-rm $(DESTDIR)$(pdfdir)/Linux-PAM_ADG.pdf

releasedocs: all
	$(mkinstalldirs) $(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/html
	test -f html/Linux-PAM_ADG.html || exit 0; \
	    cp -ap html/Linux-PAM_ADG.html html/adg-*.html \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/html/ || \
	    cp -ap $(srcdir)/html/Linux-PAM_ADG.html \
		$(srcdir)/html/adg-*.html \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/html/
	test -f Linux-PAM_ADG.txt || exit 0; \
	    cp -p Linux-PAM_ADG.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/ || \
	    cp -p $(srcdir)/Linux-PAM_ADG.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/
	test -f Linux-PAM_ADG.pdf || exit 0; \
	    cp -p Linux-PAM_ADG.pdf \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/ || \
	    cp -p $(srcdir)/Linux-PAM_ADG.pdf \
		$(top_builddir)/Linux-PAM-$(VERSION)/doc/adg/
