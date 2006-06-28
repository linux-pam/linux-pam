#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = Linux-PAM_ADG.fo *~

EXTRA_DIST = $(XMLS)

XMLS = Linux-PAM_ADG.xml $(shell ls $(srcdir)/pam_*.xml)

if ENABLE_REGENERATE_MAN
MAINTAINERCLEANFILES = Linux-PAM_ADG.txt Linux-PAM_ADG.pdf html/*.html

all: Linux-PAM_ADG.txt html/Linux-PAM_ADG.html Linux-PAM_ADG.pdf

Linux-PAM_ADG.pdf: $(XMLS)
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

Linux-PAM_ADG.txt: $(XMLS)
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< | $(BROWSER) > $@

html/Linux-PAM_ADG.html: $(XMLS)
	@test -d html || mkdir -p html
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam base.dir html/ \
	  --stringparam root.filename Linux-PAM_ADG \
	  --stringparam use.id.as.filename 1 \
	  --stringparam chunk.first.sections 1 \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
endif

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/txt
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/pdf
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/html
	test -f html/Linux-PAM_ADG.html && \
	    $(install_sh_DATA) html/Linux-PAM_ADG.html html/adg-*.html \
		$(DESTDIR)$(DOCDIR)/html/ || \
	    $(install_sh_DATA) $(srcdir)/html/Linux-PAM_ADG.html \
		$(srcdir)/html/sag-*.html \
		$(DESTDIR)$(DOCDIR)/html/
	test -f Linux-PAM_ADG.txt && \
	    $(install_sh_DATA) Linux-PAM_ADG.txt $(DESTDIR)$(DOCDIR)/txt/ || \
	    $(install_sh_DATA) $(srcdir)/Linux-PAM_ADG.txt \
		$(DESTDIR)$(DOCDIR)/txt/
	test -f Linux-PAM_ADG.pdf && \
	    $(install_sh_DATA) Linux-PAM_ADG.pdf $(DESTDIR)$(DOCDIR)/pdf/ || \
	    $(install_sh_DATA) $(srcdir)/Linux-PAM_ADG.pdf \
		$(DESTDIR)$(DOCDIR)/pdf/

releasedocs: all
	test -f html/Linux-PAM_ADG.html && \
	    cp -ap html/Linux-PAM_ADG.html html/adg-*.html \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/html/ || \
	    cp -ap $(srcdir)/html/Linux-PAM_ADG.html \
		$(srcdir)/html/adg-*.html \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/html/
	test -f Linux-PAM_ADG.txt && \
	    cp -p Linux-PAM_ADG.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/txt/ || \
	    cp -p $(srcdir)/Linux-PAM_ADG.txt \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/txt/
	test -f Linux-PAM_ADG.pdf && \
	    cp -p Linux-PAM_ADG.pdf \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/pdf/ || \
	    cp -p $(srcdir)/Linux-PAM_ADG.pdf \
		$(top_builddir)/Linux-PAM-$(VERSION)-docs/pdf/
