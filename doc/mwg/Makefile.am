#
# Copyright (c) 2006 Thorsten Kukuk <kukuk@thkukuk.de>
#

CLEANFILES = Linux-PAM_MWG.fo *~

EXTRA_DIST = $(XMLS)

XMLS = Linux-PAM_MWG.xml $(shell ls pam_*.xml)

if ENABLE_REGENERATE_MAN
MAINTAINERCLEANFILES = Linux-PAM_MWG.txt Linux-PAM_MWG.pdf html/*.html

all: Linux-PAM_MWG.txt html/Linux-PAM_MWG.html Linux-PAM_MWG.pdf

Linux-PAM_MWG.pdf: $(XMLS)
if ENABLE_GENERATE_PDF
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl $< > Linux-PAM_MWG.fo
	$(FO2PDF) Linux-PAM_MWG.fo $(srcdir)/$@
else
	echo "No fo2pdf processor installed, skip PDF generation"
endif

Linux-PAM_MWG.txt: $(XMLS)
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam generate.toc "book toc" \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< | $(BROWSER) > $(srcdir)/$@

html/Linux-PAM_MWG.html: $(XMLS)
	@test -d $(srcdir)/html || mkdir -p $(srcdir)/html
	$(XMLLINT) --nonet --xinclude --postvalid --noent --noout $<
	$(XSLTPROC) --stringparam base.dir html/ \
	  --stringparam root.filename Linux-PAM_MWG \
	  --stringparam use.id.as.filename 1 \
	  --stringparam chunk.first.sections 1 \
	  --stringparam section.autolabel 1 \
	  --stringparam section.label.includes.component.label 1 \
	  --stringparam toc.max.depth 3 --xinclude --nonet \
	  http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
endif
