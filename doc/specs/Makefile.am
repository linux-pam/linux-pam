#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = draft-morgan-pam-current.txt *~

EXTRA_DIST = draft-morgan-pam.raw std-agent-id.raw rfc86.0.txt

all: padout spec
	test -f rfc86.0.txt || cp -p $(srcdir)/rfc86.0.txt .

spec: draft-morgan-pam.raw
	./padout < $(srcdir)/draft-morgan-pam.raw > draft-morgan-pam-current.txt

noinst_PROGRAMS = padout

padout_SOURCES = parse.y parse.lex

padout_LDADD = @LEXLIB@

parse.c: lex.yy.c

lex.yy.c: $(srcdir)/parse.lex
	$(LEX) $(srcdir)/parse.lex

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(DOCDIR)/spec
	$(INSTALL_DATA) draft-morgan-pam-current.txt $(DESTDIR)$(DOCDIR)/spec/
	$(INSTALL_DATA) rfc86.0.txt $(DESTDIR)$(DOCDIR)/spec/
