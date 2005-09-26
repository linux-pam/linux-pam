#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = draft-morgan-pam-current.txt *~

EXTRA_DIST = draft-morgan-pam.raw std-agent-id.raw rfc86.0.txt lex.yy.c

all: padout spec

spec: draft-morgan-pam.raw
	./padout < draft-morgan-pam.raw > draft-morgan-pam-current.txt

noinst_PROGRAMS = padout

padout_SOURCES = parse.y parse.lex

padout_LDADD = @LEXLIB@

parse.c: lex.yy.c

lex.yy.c: parse.lex
	$(LEX) parse.lex
