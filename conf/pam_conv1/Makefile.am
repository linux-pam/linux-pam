#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README

noinst_PROGRAMS = pam_conv1

pam_conv1_SOURCES = pam_conv.lex pam_conv.y

pam_conv1_LDADD = @LEXLIB@

pam_conv.c: lex.yy.c

lex.yy.c: pam_conv.lex
	$(LEX) $(srcdir)/pam_conv.lex
