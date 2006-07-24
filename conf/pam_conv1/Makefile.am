#
# Copyright (c) 2005 Thorsten Kukuk <kukuk@suse.de>
#

CLEANFILES = *~

EXTRA_DIST = README

AM_YFLAGS = -d

BUILT_SOURCES = pam_conv_y.h

noinst_PROGRAMS = pam_conv1

pam_conv1_SOURCES = pam_conv_l.l pam_conv_y.y

pam_conv1_LDADD = @LEXLIB@
