#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).

# $Id$
# Created by Cristian Gafton <gafton@redhat.com>

include ../../Make.Rules

TITLE=pam_userdb

ifeq ($(HAVE_LIBDB),yes)
 WHICH_DB=db
 MODULE_SIMPLE_EXTRALIBS = -ldb
else
ifeq ($(HAVE_LIBNDBM),yes)
 WHICH_DB=ndbm
 MODULE_SIMPLE_EXTRALIBS = -lndbm
else
 WHICH_DB=none
endif
endif

ifeq ($(WHICH_DB),none)

include ../dont_makefile

else

include ../Simple.Rules

endif
