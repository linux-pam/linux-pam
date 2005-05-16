#
# $Id$
#

include ../../Make.Rules

ifeq ($(HAVE_LIBSELINUX),yes)

TITLE=pam_selinux
APPLICATION=$(TITLE)_check
APPMODE=04511
MAN8=$(TITLE).8 $(TITLE)_check.8
MODULE_SIMPLE_EXTRALIBS=-lselinux

#MODULE_SIMPLE_INSTALL=$(MAKE) $(APPLICATION); $(INSTALL) -m $(APPMODE) $(APPLICATION) $(FAKEROOT)$(SUPLEMENTED)

include ../Simple.Rules

$(APPLICATION): $(APPLICATION).c
	$(CC) $(CFLAGS) $(INCLUDE_PAMMODUTILS) -o $@ $^ $(LINK_PAMMODUTILS) -lpam -lpam_misc

else

include ../dont_makefile

endif