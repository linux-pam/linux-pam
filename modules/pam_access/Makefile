# $Id$
#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#

include ../../Make.Rules

TITLE=pam_access

CONFD=$(CONFIGED)/security
CONFILE=$(CONFD)/access.conf

DEFS=-DCONFILE=\"$(CONFILE)\"
CFLAGS += $(DEFS)

MODULE_SIMPLE_INSTALL=$(MKDIR) $(FAKEROOT)$(SCONFIGED);bash -f ./install_conf
MODULE_SIMPLE_REMOVE=rm -f $(FAKEROOT)$(CONFILE)
MODULE_SIMPLE_CLEAN=rm -f ./.ignore_age

include ../Simple.Rules
