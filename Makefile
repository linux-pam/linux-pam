##
## $Id$
##

## Note, ideally I would prefer it if this top level makefile did
## not get created by autoconf. As I find typing 'make' and relying
## on it to take care of all dependencies much more friendly than
## the multi-stage autoconf+make and also worry about updates to
## configure.in not getting propagated down the tree. (AGM) [I realise
## that this may not prove possible, but at least I tried.. Sigh.]

DISTNAME=Linux-PAM

ifeq ($(shell test \! -f Make.Rules || echo yes),yes)
    include Make.Rules
endif

THINGSTOMAKE = libpam libpamc libpam_misc modules doc examples

all: $(THINGSTOMAKE)

 # Let's get a dynamic libpam.so first
 bootstrap-libpam: _pam_aconf.h prep
	$(MAKE) -C libpam bootstrap-libpam

prep:
	rm -f security
	ln -sf . security

clean:
	if [ ! -f Make.Rules ]; then touch Make.Rules ; fi
	for i in $(THINGSTOMAKE) ; do $(MAKE) -C $$i clean ; done
	rm -f security *~ *.orig *.rej Make.Rules #*#

distclean: clean
	rm -f Make.Rules _pam_aconf.h
	rm -f config.status config.cache config.log core

maintainer-clean: distclean
	@echo files should be ok for packaging now.

# NB _pam_aconf.h.in changes will remake this too
Make.Rules: configure Make.Rules.in _pam_aconf.h.in
	./config.status --recheck
	./config.status

_pam_aconf.h: Make.Rules

configure: configure.in
	@echo
	@echo You do not appear to have an up-to-date ./configure file.
	@echo Please run autoconf, and then ./configure [..options..]
	@echo
	@rm -f configure
	@exit 1

$(THINGSTOMAKE): _pam_aconf.h prep bootstrap-libpam
	$(MAKE) -C $@ all

install: _pam_aconf.h prep
	for x in $(THINGSTOMAKE) ; do $(MAKE) -C $$x install ; done

remove:
	rm -f $(FAKEROOT)$(INCLUDED)/_pam_aconf.h
	for x in $(THINGSTOMAKE) ; do $(MAKE) -C $$x remove ; done

release:
	@if [ ! -f Make.Rules ]; then echo $(MAKE) Make.Rules first ;exit 1 ;fi
	@if [ ! -L ../$(DISTNAME)-$(MAJOR_REL).$(MINOR_REL) ]; then \
	   echo generating ../$(DISTNAME)-$(MAJOR_REL).$(MINOR_REL) link ; \
	   ln -sf $(DISTNAME) ../$(DISTNAME)-$(MAJOR_REL).$(MINOR_REL) ; \
	   echo to ../$(DISTNAME) . ; fi
	@diff ../$(DISTNAME)-$(MAJOR_REL).$(MINOR_REL)/Make.Rules Make.Rules
	$(MAKE) distclean
	cd .. ; tar zvfc $(DISTNAME)-$(MAJOR_REL).$(MINOR_REL).tar.gz \
		--exclude CVS --exclude .cvsignore --exclude '.#*' \
		$(DISTNAME)-$(MAJOR_REL).$(MINOR_REL)/*

