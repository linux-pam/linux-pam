#
# $Id$
#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#
# Created by Andrew Morgan <morgan@linux.kernel.org> 1996/3/11
#

ifeq ($(OS),solaris)

include ../dont_makefile

else

TITLE=pam_filter
FILTERS=upperLOWER
FILTERSDIR=$(SUPLEMENTED)/pam_filter
export FILTERSDIR

CFLAGS += -I. -I..
#

LIBSRC = $(TITLE).c
LIBOBJ = $(TITLE).o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
LIBOBJS = $(addprefix static/,$(LIBOBJ))

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(STATIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

ifdef DYNAMIC
LIBSHARED = $(TITLE).so
endif

ifdef STATIC
LIBSTATIC = lib$(TITLE).o
endif

####################### don't edit below #######################

dummy:
	@echo "**** This is not a top-level Makefile "
	exit

#
# this is where we compile this module
#

all: dirs $(LIBSHARED) $(LIBSTATIC) register filters

dirs:
	if [ ! -f security ]; then ln -sf include security ; fi
ifdef DYNAMIC
	$(MKDIR) ./dynamic
endif
ifdef STATIC
	$(MKDIR) ./static
endif

register:
ifdef STATIC
	( cd .. ; ./register_static $(TITLE) $(TITLE)/$(LIBSTATIC) )
endif

filters:
	@for i in $(FILTERS) ; do \
		if [ -d $$i ]; then \
		   $(MAKE) -C $$i all ; \
		fi ; \
	done


ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)
endif

ifdef DYNAMIC
$(LIBSHARED):	$(LIBOBJD)
		$(LD_D) -o $@ $(LIBOBJD)
endif

ifdef STATIC
$(LIBOBJS): $(LIBSRC)
endif

ifdef STATIC
$(LIBSTATIC): $(LIBOBJS)
	$(LD) -r -o $@ $(LIBOBJS)
endif

install: all
	@for i in $(FILTERS) ; do \
		if [ -d $$i ]; then \
		   $(MAKE) -C $$i install ; \
		fi ; \
	done
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif
	$(MKDIR) $(FAKEROOT)$(INCLUDED)
	$(INSTALL) -m 644 include/pam_filter.h $(FAKEROOT)$(INCLUDED)

remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so
	rm -f $(FAKEROOT)$(INCLUDED)/pam_filter.h
	@for i in $(FILTERS) ; do \
		if [ -d $$i ]; then \
		   $(MAKE) -C $$i remove ; \
		fi ; \
	done

lclean:
	rm -f $(LIBSHARED) $(LIBOBJD) $(LIBOBJS) core *~

clean: lclean
	@for i in $(FILTERS) ; do \
		if [ -d $$i ]; then \
		   $(MAKE) -C $$i clean ; \
		fi ; \
	done

extraclean: lclean
	@rm -f security
	@rm -f *.a *.o *.so *.bak
	for i in $(FILTERS) ; do \
		if [ -d $$i ]; then \
		   $(MAKE) -C $$i extraclean ; \
		fi ; \
	done

security:
	ln -s include security

endif
