# $Id$
#

dummy:
	@echo "*** This is not a top-level Makefile!"

# ///////////////////////////////////////////////////////////////////

# uncomment if you wnat libpam_misc to be made as a dynamic library
# AGM has had some segfaulting from libdl when I did this. I have not
# investigated the cause...

MAKE_DYNAMIC=yes

ifeq ($(DEBUG_REL),yes)
 LIBNAME=pamd_misc
else
 LIBNAME=pam_misc
endif
LIBMAJOR=$(MAJOR_REL)
LIBMINOR=$(MINOR_REL)

FILES=misc_conv help_env

#
# Probably no need to alter anything below here.
#

# build dynamic library names

LIBDYNAMIC=lib$(LIBNAME).$(DYNTYPE)
LIBDYNMAJ=$(LIBDYNAMIC).$(LIBMAJOR)
LIBDYNMIN=$(LIBDYNMAJ).$(LIBMINOR)

# static library name

LIBSTATIC = lib$(LIBNAME).a

# sources and object files

LIBSRC = $(addsuffix .c,$(FILES))
LIBOBJ = $(addsuffix .o,$(FILES))

# rules

all: $(LIBSTATIC) $(LIBDYNAMIC)

$(LIBDYNAMIC): $(LIBOBJ)
ifdef MAKE_DYNAMIC
    ifeq ($(USESONAME),yes)
	$(LD_L) $(SOSWITCH) $(LIBDYNMAJ) -o $@ $(LIBOBJ) $(LINKLIBS)
    else
	$(LD_L) -o $@ $(LIBOBJ)
    endif
    ifeq ($(NEEDSONAME),yes)
	rm -f $(LIBDYNMIN)
	ln -s $(LIBDYNAMIC) $(LIBDYNMAJ)
	rm -f $(LIBDYNMAJ)
	ln -s $(LIBDYNAMIC) $(LIBDYNMIN)
    endif
endif

$(LIBSTATIC): $(LIBOBJ)
	$(AR) $@ $(LIBOBJ)
	$(RANLIB) $@

install: all
	$(MKDIR) $(FAKEROOT)$(INCLUDED)
	$(INSTALL) -m 644 ./pam_misc.h $(FAKEROOT)$(INCLUDED)
ifdef MAKE_DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBDYNAMIC) $(FAKEROOT)$(LIBDIR)/$(LIBDYNMIN)
	$(LDCONFIG)
  ifneq ($(DYNTYPE),"sl")
	( cd $(FAKEROOT)$(LIBDIR) ; ln -sf $(LIBDYNMAJ) $(LIBDYNAMIC) )
  endif
endif
	$(INSTALL) -m 644 $(LIBSTATIC) $(FAKEROOT)$(LIBDIR)

clean:
	rm -f *.so *.a core a.out *~

remove:
	rm -f $(FAKEROOT)$(INCLUDED)/pam_misc.h
	rm -f $(FAKEROOT)$(LIBDIR)/$(LIBDYNAMIC).*
	rm -f $(FAKEROOT)$(LIBDIR)/$(LIBDYNAMIC)
	$(LDCONFIG)
	rm -f $(FAKEROOT)$(LIBDIR)/$(LIBSTATIC)
	rm -f $(FAKEROOT)$(INCLUDED)/chk_malloc.h

.c.o:
	$(CC) -c $(DEFS) $(CFLAGS) $<

extraclean:
	@$(MAKE) clean
	rm -f *.o *.bak

