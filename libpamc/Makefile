#
# $Id$
#

# lots of debugging information goes to /tmp/pam-debug.log
#MOREFLAGS += -D"DEBUG"

ifeq ($(DEBUG_REL),yes)
 LIBNAME=libpamcd
else
 LIBNAME=libpamc
endif
VERSION=.$(MAJOR_REL)
MODIFICATION=.$(MINOR_REL)

# ---------------------------------------------

dummy:
	@echo "*** This is not a top-level Makefile!"

# ---------------------------------------------

CFLAGS += $(DYNAMIC) $(STATIC) $(MOREFLAGS)

# dynamic library names

LIBPAMC = $(LIBNAME).$(DYNTYPE)
LIBPAMCNAME = $(LIBPAMC)$(VERSION)
LIBPAMCFULL = $(LIBPAMCNAME)$(MODIFICATION)

# static library name

LIBPAMCSTATIC = $(LIBNAME).a

LIBOBJECTS = pamc_client.o pamc_converse.o pamc_load.o

ifdef DYNAMIC_LIBPAM
DLIBOBJECTS = $(addprefix dynamic/,$(LIBOBJECTS))
endif

ifdef STATIC_LIBPAM
SLIBOBJECTS = $(addprefix static/,$(LIBOBJECTS))
endif

# ---------------------------------------------
## rules

all: dirs $(LIBPAMC) $(LIBPAMCSTATIC)

dirs:
ifdef DYNAMIC_LIBPAM
	mkdir -p dynamic
endif
ifdef STATIC_LIBPAM
	mkdir -p static
endif

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(STATIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

$(LIBPAMC): $(DLIBOBJECTS)
ifdef DYNAMIC_LIBPAM
    ifeq ($(USESONAME),yes)
	$(LD_L) $(SOSWITCH) $(LIBPAMCNAME) -o $@ $(DLIBOBJECTS) $(MODULES) $(LINKLIBS)
    else
	$(LD_L) -o $@ $(DLIBOBJECTS) $(MODULES)
    endif
    ifeq ($(NEEDSONAME),yes)
	rm -f $(LIBPAMCFULL)
	ln -s $(LIBPAMC) $(LIBPAMCFULL)
	rm -f $(LIBPAMCNAME)
	ln -s $(LIBPAMC) $(LIBPAMCNAME)
    endif
endif

$(LIBPAMCSTATIC): $(SLIBOBJECTS)
ifdef STATIC_LIBPAM
	$(AR) $@ $(SLIBOBJECTS) $(MODULES)
	$(RANLIB) $@
endif

install: all
	$(MKDIR) $(FAKEROOT)$(INCLUDED)
	$(INSTALL) -m 644 include/security/pam_client.h $(FAKEROOT)$(INCLUDED)
ifdef DYNAMIC_LIBPAM
	$(INSTALL) -m $(SHLIBMODE) $(LIBPAMC) $(FAKEROOT)$(LIBDIR)/$(LIBPAMCFULL)
	$(LDCONFIG)
  ifneq ($(DYNTYPE),"sl")
	( cd $(FAKEROOT)$(LIBDIR) ; rm -f $(LIBPAMC) ; ln -s $(LIBPAMCNAME) $(LIBPAMC) )
  endif
endif
ifdef STATIC_LIBPAM
	$(INSTALL) -m 644 $(LIBPAMCSTATIC) $(FAKEROOT)$(LIBDIR)
endif

remove:
	rm -f $(FAKEROOT)$(INCLUDED)/pam_client.h
	$(LDCONFIG)
	rm -f $(FAKEROOT)$(LIBDIR)/$(LIBPAMCSTATIC)

clean:
	rm -f a.out core *~ static/*.o dynamic/*.o

extraclean: clean
	rm -f *.a *.out *.o *.so ./include/security/*~
	if [ -d dynamic ]; then rmdir dynamic ; fi
	if [ -d static ]; then rmdir static ; fi
