#
# $Id$
#

# lots of debugging information goes to /tmp/pam-debug.log
#MOREFLAGS += -D"DEBUG"

include ../Make.Rules

ifeq ($(DEBUG_REL),yes)
 LIBNAME=libpamcd
else
 LIBNAME=libpamc
endif
ifeq ($(WITH_PRELUDE),yes)
 CFLAGS += -DPRELUDE -DLIBPRELUDE_CONFIG_PREFIX=\"`libprelude-config --prefix`\"
endif
VERSION=.$(MAJOR_REL)
MODIFICATION=.$(MINOR_REL)

CFLAGS += $(MOREFLAGS) $(DYNAMIC) $(STATIC)

# dynamic library names

LIBNAMED = $(LIBNAME).$(DYNTYPE)
LIBNAMEDNAME = $(LIBNAMED)$(VERSION)
LIBNAMEDFULL = $(LIBNAMEDNAME)$(MODIFICATION)

# static library name

LIBNAMEDSTATIC = $(LIBNAME).a

LIBOBJECTS = pamc_client.o pamc_converse.o pamc_load.o

ifeq ($(DYNAMIC_LIBPAM),yes)
DLIBOBJECTS = $(addprefix dynamic/,$(LIBOBJECTS))
endif

ifeq ($(STATIC_LIBPAM),yes)
SLIBOBJECTS = $(addprefix static/,$(LIBOBJECTS))
endif

# ---------------------------------------------
## rules

all: dirs $(LIBNAMED) $(LIBNAMEDSTATIC)

dirs:
ifeq ($(DYNAMIC_LIBPAM),yes)
	$(MKDIR) dynamic
endif
ifeq ($(STATIC_LIBPAM),yes)
	$(MKDIR) static
endif

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

$(LIBNAMED): $(DLIBOBJECTS)
ifeq ($(DYNAMIC_LIBPAM),yes)
    ifeq ($(USESONAME),yes)
	$(LD_L) $(SOSWITCH)$(LIBNAMEDNAME) -o $@ $(DLIBOBJECTS) $(MODULES) $(LINKLIBS)
    else
	$(LD_L) -o $@ $(DLIBOBJECTS) $(MODULES)
    endif
    ifeq ($(NEEDSONAME),yes)
	rm -f $(LIBNAMEDFULL)
	ln -s $(LIBNAMED) $(LIBNAMEDFULL)
	rm -f $(LIBNAMEDNAME)
	ln -s $(LIBNAMED) $(LIBNAMEDNAME)
    endif
endif

$(LIBNAMEDSTATIC): $(SLIBOBJECTS)
ifeq ($(STATIC_LIBPAM),yes)
	$(AR) rcu $@ $(SLIBOBJECTS) $(MODULES)
ifdef RANLIB
	$(RANLIB) $@
endif
endif

install: all
	$(MKDIR) $(FAKEROOT)$(INCLUDED)
	$(INSTALL) -m 644 include/security/pam_client.h $(FAKEROOT)$(INCLUDED)
ifeq ($(DYNAMIC_LIBPAM),yes)
	$(MKDIR) $(FAKEROOT)$(libdir)
	$(INSTALL) -m $(SHLIBMODE) $(LIBNAMED) $(FAKEROOT)$(libdir)/$(LIBNAMEDFULL)
ifndef FAKEROOT
	$(LDCONFIG)
else
	$(LDCONFIG) -n $(FAKEROOT)$(libdir)
endif
  ifneq ($(DYNTYPE),"sl")
	( cd $(FAKEROOT)$(libdir) ; rm -f $(LIBNAMED) ; ln -s $(LIBNAMEDNAME) $(LIBNAMED) )
  endif
endif
ifeq ($(STATIC_LIBPAM),yes)
	$(INSTALL) -m 644 $(LIBNAMEDSTATIC) $(FAKEROOT)$(libdir)
endif

remove:
	rm -f $(FAKEROOT)$(INCLUDED)/pam_client.h
	rm -f $(FAKEROOT)$(libdir)/$(LIBNAMEDFULL)
	rm -f $(FAKEROOT)$(libdir)/$(LIBNAMED)
ifndef FAKEROOT
	$(LDCONFIG)
endif
	rm -f $(FAKEROOT)$(libdir)/$(LIBNAMEDSTATIC)

clean:
	rm -f a.out core *~ static/*.o dynamic/*.o
	rm -f *.a *.out *.o *.so ./include/security/*~
	rm -f *.orig $(LIBNAMEDNAME) $(LIBNAMEDFULL)
	if [ -d dynamic ]; then rmdir dynamic ; fi
	if [ -d static ]; then rmdir static ; fi

