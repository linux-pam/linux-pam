#
# $Id$
#

# lots of debugging information goes to /tmp/pam-debug.log
#MOREFLAGS += -D"DEBUG"

include ../Make.Rules

ifeq ($(DEBUG_REL),yes)
 LIBNAME=libpam_miscd
else
 LIBNAME=libpam_misc
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

LIBOBJECTS = help_env.o misc_conv.o

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
	$(LD_L) $(SOSWITCH) $(LIBNAMEDNAME) -o $@ $(DLIBOBJECTS) $(MODULES) $(LINKLIBS)
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
	$(AR) $@ $(SLIBOBJECTS) $(MODULES)
	$(RANLIB) $@
endif

install: all
	$(MKDIR) $(FAKEROOT)$(INCLUDED)
	$(INSTALL) -m 644 include/security/pam_misc.h $(FAKEROOT)$(INCLUDED)
ifeq ($(DYNAMIC_LIBPAM),yes)
	$(INSTALL) -m $(SHLIBMODE) $(LIBNAMED) $(FAKEROOT)$(LIBDIR)/$(LIBNAMEDFULL)
	$(LDCONFIG)
  ifneq ($(DYNTYPE),"sl")
	( cd $(FAKEROOT)$(LIBDIR) ; rm -f $(LIBNAMED) ; ln -s $(LIBNAMEDNAME) $(LIBNAMED) )
  endif
endif
ifeq ($(STATIC_LIBPAM),yes)
	$(INSTALL) -m 644 $(LIBNAMEDSTATIC) $(FAKEROOT)$(LIBDIR)
endif

remove:
	rm -f $(FAKEROOT)$(INCLUDED)/pam_misc.h
	$(LDCONFIG)
	rm -f $(FAKEROOT)$(LIBDIR)/$(LIBNAMEDSTATIC)

clean:
	rm -f a.out core *~ static/*.o dynamic/*.o

extraclean: clean
	rm -f *.a *.out *.o *.so ./include/security/*~
	if [ -d dynamic ]; then rmdir dynamic ; fi
	if [ -d static ]; then rmdir static ; fi
