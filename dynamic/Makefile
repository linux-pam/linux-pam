#
# $Id$
#
#

include ../Make.Rules

ifeq ($(WITH_LIBDEBUG),yes)
 LIBNAME=pamd
else
 LIBNAME=pam
endif
VERSION=.$(MAJOR_REL)
MODIFICATION=.$(MINOR_REL)

# ---------------------------------------------

dummy: ../Make.Rules all

# ---------------------------------------------

# dynamic library names

PAMSHOBJ = pam.so
PAMSHOBJMAJ = $(PAMSHOBJ)$(VERSION)

DLIBOBJECTS = pam.o

# ---------------------------------------------
## rules

all: dirs $(PAMSHOBJ) ../Make.Rules

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

$(PAMSHOBJ): $(DLIBOBJECTS)
ifeq ($(USESONAME),yes)
	$(LD_L) $(SOSWITCH) $(PAMSHOBJMAJ) -o $@ $+ $(LINKLIBS)
else
	$(LD_L) -o $@ $(DLIBOBJECTS) $(LINKLIBS)
endif

install: all
	$(MKDIR) $(FAKEROOT)$(libdir)
ifeq ($(DYNAMIC_LIBPAM),yes)
	$(INSTALL) -m $(SHLIBMODE) $(PAMSHOBJ) $(FAKEROOT)$(libdir)/$(PAMSHOBJ)
	$(LDCONFIG)
endif

remove:
	rm -f $(FAKEROOT)$(libdir)/$(LIBPAM)
	$(LDCONFIG)

clean:
	rm -f a.out core *~ static/*.o dynamic/*.o
	rm -f *.a *.o *.so ./include/security/*~
	if [ -d dynamic ]; then rmdir dynamic ; fi
	if [ -d static ]; then rmdir static ; fi
