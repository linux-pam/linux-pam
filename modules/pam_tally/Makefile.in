#
# $Id$
#
# This Makefile controls a build process of $(TITLE) module and
# application for Linux-PAM. You should not modify this Makefile
# (unless you know what you are doing!).
#
#

TITLE=pam_tally

#
## Additional rules for making (and moving) the application added.
## Assuming that all modules' applications are called $TITLE
#

LIBSRC = $(TITLE).c
LIBOBJ = $(TITLE).o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
LIBOBJS = $(addprefix static/,$(LIBOBJ))

APPSRC = $(TITLE)_app.c
APPOBJ = $(TITLE)_app.o
APPOBJD = $(addprefix dynamic/,$(APPOBJ))
APPOBJS = $(addprefix static/,$(APPOBJ))
    
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

APPLICATION = $(TITLE)
APPMODE = 755

####################### don't edit below #######################

dummy:
	@echo "**** This is not a top-level Makefile "
	exit

all: dirs $(LIBSHARED) $(LIBSTATIC) register
# we're not yet in a position to build this. If you want it, build it
# separately...
# $(APPLICATION)

dirs:
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

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)

$(LIBSHARED):   $(LIBOBJD)
	$(LD_D) -o $@ $(LIBOBJD)

$(APPLICATION):   $(APPOBJD)
	$(CC) $(CFLAGS) -o $@ $< $(LOADLIBES)
    
endif

ifdef STATIC
$(LIBOBJS): $(LIBSRC)

$(LIBSTATIC): $(LIBOBJS)
	$(LD) -r -o $@ $(LIBOBJS)

$(APPLICATION):   $(APPOBJS)
	$(CC) $(CFLAGS) -o $@ $< $(LOADLIBES)
endif

install: all
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif
	$(MKDIR) $(FAKEROOT)$(SUPLEMENTED)
#	$(INSTALL) -m $(APPMODE) $(APPLICATION) $(FAKEROOT)$(SUPLEMENTED)

remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so
	rm -f $(FAKEROOT)$(SUPLEMENTED)/$(TITLE)

clean:
	rm -f $(LIBOBJD) $(LIBOBJS) $(APPOBJD) $(APPOBJS) core *~

extraclean: clean
	rm -f *.a *.o *.so *.bak dynamic/* static/* $(APPLICATION)

.c.o:   
	$(CC) $(CFLAGS) -c $<
