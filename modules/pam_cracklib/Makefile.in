#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).
#
# Created by Cristian Gafton <gafton@redhat.com> 1996/09/10
#

ifndef FULL_LINUX_PAM_SOURCE_TREE
#
# here you should make default variable defines...
#
MKDIR=mkdir -p
LD_D=gcc -shared -Xlinker -x
INSTALL=install
SECUREDIR=/usr/lib/security
#
HAVE_CRACKLIB=yes
EXTRALS=-lcrypt
endif

ifeq ($(HAVE_CRACKLIB),yes)

TITLE=pam_cracklib
CRACKLIB=-lcrack
ifeq ($(shell if [ -f /usr/lib/cracklib_dict.hwm ]; then echo yes ; fi),yes)
 CRACKLIB_DICTPATH=/usr/lib/cracklib_dict
else
 CRACKLIB_DICTPATH=/usr/share/dict/cracklib_dict
endif
#
ifeq ($(shell if [ -f /usr/include/crypt.h ]; then echo yes ; fi),yes)
 NEED_CRYPT_HEADER=-DNEED_CRYPT_HEADER
endif
#
LIBSRC = $(TITLE).c
LIBOBJ = $(TITLE).o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
LIBOBJS = $(addprefix static/,$(LIBOBJ))

ifdef CRACKLIB_DICTPATH
CFLAGS+=-DCRACKLIB_DICTPATH=\"$(CRACKLIB_DICTPATH)\"
endif

dynamic/%.o : %.c
	$(CC) $(NEED_CRYPT_HEADER) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

static/%.o : %.c
	$(CC) $(NEED_CRYPT_HEADER) $(CFLAGS) $(STATIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@


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

all: dirs $(LIBSHARED) $(LIBSTATIC) register

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
$(LIBOBJD): $(LIBSRC) Makefile

$(LIBSHARED):	$(LIBOBJD)
	$(LD_D) -o $@ $(LIBOBJD) $(CRACKLIB) $(EXTRALS) $(LINKLIBS)
endif

ifdef STATIC
$(LIBOBJS): $(LIBSRC)

$(LIBSTATIC): $(LIBOBJS)
	$(LD) -r -o $@ $(LIBOBJS)
endif

install: all
	$(MKDIR) $(FAKEROOT)$(SECUREDIR)
ifdef DYNAMIC
	$(INSTALL) -m $(SHLIBMODE) $(LIBSHARED) $(FAKEROOT)$(SECUREDIR)
endif

remove:
	rm -f $(FAKEROOT)$(SECUREDIR)/$(TITLE).so

clean:
	rm -f $(LIBOBJD) $(LIBOBJS) core *~ *.so

extraclean: clean
	rm -f *.a *.o *.so *.bak dynamic/* static/*

.c.o:	
	$(CC) $(CFLAGS) -c $<

else

include ../dont_makefile

endif
