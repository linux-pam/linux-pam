#
# This Makefile controls a build process of $(TITLE) module for
# Linux-PAM. You should not modify this Makefile (unless you know
# what you are doing!).

# $Id$
# Created by Cristian Gafton <gafton@redhat.com>

WHICH_DB=$(shell ./libdbfound.sh)
ifeq ($(WHICH_DB),none)

include ../dont_makefile

else

TITLE=pam_userdb

LIBSRC = $(TITLE).c conv.c
LIBOBJ = $(TITLE).o conv.o
LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
#LIBOBJS = $(addprefix static/,$(LIBOBJ))

EXTRALS += -ldb
CFLAGS += $(WHICH_DB)

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@

#static/%.o : %.c
#	$(CC) $(CFLAGS) $(STATIC) $(CPPFLAGS) $(TARGET_ARCH) -c $< -o $@


ifdef DYNAMIC
LIBSHARED = $(TITLE).so
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

ifdef DYNAMIC
$(LIBOBJD): $(LIBSRC)

$(LIBSHARED):	$(LIBOBJD)
	$(LD_D) -o $@ $(LIBOBJD) $(EXTRALS)
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

.PHONY: register

test:
	install -m 755 $(TITLE).so /tmp

endif
