#
# $Id$
#
# This directory contains a pam_filter filter executable
#
# Created by Andrew Morgan <morgan@transmeta.com> 1996/3/11
#

include ../../../Make.Rules

TITLE=upperLOWER

#

OBJS = $(TITLE).o

####################### don't edit below #######################

dummy:
	@echo "**** This is not a top-level Makefile "

all: $(TITLE)

$(TITLE): $(OBJS)
	$(CC) -o $(TITLE) $(OBJS)
	strip $(TITLE)

install:
	$(MKDIR) $(FAKEROOT)$(FILTERSDIR)
	$(INSTALL) -m 511 $(TITLE) $(FAKEROOT)$(FILTERSDIR)

remove:
	cd $(FAKEROOT)$(FILTERSDIR) && rm -f $(TITLE)

clean:
	rm -f $(TITLE) $(OBJS) core *~

.c.o:	
	$(CC) $(CFLAGS) -c $<

