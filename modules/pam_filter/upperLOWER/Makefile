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

CFLAGS += -I../include -I../../pammodutil/include

OBJS = $(TITLE).o

LIBS +=  $(GLIB_LIBS) -L../../pammodutil -lpammodutil
LDFLAGS = $(LIBS)

####################### don't edit below #######################

all: $(TITLE)

$(TITLE): $(OBJS)
	$(CC) $(CFLAGS) -o $(TITLE) $(OBJS) $(LDFLAGS)
	$(STRIP) $(TITLE)

install:
	$(MKDIR) $(FAKEROOT)$(FILTERSDIR)
	$(INSTALL) -m 511 $(TITLE) $(FAKEROOT)$(FILTERSDIR)

remove:
	cd $(FAKEROOT)$(FILTERSDIR) && rm -f $(TITLE)

clean:
	rm -f $(TITLE) $(OBJS) core *~

.c.o:	
	$(CC) $(CFLAGS) -c $<

