# $Id$
DEFINES = -DHAVE_DIRECT_H -DHAVE_IO_H -DHAVE_DOS_H -DHAVE_MALLOC_H &
          -DHAVE_SYS_UTIME_H -DHAVE_MKTIME -DHAVE_FILELENGTH -DHAVE_STRICMP &
          -DHAVE_STRNICMP
CC = wcc386
CFLAGS = /bm /w3 /fo=$@ $(DEFINES)
LIB = wlib
OBJDIR = obj2

OBJS = &
 $(OBJDIR)\myopen.obj &
 $(OBJDIR)\montable.obj &
 $(OBJDIR)\weekday.obj &
 $(OBJDIR)\daymon.obj &
 $(OBJDIR)\copyfile.obj &
 $(OBJDIR)\getfaddr.obj &
 $(OBJDIR)\crc.obj &
 $(OBJDIR)\binksem.obj &
 $(OBJDIR)\lbsosem.obj &
 $(OBJDIR)\fdsem.obj &
 $(OBJDIR)\bsyname.obj &
 $(OBJDIR)\getfmask.obj &
 $(OBJDIR)\chkmask.obj &
 $(OBJDIR)\touch.obj &
 $(OBJDIR)\dayweek.obj &
 $(OBJDIR)\movefile.obj &
 $(OBJDIR)\rmove.obj &
 $(OBJDIR)\scanbnk.obj

all:	$(OBJDIR) flibp.lib

$(OBJDIR):
	-mkdir $(OBJDIR)

clean:	.SYMBOLIC
	rm -f $(OBJS) flibp.bak

flibp.lib:	$(OBJS) .AUTODEPEND
	$(LIB) $@ +- $?

.c.obj:
	$(CC) $(CFLAGS) $<

$(OBJS):	fidolib.h
