# $Id$
DEFINES = -DHAVE_DIRECT_H -DHAVE_IO_H -DHAVE_DOS_H -DHAVE_MALLOC_H &
          -DHAVE_SYS_UTIME_H -DHAVE_MKTIME -DHAVE_FILELENGTH -DHAVE_STRICMP &
          -DHAVE_STRNICMP -DHAVE_STRUPR -DREGEX_MALLOC -DHAVE_STRING_H &
          -DHAVE_SOPEN -DHAVE_SHARE_H -DHAVE_ISASCII -DHAVE_SETMODE &
          -DHAVE_ENVIRON -DHAVE_SNPRINTF &
          -Dsnprintf=_bprintf -Dvsnprintf=_vbprintf

CC = wcc386
COPT = /bm /w3 /fo=$@ /i=..\fidolib $(DEFINES)
LIB = wlib
OBJDIR = obj2

!ifdef DEBUG
CFLAGS = $(COPT) /d2 /hw
OBJDIR = obj2\debug
!else
CFLAGS = $(COPT)
OBJDIR = obj2
!endif

OBJS = &
 $(OBJDIR)\cmpaddr.obj &
 $(OBJDIR)\debug.obj &
 $(OBJDIR)\ea.obj &
 $(OBJDIR)\gettz.obj &
 $(OBJDIR)\logwrite.obj &
 $(OBJDIR)\myfopen.obj &
 $(OBJDIR)\regex.obj &
 $(OBJDIR)\rwmsghdr.obj &
 $(OBJDIR)\savein.obj &
 $(OBJDIR)\run2.obj &
 $(OBJDIR)\sysexit.obj &
 $(OBJDIR)\sysfuncs.obj &
 $(OBJDIR)\template.obj &
 $(OBJDIR)\charsets.obj

.c.obj:
	$(CC) $(CFLAGS) $<

all:	$(OBJDIR) lgatep.lib

obj2:
	-mkdir obj2

obj2\debug:	obj2
	-mkdir obj2\debug

clean:	.SYMBOLIC
	rm -f $(OBJS) lgatep.bak

lgatep.lib:	$(OBJS) .AUTODEPEND
	$(LIB) $@ +- $?

$(OBJS):	libgate.h .AUTODEPEND
