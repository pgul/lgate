CC = wcc386
LINK = wcl386
DEFINES = -DHAVE_DIRECT_H -DHAVE_IO_H -DHAVE_DOS_H -DHAVE_MALLOC_H &
          -DHAVE_SYS_UTIME_H -DHAVE_MKTIME -DHAVE_FILELENGTH -DHAVE_STRICMP &
          -DHAVE_STRNICMP -DHAVE_STRUPR -DREGEX_MALLOC -DHAVE_SOPEN &
          -DHAVE_PROCESS_H -DHAVE_SHARE_H -DHAVE_SETMODE
COPT = /w3 /i=..\lib /i=..\fidolib /fo=$@ $(DEFINES)
LOPT = /x

!ifdef DEBUG
CFLAGS = $(COPT) /d2 /hw
LFLAGS = $(LOPT) /d2 /hw
OBJDIR = obj2\debug
!else
CFLAGS = $(COPT)
LFLAGS = $(LOPT)
OBJDIR = obj2
!endif

.c.obj:
  $(CC) $(CFLAGS) $<

.asm.obj:
  wasm $<

OBJS = $(OBJDIR)\forward.obj

all: $(OBJDIR) $(OBJDIR)\forward2.exe $(OBJDIR)\forward.exe

obj2\debug:	obj2
	mkdir obj2\debug
obj2:
	mkdir obj2

$(OBJDIR)\forward.obj:  forward.c

$(OBJDIR)\forward.exe: forward.exe $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib
  $(LINK) /"Option stub=forward.exe" /fe=$(OBJDIR)\forward.exe $(LFLAGS) $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib

$(OBJDIR)\forward2.exe: $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib
  $(LINK) /fe=$(OBJDIR)\forward2.exe $(LFLAGS) $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib

$(OBJS):	../lib/libgate.h ../fidolib/fidolib.h

clean: .SYMBOLIC
  del $(OBJDIR)\*.obj
