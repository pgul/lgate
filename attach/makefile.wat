CC = wcc386
LINK = wcl386
DEFINES = -DHAVE_DIRECT_H -DHAVE_IO_H -DHAVE_DOS_H -DHAVE_MALLOC_H &
          -DHAVE_SYS_UTIME_H -DHAVE_MKTIME -DHAVE_FILELENGTH -DHAVE_STRICMP &
          -DHAVE_STRNICMP -DHAVE_STRUPR -DREGEX_MALLOC -DHAVE_SOPEN &
          -DHAVE_PROCESS_H -DHAVE_SHARE_H -DHAVE_SETMODE -DHAVE_SNPRINTF &
          -Dsnprintf=_bprintf -Dvsnprintf=_vbprintf
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

OBJS = &
 $(OBJDIR)\attach.obj &
 $(OBJDIR)\config.obj &
 $(OBJDIR)\uuencode.obj &
 $(OBJDIR)\uudecode.obj &
 $(OBJDIR)\from.obj &
 $(OBJDIR)\misc.obj &
 $(OBJDIR)\checktmp.obj &
 $(OBJDIR)\do_uuen.obj &
 $(OBJDIR)\do_uude.obj &
 $(OBJDIR)\do_b64.obj &
 $(OBJDIR)\do_unb64.obj &
 $(OBJDIR)\hgets.obj

all: $(OBJDIR) $(OBJDIR)\attuucp2.exe $(OBJDIR)\attuucp.exe

obj2\debug:	obj2
	-mkdir obj2\debug
obj2:
	-mkdir obj2

$(OBJDIR)\attach.obj:   attach.c
$(OBJDIR)\config.obj:   config.c
$(OBJDIR)\from.obj:     from.c
$(OBJDIR)\misc.obj:     misc.c
$(OBJDIR)\checktmp.obj: checktmp.c
$(OBJDIR)\uuencode.obj: uuencode.c
$(OBJDIR)\uudecode.obj: uudecode.c
$(OBJDIR)\do_uuen.obj:  do_uuen.c
$(OBJDIR)\do_uude.obj:  do_uude.c
$(OBJDIR)\do_b64.obj:   do_b64.c
$(OBJDIR)\do_unb64.obj: do_unb64.c
$(OBJDIR)\logwrite.obj: logwrite.c
$(OBJDIR)\hgets.obj:    hgets.c

$(OBJS):	gate.h

$(OBJDIR)\attuucp.exe: attuucp.dos $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib
  $(LINK) /"Option stub=attuucp.dos" /fe=$(OBJDIR)\attuucp.exe $(LFLAGS) $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib

$(OBJDIR)\attuucp2.exe: $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib
  $(LINK) /fe=$(OBJDIR)\attuucp2.exe $(LFLAGS) $(OBJS) ..\fidolib\flibp.lib ..\lib\lgatep.lib

clean: .SYMBOLIC
  del $(OBJDIR)\*.obj
