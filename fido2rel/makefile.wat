# $Id$
CC = wcc386
LINK = wcl386
DEFINES = -DHAVE_FILELENGTH -DHAVE_MALLOC_H -DHAVE_STDARG_H -DHAVE_DOS_H &
          -DHAVE_DIRECT_H -DHAVE_SYS_UTIME_H -DHAVE_IO_H -DHAVE_PROCESS_H &
          -DHAVE_SHARE_H -DHAVE_ENVIRON -DHAVE_STRICMP -DHAVE_STRNICMP &
          -DHAVE_SOPEN -DHAVE_PROCESS_H -DHAVE_SETMODE -DHAVE_SNPRINTF &
          -Dsnprintf=_bprintf -Dvsnprintf=_vbprintf

COPT = /fo=$@ /i=..\lib /i=..\fidolib /w3 /bm $(DEFINES)
LOPT = /x /k1024k /bm /"Library rexx"

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

All: $(OBJDIR) $(OBJDIR)\fido2re2.exe $(OBJDIR)\fido2rel.exe

obj2\debug:	obj2
	-mkdir obj2\debug
obj2:
	-mkdir obj2

OBJS = &
 $(OBJDIR)\arbmath.obj &
 $(OBJDIR)\config.obj &
 $(OBJDIR)\fido2rel.obj &
 $(OBJDIR)\one_mess.obj &
 $(OBJDIR)\genrej.obj &
 $(OBJDIR)\getfaddr.obj &
 $(OBJDIR)\import.obj &
 $(OBJDIR)\makeaddr.obj &
 $(OBJDIR)\rsend.obj &
 $(OBJDIR)\virtfile.obj &
 $(OBJDIR)\misc.obj &
 $(OBJDIR)\base64.obj

$(OBJDIR)\arbmath.obj: arbmath.c lib.h
$(OBJDIR)\config.obj: config.c lib.h import.h
$(OBJDIR)\fido2rel.obj: fido2rel.c
$(OBJDIR)\one_mess.obj: one_mess.c
$(OBJDIR)\genrej.obj: genrej.c
$(OBJDIR)\getfaddr.obj: getfaddr.c
$(OBJDIR)\import.obj: import.c lib.h import.h
$(OBJDIR)\makeaddr.obj: makeaddr.c
$(OBJDIR)\misc.obj: misc.c
$(OBJDIR)\base64.obj: base64.c
$(OBJDIR)\rsend.obj: rsend.c
$(OBJDIR)\virtfile.obj: virtfile.c

$(OBJS):	gate.h ..\lib\libgate.h ..\fidolib\fidolib.h

$(OBJDIR)\fido2rel.exe: fido2rel.com $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib
  $(LINK) $(LFLAGS) /"Option stub=fido2rel.com" /fe=$(OBJDIR)\fido2rel.exe $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib

$(OBJDIR)\fido2re2.exe: $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib
  $(LINK) $(LFLAGS) /fe=$(OBJDIR)\fido2re2.exe $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib

clean:  .SYMBOLIC
  if exist $(OBJDIR)\*.obj del $(OBJDIR)\*.obj
  if exist $(OBJDIR)\fido2rel.exe del $(OBJDIR)\fido2rel.exe
