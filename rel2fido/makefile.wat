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

All:	$(OBJDIR) $(OBJDIR)\rel2fid2.exe $(OBJDIR)\rel2fido.exe

obj2\debug:	obj2
	-mkdir obj2\debug
obj2:
	-mkdir obj2

OBJS = &
 $(OBJDIR)\arbmath.obj &
 $(OBJDIR)\config.obj &
 $(OBJDIR)\from.obj &
 $(OBJDIR)\rel2fido.obj &
 $(OBJDIR)\getput.obj &
 $(OBJDIR)\getspool.obj &
 $(OBJDIR)\import.obj &
 $(OBJDIR)\transadr.obj &
 $(OBJDIR)\misc.obj &
 $(OBJDIR)\parseadr.obj &
 $(OBJDIR)\readhdr.obj &
 $(OBJDIR)\unmime.obj

$(OBJDIR)\arbmath.obj:  arbmath.c
$(OBJDIR)\config.obj:   config.c lib.h import.h ..\lib\exec.h
$(OBJDIR)\from.obj:     from.c
$(OBJDIR)\getput.obj:   getput.c
$(OBJDIR)\getspool.obj: getspool.c
$(OBJDIR)\import.obj:   import.c lib.h import.h
$(OBJDIR)\misc.obj:     misc.c
$(OBJDIR)\parseadr.obj: parseadr.c
$(OBJDIR)\readhdr.obj:  readhdr.c
$(OBJDIR)\rel2fido.obj: rel2fido.c
$(OBJDIR)\transadr.obj: transadr.c
$(OBJDIR)\unmime.obj:   unmime.c

$(OBJS):	gate.h ..\lib\libgate.h ..\fidolib\fidolib.h

$(OBJDIR)\rel2fido.exe: rel2fido.dos $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib
  $(LINK) $(LFLAGS) /"Option stub=rel2fido.dos" /fe=$(OBJDIR)\rel2fido.exe $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib

$(OBJDIR)\rel2fid2.exe: $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib
  $(LINK) $(LFLAGS) /fe=$(OBJDIR)\rel2fid2.exe $(OBJS) ..\lib\lgatep.lib ..\fidolib\flibp.lib

clean:  .SYMBOLIC
  rm -f $(OBJDIR)\*.obj $(OBJDIR)\debug\*.obj
