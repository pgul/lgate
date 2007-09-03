# $Id$
USER = root
GROUP = mail
INSTALL = install

all:	attach/attuucp fido2rel/fido2rel rel2fido/rel2fido forward/forward
attach/attuucp:		fidolib/libfido.a lib/lgate.a attach/Makefile
	cd attach; make; cd ..
rel2fido/rel2fido:	fidolib/libfido.a lib/lgate.a rel2fido/Makefile
	cd rel2fido; make; cd ..
fido2rel/fido2rel:	fidolib/libfido.a lib/lgate.a fido2rel/Makefile
	cd fido2rel; make; cd ..
forward/forward:	fidolib/libfido.a lib/lgate.a forward/Makefile
	cd forward; make; cd ..
lib/lgate.a:		lib/Makefile
	cd lib; make; cd ..
fidolib/libfido.a:	fidolib/Makefile
	cd fidolib; make; cd ..
attach/Makefile:	attach/Makefile.in configure
	./configure
rel2fido/Makefile:	rel2fido/Makefile.in configure
	./configure
fido2rel/Makefile:	fido2rel/Makefile.in configure
	./configure
forward/Makefile:	forward/Makefile.in configure
	./configure
lib/Makefile:		lib/Makefile.in configure
	./configure
fidolib/Makefile:	fidolib/Makefile.in configure
	./configure
minstall:	minstall.in configure
	./configure
configure:		configure.in
	autoconf

install:	attach/attuucp fido2rel/fido2rel rel2fido/rel2fido forward/forward minstall
	USER=${USER} GROUP=${GROUP} INSTALL=${INSTALL} make -f minstall install

update:	attach/attuucp fido2rel/fido2rel rel2fido/rel2fido forward/forward minstall
	USER=${USER} GROUP=${GROUP} INSTALL=${INSTALL} make -f minstall update

clean:
	rm -f rel2fido/*.o fido2rel/*.o attach/*.o fidolib/*.o lib/*.o forwrd/*.o
	rm -f rel2fido/*.err fido2rel/*.err attach/*.err fidolib/*.err lib/*.err forwrd/*.err
	rm -f fidolib/*.a lib/*.a fidolib/*.lib fidolib/*.LIB lib/lgate*.lib lib/lgate*.LIB fidolib/*.bak lib/*.bak
	rm -f rel2fido/OBJ/*.obj rel2fido/obj2/*.obj rel2fido/objemx/*.obj rel2fido/OBJBC/*.obj rel2fido/turboc.cfg rel2fido/bc.cfg
	rm -f fido2rel/OBJ/*.obj fido2rel/OBJ/*.asm fido2rel/obj2/*.obj fido2rel/objemx/*.obj fido2rel/OBJBC/*.obj fido2rel/turboc.cfg fido2rel/bc.cfg
	rm -f attach/OBJ/*.obj   attach/obj2/*.obj   attach/objemx/*.obj   attach/OBJBC/*.obj   attach/turboc.cfg   attach/bc.cfg
	rm -f forward/OBJ/*.obj  forward/obj2/*.obj  forward/objemx/*.obj  forward/OBJBC/*.obj  forward/turboc.cfg  forward/bc.cfg
	rm -f lib/OBJ/*.obj      lib/obj2/*.obj      lib/objemx/*.obj      lib/OBJBC/*.obj      lib/turboc.cfg      lib/bc.cfg
	rm -f fidolib/OBJ/*.obj  fidolib/obj2/*.obj  fidolib/objemx/*.obj  fidolib/OBJBC/*.obj  fidolib/turboc.cfg  fidolib/bc.cfg
	rm -f rel2fido/OBJ/*.OBJ rel2fido/obj2/*.OBJ rel2fido/objemx/*.OBJ rel2fido/OBJBC/*.OBJ rel2fido/TURBOC.CFG rel2fido/BC.CFG
	rm -f fido2rel/OBJ/*.OBJ fido2rel/OBJ/*.ASM fido2rel/obj2/*.OBJ fido2rel/objemx/*.OBJ fido2rel/OBJBC/*.OBJ fido2rel/TURBOC.CFG fido2rel/BC.CFG
	rm -f attach/OBJ/*.OBJ   attach/obj2/*.OBJ   attach/objemx/*.OBJ   attach/OBJBC/*.OBJ   attach/TURBOC.CFG   attach/BC.CFG
	rm -f forward/OBJ/*.OBJ  forward/obj2/*.OBJ  forward/objemx/*.OBJ  forward/OBJBC/*.OBJ  forward/TURBOC.CFG  forward/BC.CFG
	rm -f lib/OBJ/*.OBJ      lib/obj2/*.OBJ      lib/objemx/*.OBJ      lib/OBJBC/*.OBJ      lib/TURBOC.CFG      lib/BC.CFG
	rm -f fidolib/OBJ/*.OBJ  fidolib/obj2/*.OBJ  fidolib/objemx/*.OBJ  fidolib/OBJBC/*.OBJ  fidolib/TURBOC.CFG  fidolib/BC.CFG
	rm -f rel2fido/objemxpl/*.obj fido2rel/objemxpl/*.obj
	rm -f config.cache config.status

cleanall:	configure
	rm -f rel2fido/*.o fido2rel/*.o attach/*.o forward/*.o fidolib/*.o lib/*.o
	rm -f rel2fido/*.err fido2rel/*.err attach/*.err fidolib/*.err lib/*.err forward/*.err
	rm -f fidolib/*.a lib/*.a fidolib/*.lib lib/lgate*.lib fidolib/*.bak lib/*.bak
	rm -f fidolib/*.LIB lib/LGATE*.LIB fidolib/*.BAK lib/*.BAK
	rm -f rel2fido/Makefile fido2rel/Makefile attach/Makefile forward/Makefile
	rm -f lib/Makefile fidolib/Makefile minstall
	rm -f rel2fido/rel2fido fido2rel/fido2rel attach/attuucp forward/forward
	rm -rf rel2fido/obj2 fido2rel/obj2 attach/obj2 lib/obj2 fidolib/obj2 forward/obj2
	rm -rf rel2fido/objemx fido2rel/objemx attach/objemx lib/objemx fidolib/objemx forward/objemx
	rm -rf rel2fido/OBJ fido2rel/OBJ attach/OBJ lib/OBJ fidolib/OBJ forward/OBJ
	rm -rf rel2fido/OBJBC fido2rel/OBJBC attach/OBJBC lib/OBJBC fidolib/OBJBC forward/OBJBC
	rm -rf rel2fido/objemxpl fido2rel/objemxpl
	rm -f rel2fido/*.exe fido2rel/*.exe attach/*.exe forward/*.exe
	rm -f rel2fido/*.EXE fido2rel/*.EXE attach/*.EXE forward/*.EXE
	rm -f fido2rel/*.com attach/*.dos forward/*.dos rel2fido/*.dos
	rm -f fido2rel/*.COM attach/*.DOS forward/*.DOS rel2fido/*.DOS
	rm -f rel2fido/turboc.cfg fido2rel/turboc.cfg attach/turboc.cfg forward/turboc.cfg
	rm -f rel2fido/bc.cfg fido2rel/bc.cfg attach/bc.cfg forward/bc.cfg
	rm -f rel2fido/TURBOC.CFG fido2rel/TURBOC.CFG attach/TURBOC.CFG forward/TURBOC.CFG
	rm -f fidolib/turboc.cfg lib/turboc.cfg fidolib/bc.cfg lib/bc.cfg
	rm -f fidolib/TURBOC.CFG lib/TURBOC.CFG fidolib/BC.CFG lib/BC.CFG
	rm -f rel2fido/BC.CFG fido2rel/BC.CFG attach/BC.CFG forward/BC.CFG
	rm -f rel2fido/rel2fido fido2rel/fido2rel attach/attuucp forward/forward
	rm -f inf/*.inf inf/history.ipf inf/todo.ipf
	rm -f inf/gate.doc inf/techdoc.txt inf/todo.txt inf/history.txt
	rm -f inf/route.cfg inf/confer.lst inf/forward.cfg inf/lgate.faq
	rm -f inf/badaddr.tpl inf/reject.tpl inf/held.tpl
	rm -f config.cache config.status config.log
