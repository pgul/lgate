# $Id$

All:	lgate.inf gate.doc techdoc.txt todo.txt history.txt confer.lst route.cfg badaddr.tpl reject.tpl held.tpl lgate.faq forward.cfg

lgate.inf:	faq.ipf history.ipf lgate.ipf register.ipf sendmail.ipf start.ipf techdoc.ipf todo.ipf
	ipfc lgate.ipf /INF
	ren lgate.INF lgate.inf

history.ipf:	..\history.txt
	hist2ipf.cmd > history.ipf

todo.ipf:	..\todo.txt
	todo2ipf.cmd > todo.ipf

gate.doc:	..\README
	cat ..\README | koi2alt | perl -p -n -e "{ s/INSTALL/start.doc/g; s/gate.conf/gate.cfg/g; if (m@/usr/fnet/([a-z0-9/]+)@) { $$m=$$1; $$p=$$`; $$l=$$'; $$m=~s@/@\\@g; $$_=$$p.'c:\\lgate\\'.$$m.$$l; } s@(c:\\lgate\\[a-z\\]+chk) @$$1.exe @g; s/attuucp([, ])/attuucp.exe$$1/g; s/uucppublic/uupc\\public/g; s/uucico([ ,])/uucico.exe$$1/g; s/uux([ ,])/uux.exe$$1/g; s@/var/mail/@uupc\\mail\\boxes\\@g; }" > gate.doc

techdoc.txt:	..\techdoc.txt
	cat ..\techdoc.txt | koi2alt | perl -p -n -e "{ s/INSTALL/start.doc/g; s/gate.conf/gate.cfg/g; if (m@/usr/fnet/([a-z0-9/]+)@) { $$m=$$1; $$p=$$`; $$l=$$'; $$m=~s@/@\\@g; $$_=$$p.'c:\\lgate\\'.$$m.$$l; } s@(c:\\lgate\\[a-z\\]+chk) @$$1.exe @g; s/attuucp([, ])/attuucp.exe$$1/g; s/uucppublic/uupc\\public/g; s/uucico([ ,])/uucico.exe$$1/g; s/uux([ ,])/uux.exe$$1/g; s@/var/mail/@uupc\\mail\\boxes\\@g; }" > techdoc.txt

todo.txt:	..\todo.txt
	cat ..\todo.txt | koi2alt > todo.txt

history.txt:	..\history.txt
	cat ..\history.txt | koi2alt > history.txt

confer.lst:	..\confer.lst
	cat ..\confer.lst | koi2alt | perl -p -n -e "{ s@/var/spool/news/@c:\\uupc\\news\\@g; }" > confer.lst

route.cfg:	..\route.cfg
	cat ..\route.cfg | koi2alt | perl -p -n -e "{ s@\[home\]/@c:\\fido\\@g; }" > route.cfg

badaddr.tpl:	..\badaddr.tpl
	koi2alt < ..\badaddr.tpl > badaddr.tpl

forward.cfg:	..\forward\forward.cfg
	cat ..\forward\forward.cfg | koi2alt | perl -p -n -e "{ s/INSTALL/start.doc/g; s/gate.conf/gate.cfg/g; if (m@/usr/fnet/([a-z0-9/]+)@) { $$m=$$1; $$p=$$`; $$l=$$'; $$m=~s@/@\\@g; $$_=$$p.'c:\\lgate\\'.$$m.$$l; } s@(c:\\lgate\\[a-z\\]+chk) @$$1.exe @g; s/attuucp([, ])/attuucp.exe$$1/g; s/uucppublic/uupc\\public/g; s/uucico([ ,])/uucico.exe$$1/g; s/uux([ ,])/uux.exe$$1/g; s@/var/mail/@uupc\\mail\\boxes\\@g; }" > forward.cfg

reject.tpl:	..\reject.tpl
	koi2alt < ..\reject.tpl > reject.tpl

held.tpl:	..\held.tpl
	koi2alt < ..\held.tpl > held.tpl

lgate.faq:	..\lgate.faq
	koi2alt < ..\lgate.faq > lgate.faq
