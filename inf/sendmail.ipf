:p.
:lines align=center.
:hp2.��� ���⠢��� ���� ����������⢮���� �� � UUPC,
� � sendmail/2 � � INN/DNEWS/Changi:ehp2.
:elines.
:p.
��� ⮣�, �⮡� ���⠢��� ���� ����������⢮���� � sendmail, � ��
� UUPC, �㦭�:

:ol.
:li.���⠢��� Sendmail 2.02 ��� ����� ᢥ���. � ����� ���묨
sendmail � ����⠫�� �������, �� ��� ᢮�� �������� ��������.
����筮, 2.02 - ⮦� �� ����ப, �� ��祣� ���襣� � �� ��襫. &colon.-(
:li.������ � sendmail.cf ������ ᫥���騬 ��ࠧ��&colon.
:lines.
Mgateway, P=c&colon.\gate\rel2fido.exe, F=lsDFun, S=10, R=0, A=-l a $h $u
:elines.
:p.
��� �ᮡ���� ����� 䫠�� (F=) � ��ࠬ���� (A=).
:li.���ࠢ��� ����� �� *.z2.fidonet.org �� ��� ������. �᫨ ����
�����প� mailertable - �����⥫쭮, �᫨ ��� - �਩����� ��
������ �����।�⢥��� �१ �㫥��. ���ਬ��, � ������� � ����
0-�� �㫥�� ��। ���ࠢ������ �� smtp-������ ��ப�
:lines.
R$+ < @ $+.z2.fidonet.org > $*         $#gateway $@ $2.z2.fidonet.org $&colon. $1
:elines.
:p.
� � ᠬ�� ��砫� 98-�� �㫥�� ��ப�
:lines.
R< $* > $+ < @ $+.z2.fidonet.org >     $#gateway $@ $3.z2.fidonet.org $&colon. $2
:elines.
:p.
��। "$#gateway" ������ ���� ⠡����, � �� �஡��� - �� �����!
:li.� gate.cfg ᪠����
:lines.
uupcver=sendmail
:elines.
:p.
����� �� ��������, ���ਬ��,
:lines.
rmail=c&colon.\tcpip\bin\sendmail.exe -i -odq
:elines.
:li.�᫨ UUPC ᮢᥬ �� ��⠭������, �㦭� �모���� �� gate.cfg
��ப� "uupc=" � �������� ��ப� "domain=" � ��訬 �������
�������.
:eol.
:p.
����⢥���, ��. �뫮 ������ ����� ��ଠ�쭮 室���.
:p.
������ �����. ����� ���� ���� �१ mailnews-�ࢥ� �஢�����,
���� �१ cnews-������ (��।������ ���� �� UUPC �஢������,
���� �����쭮�� news-�ࢥ�� ⨯� INN, DNEWS, Changi etc.).
:p.
�� mailnews �� �ந�室�� ��� � ��ਠ�� UUPC: �㦭� ������
�����쭮�� ���짮��⥫�, 㪠���� ��� ��ࠬ��஬ "user=" �
gate.cfg � �������� ��� feed-�� �� ����㥬� ����७樨.
����� rel2fido �㤥� ࠧ����� ��� mailbox � ���⮢��� ���쬠
���㤠. � gate.cfg �㦭� �������� ��ࠬ��� "MailDir=", � ���஬
������� ��⠫��, ��� ����� ��� mailbox.
�ࠢ��, �� �� ���஢�����. &colon.-(
:p.
� ��砥 �ਥ�� cnews �㦭� ���� ��� ��室��� ����⮢ ����᪠��
rel2fido � ���祬 -r, ���� ᪫��뢠�� �� ������ � �⤥���
��⠫��, 㪠��� ��� ��ࠬ��஬ "NewsDir=" � gate.cfg.
��ࠢ�� cnews-����⮢ ⮦� ����� �ந�室��� ���� ᪫��뢠����
��室��� ����⮢ � 㪠����� � ��ப� group ��⠫��, ���� ��
�室 �ணࠬ��, ���ᠭ��� ��ࠬ��஬ "rnews=" � gate.cfg.
:p.
�����騥 ����� � gate.cfg �������� ��ࠬ���� "local=" (��
�㤥� �⠢���� � "Path&colon." ��室��� ���ᮢ - �� 㬮�砭��
������ �� uupc.rc, ���� �� ��ࠬ��� "domain="),
"ExtSetName=" (�� �㤥� �⠢����� ��ࠬ��஬ charset= �
��������� ��室��� ��ᥬ, �� 㬮�砭�� "koi8-r"),
"IntSetName=" (��� ����७��� ����஢��, �� 㬮�砭�� "x-cp866"),
"ExtCharSet=" (��� 䠩�� � ⠡��楩 ��४���஢�� �� ���譥�
�� ����७���), � ����� ��ࠬ��஢ "charset=", �� 㬮�砭��
:parml compact break=none tsize=40.
:pt.CHARSET=x-cp866:pd. cp866-u.cod
:pt.CHARSET=x-cp866-u:pd. cp866-u.cod
:pt.CHARSET=koi8-r:pd. raw.cod
:pt.CHARSET=x-koi8-u:pd. raw.cod
:pt.CHARSET=us-ascii:pd. raw.cod
:pt.CHARSET=windows-1251:pd. cp1251.cod
:eparml.
:p.
�� ⠡��窨 ���஥��� (�� �� 㪠����� charset � gate.cfg 䠩��
� ⠡��窠�� ������ ������⢮����!).
:p.
��� �࣠����樨 FTN-����� �१ ����� (�� ����� attuucp.exe)
�����筮 � 䠩� %etc%\aliases �������� ��ப�
:lines.
fnet&colon.   "| c&colon./gate/attuucp.exe -l"
:elines.
:p.
��� �ᯮ�짮����� sendmail ����� ��� �� ����ﭭ�� ������祭��
� Internet, � � �⮬ ��砥 ����筥� �ᯮ�짮���� �� attuucp, �,
���ਬ��, binkd. ;)
:p.
���, ᮡ�⢥���, � ��.
:p.
