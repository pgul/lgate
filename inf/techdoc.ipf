.* $Id$
:lines align=center.
:hp2.��� �� �� ࠡ�⠥� �� �孨�᪮� �஢��:ehp2.
:elines.
:ol.
:li.:link reftype=hd refid='net2uucp'.Netmail FTN->uucp:elink..
:li.:link reftype=hd refid='net2ftn'.Netmail uucp->FTN:elink..
:li.:link reftype=hd refid='echo2uucp'.Echomail FTN->uucp:elink..
:li.:link reftype=hd refid='echo2ftn'.Echomail uucp->FTN:elink..
:eol.

:h2 id='net2uucp'.Netmail FTN->uucp
:p.
��ᬠ�ਢ����� ��⠫�� netmail � ���᪠� *.msg �� ���� ���� (�᫨ ��
㪠��� ���� -nonet), ��� ���������, ��ࠢ������ �१ rmail.exe, �
㤠������, �᫨ ���� KillSent, ���� �� ��� �⠢���� Sent, �᫨ 䫠��
KillSent ����. ����� ��ᬮ�ਢ����� pktin ��� binkout (� ����ᨬ���
�� ⮣�, �� 㪠����) - �� ������ ���� �᭮���� outbound - � ���᪠�
*.pkt � *.out �� ���� ����. �᫨ ⠪�� ��室����, � ���쬠 �� �⮣�
pkt-譨��, �����-⠪�, ���������, � pkt-譨� 㤠�����. ����� 㤠������
����� ���� �� ���� ����.
:p.
:h2 id='net2ftn'. Netmail uucp->FTN
:p.
������� ��� ��ਠ��.
:ol.
:li.��१ spool ��⥬� fidonet.
.br
� ���䨣�� UUPC (� 䠩�� systems) ����뢠���� ����㠫쭠� ��⥬� fidonet,
� � 䠩�� hostpath ���������� ��ப�, ���ਬ��, "*.z2.fidonet.org fidonet".
��᫥ �⮣� ��� ���� �� *.z2.fidonet.org �������� � spool �� ��⥬� fidonet,
� rel2fido ��ॡ��� ���쬠 �� �㫠, ᮧ���� pkt (��� msg - � ����ᨬ��
�� 㪠������� � ���䨣�) � 㤠��� ���쬠 �� �㫠. ��� ⮣�, �⮡� ��
ࠡ�⠫�, ������ ���� �ࠢ��쭮 㪠��� ��ࠬ��� uupcver � gate.cfg, ��⮬�
�� � ࠧ��� ������ ࠧ�� �ଠ�� spool. ��� ���ᨨ 6.14e ������ ����
㪠���� "uupcver=6".
:li.��१ ���� � hostpath.
.br
� 䠩�� hostpath ������ ��ப�
:lines.
*.z2.fidonet.org | rel2fido.exe -l -q".
:elines.
.br
� �⮬ ��砥 �� ��室� ������� ���쬠 �� *.z2.fidonet.org rmail.exe
��뢠�� rel2fido.exe, ��ࠬ��ࠬ� ��� ���� ���� ��ࠢ�⥫� �
�����⥫�, � �� stdin ᪠ଫ����� ᠬ ⥪�� ���쬠. �� ����砥���
��᪮�쪮 ��ᨢ��, �� ��ଠ�쭮 ࠡ�⠥� ⮫쪮 ��稭�� � UUPC ver 6.15.
:eol.
:p.

:h2 id='echo2uucp'. Echomail FTN->uucp
:p.
���������� echomail (�.�. *.pkt) ����ࠥ��� �� outbound (����� ���ᠭ
� gate.cfg ��� pktin ��� ��� binkout) � ��������. ����� � ����ᨬ���
�� ���祩 � ᮮ⢥�����饩 ��ப� group �ந�室�� ���� �� ��� ����⢨�:
:parml compact break=none tsize=2.
:pt.-:pd.���쬮 �१ rmail.exe ��ࠢ����� �� mailnews-server;
:pt.-:pd.���쬮 ������� � cnews-����� � �१ uux.exe (��� �� 㪠���� ���
BatchMail � uupc.rc) ���� �����।�⢥��� ��ࠢ����� �஢������, �
���ண� �믮������ ������� rnews. ��� �⮣� �㦭� ������७����� �
�஢����஬.
:pt.-:pd.���쬮 ������� � cnews-����� � ᪫��뢠���� � ��।������ ��⠫��
��� ��᫥���饩 ��ࠡ�⪨/��ࠢ��. ���ਬ��, ������� news-server-��.
:eparml.
:p.

:h2 id='echo2ftn'. Echomail uucp->FTN
:p.
� ��⠫���, 㪠������ ��� NewsDir � uupc.rc ������ cnews-������.
�᫨ ������� - �ᯠ���뢠���� � ���������.
��⮬ �⠥��� 䠩� uupc\mail\boxes\googate (�� ��� ��㣮� �, 㪠�����
��� user � gate.cfg, �த�) �� �।��� ��ᥬ, ��襤�� �� mailnews-
�ࢥ� �� feed. ��� ⮦� ���������.
� १���� ��������� *.pkt � ��⠫���, ���ᠭ��� ��� pktout � gate.cfg.
:p.
��� ⮣�, �⮡� �� �� ��ଠ�쭮 ࠡ�⠫�, � ���䨣� �宯����� �㦭�
������ ���� � ���ᮬ ����, � ��ࠢ���� ���쬠 � ���� �� ����
���������묨 � � ����ᮬ normail (������� hold, direct, crash, imm � ��.
���� �� ������).
:p.
