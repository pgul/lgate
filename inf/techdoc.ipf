.* $Id$
:lines align=center.
:hp2.Как это все работает на техническом уровне:ehp2.
:elines.
:ol.
:li.:link reftype=hd refid='net2uucp'.Netmail FTN->uucp:elink..
:li.:link reftype=hd refid='net2ftn'.Netmail uucp->FTN:elink..
:li.:link reftype=hd refid='echo2uucp'.Echomail FTN->uucp:elink..
:li.:link reftype=hd refid='echo2ftn'.Echomail uucp->FTN:elink..
:eol.

:h2 id='net2uucp'.Netmail FTN->uucp
:p.
Просматривается каталог netmail в поисках *.msg на адрес гейта (если не
указан ключ -nonet), они гейтуются, отправляются через rmail.exe, и
удаляются, если есть KillSent, либо на них ставится Sent, если флага
KillSent нету. Далее просмотривается pktin или binkout (в зависимости
от того, что указано) - это должен быть основной outbound - в поисках
*.pkt и *.out на адрес гейта. Если такие находятся, то письма из этого
pkt-шника, опять-таки, гейтуются, и pkt-шник удаляется. Также удаляются
пустые аттачи на адрес гейта.
:p.
:h2 id='net2ftn'. Netmail uucp->FTN
:p.
Существует два варианта.
:ol.
:li.Через spool системы fidonet.
.br
В конфигах UUPC (в файле systems) описывается виртуальная система fidonet,
и в файле hostpath добавляется строка, например, "*.z2.fidonet.org fidonet".
После этого вся почта на *.z2.fidonet.org кладется в spool на систему fidonet,
а rel2fido выгребает письма из спула, создает pkt (или msg - в зависимоти
от указанного в конфиге) и удаляет письма из спула. Для того, чтобы это
работало, должен быть правильно указан параметр uupcver в gate.cfg, потому
что в разных версиях разные форматы spool. Для версии 6.14e должно быть
указано "uupcver=6".
:li.Через пайп в hostpath.
.br
В файле hostpath пишется строка
:lines.
*.z2.fidonet.org | rel2fido.exe -l -q".
:elines.
.br
В этом случае по приходу каждого письма на *.z2.fidonet.org rmail.exe
вызывает rel2fido.exe, параметрами ему дает адреса отправителя и
получателя, а на stdin скармливает сам текст письма. Это получается
несколько красивее, но нормально работает только начиная с UUPC ver 6.15.
:eol.
:p.

:h2 id='echo2uucp'. Echomail FTN->uucp
:p.
Непакованый echomail (т.е. *.pkt) забирается из outbound (который описан
в gate.cfg как pktin или как binkout) и гейтуется. Далее в зависимости
от ключей в соответствующей строке group происходит одно из трех действий:
:parml compact break=none tsize=2.
:pt.-:pd.письмо через rmail.exe отправляется на mailnews-server;
:pt.-:pd.письмо пакуется в cnews-пакет и через uux.exe (или что указано как
BatchMail в uupc.rc) либо непосредственно отправляется провайдеру, у
которого выполняется команда rnews. Для этого нужна договоренность с
провайдером.
:pt.-:pd.письмо пакуется в cnews-пакет и складывается в определенный каталог
для последующей обработки/отправки. Например, локальным news-server-ом.
:eparml.
:p.

:h2 id='echo2ftn'. Echomail uucp->FTN
:p.
В каталоге, указанном как NewsDir в uupc.rc ищутся cnews-пакеты.
Если найдены - распаковываются и гейтуются.
Потом читается файл uupc\mail\boxes\googate (ну или другой юзер, указанный
как user в gate.cfg, вроде) на предмет писем, пришедших от mailnews-
сервера по feed. Они тоже гейтуются.
В результате получаются *.pkt в каталоге, описанном как pktout в gate.cfg.
:p.
Для того, чтобы это все нормально работало, в конфиге эхопроцессора нужно
описать линк с адресом гейта, и отправлять письма и аттачи на него
непаковаными и со статусом normail (никаких hold, direct, crash, imm и пр.
быть не должно).
:p.
