/* rexx */

file='d:\tc\work\gate\postavka\history.txt';
tempfile='c:\tmp\history.tmp';

call RxFuncAdd 'SysFileDelete', 'RexxUtil', 'SysFileDelete'

inlist=0;
nver=1;
do while chars(file) > 0
  line = linein(file);
  if left(line,3) = 'ver' then
   do
    ver.nver = word(line,2);
    tver.nver = line;
    nver = nver+1;
    iterate;
   end
  if nver > 1 then
    iterate;
  if line = '' then
   do
    if inlist then
      rc=lineout(tempfile,':eparml.');
    inlist=0;
    iterate;
   end;
  if left(line,1) = ' ' then
   do
    rc=lineout(tempfile,':p.',1);
    call docolon
    rc=lineout(tempfile,line);
    rc=lineout(tempfile,':parml compact break=none tsize=3.');
    inlist=1;
    iterate;
   end;
  tag = word(line,1);
  line = delword(line,1,1);
  call docolon;
  rc=lineout(tempfile, ':pt.' || tag || ':pd.' || line);
end

iver=1;
say ':lines.';
do while iver < nver
  say ":link reftype=hd refid='" || ver.iver || "'." || tver.iver || ':elink.'
  iver = iver+1;
end;
say ':elines.'
say ':p.'

rc=stream(file, 'c', 'close');
rc=stream(tempfile, 'c', 'close');
iver=0;
do while chars(file) > 0
  line = linein(file);
  if left(line, 3) = 'ver' then
   do
    iver = iver+1;
    if iver > 1 then
     do
      prevver = iver-2;
      if prevver > 0 then
       do
        say ":link reftype=hd refid='" || ver.prevver || "'." || 'Prev version (' || ver.prevver || '):elink.'
        say ':p.'
       end;
      say ":link reftype=hd refid='" || ver.iver || "'." || 'Next version (' || ver.iver || '):elink.'
      say ':p.'
     end
    call docolon;
    say ":h2 id='" || word(line,2) || "'." || line
    do while chars(tempfile) > 0
      line = linein(tempfile);
      say line;
    end;
    rc=stream(tempfile,'c','close');
    say ':p.'
    say ':hp2.' || tver.iver || ':ehp2.'
    inlist=0;
    iterate;
   end;
  if iver = 0 then
    iterate;
  if line = '' then
   do
    if inlist then
     do
      say ':eparml.'
      say ':p.'
     end
    inlist=0;
    iterate;
   end;
  if left(line,4) = '    ' then
   do
    line = delstr(line, 1, 4);
    call docolon;
    say line
    iterate;
   end;
  if left(line,2) = '  ' | left(line,3) = ' !!' then
   do
    tag = left(line,3)
    line = delstr(line,1,3)
    if left(line, 1) = ' ' then
      line = delstr(line,1,1)
    call docolon;
    if inlist = 0 then
      say ':parml tsize=5 break=none compact.'
    inlist=1;
    say ':pt.' || tag || ':pd.' || line
    iterate;
   end
end;
if inlist then
 do
  say ':eparml.';
  say ':p.';
 end;
prevver = nver-2;
say ":link reftype=hd refid='" || ver.prevver || "'." || 'Prev version (' || ver.prevver || '):elink.'
say ":p."
rc=SysFileDelete(tempfile);
exit

docolon: procedure expose line
  if left(line,1) = '.' then
    line = '&dot' || line;
  i=0;
  do while i<length(line)
    if substr(line,i+1,1) = '&' then
      line = left(line, i) || '&amp.' || delstr(line,1,i+1)
    if substr(line,i+1,1) = ':' then
      line = left(line, i) || '&colon.' || delstr(line,1,i+1)
    i = i+1;
  end;
return
