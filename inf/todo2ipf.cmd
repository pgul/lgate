/* rexx */

/*
 * $Id$
*/

file='todo.txt'

inlist=0;
do while chars(file) > 0
  line=linein(file);
  if line = '' then
   do
    if inlist then
      say ':eparml.'
    say ':p.'
    inlist=0;
    iterate;
   end;
  if left(line,1) = ' ' then
   do
    do while left(line,1) = ' '
      line = delstr(line, 1, 1);
    end;
    tag = '';
   end;
  else
   do
    if inlist = 0 then
      say ':parml tsize=2 break=none compact.'
    inlist=1;
    tag=word(line,1);
    line=delword(line,1,1);
   end
  /* меняем ':' -> '&colon.' */
  i=0;
  do while i<length(line)
    if substr(line,i+1,1) = '&' then
      line = left(line, i) || '&amp.' || delstr(line,1,i+1)
    if substr(line,i+1,1) = ':' then
      line = left(line, i) || '&colon.' || delstr(line,1,i+1)
    i = i+1;
  end;
  if tag = '' then
    say line
  else
    say ':pt.' || tag || ':pd.' || line
end
if inlist then
  say ':eparml.'
