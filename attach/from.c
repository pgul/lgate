/* Check, if the line is start of new message */
/* Returns: 0 - is,
            1 - "From ", but is not,
            2 - left string */
/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:16  gul
 * We are under CVS for now
 *
 */

#include <string.h>
#include <stdio.h>
#include <fidolib.h>

#define ignorespc(s) for (p=s; (*p==' ') || (*p=='\t'); p++);

int isbeg(char *s)
{
  char *p;
  unsigned day, h, m, se, year;
  int i;

  if (strncmp(s, "From ", 5))
    return 2;
  /* special for rel2fido */
  p=strchr(s, '\r');
  if (p) *p='\n';
  ignorespc(s+5);
  /* идет адрес */
  p=strpbrk(p, " \t");
  if (p==NULL) return 4;
  ignorespc(p+1);
  /* день недели */
  for (i=0; i<7; i++)
    if (strncmp(weekday[i], p, 3)==0)
      break;
  if (i==7) return 2;
  p+=3;
  if ((*p!=' ') && (*p!='\t'))
    return 2;
  ignorespc(p+1);
  /* месяц */
  for (i=0; i<12; i++)
    if (strncmp(montable[i], p, 3)==0)
      break;
  if (i==12) return 2;
  p+=3;
  if ((*p!=' ') && (*p!='\t'))
    return 2;
  ignorespc(p+1);
  /* число hh:mm:ss yyyy */
  if (sscanf(p, "%u %u:%u:%u %u\n", &day, &h, &m, &se, &year)!=5)
    return 2;
  if ((day>31) || (day<1) || (h>23) || (m>59) || (se>59))
    return 2;
  if (year>1900) year-=1900;
/*
  if ((year<80) || (year>96))
    return 2;
*/
  return 0;
}
