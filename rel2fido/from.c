/* Check, if the line is start of new message */
/* Returns: 0 - is,
            1 - "From ", but is not,
            2 - left string */
/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:24  gul
 * We are under CVS for now
 *
 */

#include <string.h>
#include <stdio.h>
#include "gate.h"

#define ignorespc(s) for (p=s;(*p==' ')||(*p=='\t');p++);

static int cmatch(char * str,char * mask)
{
  for (;;)
  {
    switch(*mask)
    {
      case 'C':  if (*str!=':')
                   return 1;
                 break;
      case 'D':  if ((*str<'0') || (*str>'9'))
                   return 1;
                 break;
      case 'O':  if ((*str>='0') && (*str<='9'))
                   break;
      case 'S':  if ((*str!=' ') && (*str!='\t'))
                   return 1;
                 break;
      case 'B':  if (*str==0)
                   return 1;
                 return 0;
    }
    str++;
    mask++;
  }
}

int isbeg(char * s)
{
  char * p;
  unsigned day,h,m,se;
  int i;

  if (strncmp(s,"From ",5))
    return 2;
  ignorespc(s+5);
  /* идет адрес */
  p=strpbrk(p," \t");
  if (p==NULL) return 4;
  ignorespc(p+1);
  /* день недели */
  for (i=0;i<7;i++)
    if (strnicmp(weekday[i],p,3)==0)
      break;
  if (i==7) return 2;
  p+=3;
  if ((*p!=' ') && (*p!='\t'))
    return 2;
  ignorespc(p+1);
  /* месяц */
  for (i=0;i<12;i++)
    if (strnicmp(montable[i],p,3)==0)
      break;
  if (i==12) return 2;
  p+=3;
  if ((*p!=' ') && (*p!='\t'))
    return 2;
  p++;
  if (cmatch(p,"ODSDDCDDCDDSB"))
    return 2;
  /* число hh:mm:ss yyyy */
  if (sscanf(p,"%u %u:%u:%u ",&day,&h,&m,&se)!=4)
    return 2;
  if ((day>31)||(day<1)||(h>23)||(m>59)||(se>59))
    return 2;
  return 0;
}
