/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:50:59  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:22  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include "libgate.h"

int getmytz(char * str,int * tz)
{ char * p;
  int  i,day;
  long times,timew,curtim;
  int  mons,monw,weeks,weekw,days,dayw,shift;
  time_t curtime;
  struct tm * curtm;

  for (p=str;*p && !isdigit(*p) && (*p!='+') && (*p!='-');p++);
  if (*p=='\0') return 1;
  i=atoi(p);
  if ((i<=-24) || (i>=24))
    return 1;
  *tz=i;
  /* summer time? */
  for (p++;isdigit(*p) || (*p==':');p++);
  if (*p=='\0') return 0;
  shift=1;
  mons=3;  /* march */
  monw=10; /* october */
  weeks=weekw=-1;
  days=dayw=0;
  times=timew=7200;
  for (;isalpha(*p);p++);
  if (*p=='\0') goto doshift;
  if ((*p=='+') || (*p=='-') || isdigit(*p))
  { shift=*tz-atoi(p);
    for (p++;isdigit(*p);p++);
    if (*p=='\0') goto doshift;
  }
  if ((*p!=',') && (*p!=';'))
    goto doshift;
  p++;
  if (tolower(*p)=='m') p++;
  if (!isdigit(*p)) goto doshift;
  i=atoi(p);
  if ((i<1) || (i>=12)) goto doshift;
  mons=i;
  for (p++;isdigit(*p);p++);
  if ((*p!=',') && (*p!='.')) goto doshift;
  p++;
  if ((*p!='-') && (*p!='+') && !isdigit(*p)) goto doshift;
  i=atoi(p);
  if ((i<-5) || (i>5)) goto doshift;
  weeks=i;
  for (p++;isdigit(*p);p++);
  if ((*p!=',') && (*p!='.')) goto doshift;
  p++;
  if ((*p!='-') && (*p!='+') && !isdigit(*p)) goto doshift;
  i=atoi(p);
  if ((i<0) || (i>6)) goto doshift;
  days=i;
  for (p++;isdigit(*p);p++);
  if ((*p!=',') && (*p!='.') && (*p!='/')) goto doshift;
  p++;
  if (!isdigit(*p)) goto doshift;
  times=i=atoi(p);
  for (p++;isdigit(*p);p++);
  if (*p==':')
  { if (i>=24) goto doshift;
    p++;
    if (!isdigit(*p)) goto doshift;
    times=i*3600;
    i=atoi(p);
    if (i>=60) goto doshift;
    times+=i*60;
    for (p++;isdigit(*p);p++);
  }
  else if (times<24) times*=3600;
  if (*p!=',') goto doshift;
  p++;
  if (tolower(*p)=='m') p++;
  if (!isdigit(*p)) goto doshift;
  i=atoi(p);
  if ((i<1) || (i>=12)) goto doshift;
  monw=i;
  for (p++;isdigit(*p);p++);
  if ((*p!=',') && (*p!='.')) goto doshift;
  p++;
  if ((*p!='-') && (*p!='+') && !isdigit(*p)) goto doshift;
  i=atoi(p);
  if ((i<-5) || (i>5)) goto doshift;
  weekw=i;
  for (p++;isdigit(*p);p++);
  if ((*p!=',') && (*p!='.')) goto doshift;
  p++;
  if ((*p!='-') && (*p!='+') && !isdigit(*p)) goto doshift;
  i=atoi(p);
  if ((i<0) || (i>6)) goto doshift;
  dayw=i;
  for (p++;isdigit(*p);p++);
  if ((*p!=',') && (*p!='.') && (*p!='/')) goto doshift;
  p++;
  if (!isdigit(*p)) goto doshift;
  timew=i=atoi(p);
  for (p++;isdigit(*p);p++);
  if (*p==':')
  { if (i>=24) goto doshift;
    p++;
    if (!isdigit(*p)) goto doshift;
    timew=i*3600;
    i=atoi(p);
    if (i>=60) goto doshift;
    timew+=i*60;
    for (p++;isdigit(*p);p++);
  }
  else if (timew<24) timew*=3600;
  if (*p!=',') goto doshift;
  p++;
  if ((*p!='+') && (*p!='-') && !isdigit(*p)) goto doshift;
  shift=atoi(p);
  if ((shift>=24) || (shift<=-24))
    shift/=3600;
doshift:
  /* ohh... %-( */
  if (mons>=monw) return 0; /* impossible */
  curtime=time(NULL);
  curtm=localtime(&curtime);
  if ((curtm->tm_mon+1<mons) || (curtm->tm_mon+1>monw))
    return 0;
  if ((curtm->tm_mon+1>mons) && (curtm->tm_mon+1<monw))
  { *tz-=shift;
    return 0;
  }
  if (weeks==5) weeks=-1;
  if (weekw==5) weekw=-1;
  if (weeks==-5) weeks=1;
  if (weekw==-5) weekw=1;
  i=curtm->tm_wday;
  curtim=curtm->tm_hour*3600l+curtm->tm_min*60+curtm->tm_sec;
  if (curtm->tm_mon+1==mons)
  { for (day=1;i!=days;day++) i=(i+1)%7;
    if (weeks<0)
    { for (;day+7<daymon[mons-1];day+=7);
      for (;weeks<-1;weeks++) day-=7;
    }
    else
      for (;weeks>1;weeks--) day+=7;
    if (curtm->tm_mday<day) return 0;
    if (curtm->tm_mday>day)
    { *tz-=shift;
      return 0;
    }
    if (curtim<times) return 0;
    *tz-=shift;
    return 0;
  }
  for (day=1;i!=dayw;day++) i=(i+1)%7;
  if (weekw<0)
  { for (;day+7<daymon[monw-1];day+=7);
    for (;weekw<-1;weekw++) day-=7;
  }
  else
    for (;weekw>1;weekw--) day+=7;
  if (curtm->tm_mday>day) return 0;
  if (curtm->tm_mday<day)
  { *tz-=shift;
    return 0;
  }
  if (curtim>times) return 0;
  *tz-=shift;
  return 0;
}
