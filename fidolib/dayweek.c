/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#include <time.h>
#include <string.h>
#include "fidolib.h"

#if 0
int dayweek(int year,int mon,int day)
{ unsigned dow,i;
  /* ой... день недели определяем... */
  dow=(year-80)*(365%7)+(year-80)/4+1;
  if ((year%4==0) && (mon<2))
    dow--;
  for (i=0;i<mon;i++)
    dow+=(daymon[i]%7);
  return (dow+day+1)%7;
}
#else

#ifndef HAVE_MKTIME
#ifdef HAVE_DOS_H
#include <dos.h>
#endif

static time_t mktime(struct tm * ft)
{
   struct date sdate;
   struct time stime;
   struct tm * etm;
   time_t t;

   stime.ti_hund = 0;
   stime.ti_sec  = ft->tm_sec;
   stime.ti_min  = ft->tm_min;
   stime.ti_hour = ft->tm_hour;
   sdate.da_day  = ft->tm_mday;
   sdate.da_mon  = ft->tm_mon+1;
   sdate.da_year = ft->tm_year + 1900;

   t=dostounix(&sdate, &stime);
   etm=gmtime(&t);
   memcpy(ft, etm, sizeof(struct tm));
   return t;
} /* mktime */
#endif

int dayweek(int year,int mon,int day)
{ struct tm etm;

  etm.tm_year=year;
  etm.tm_mon=mon;
  etm.tm_mday=day;
  etm.tm_hour=12;
  etm.tm_min=etm.tm_sec=etm.tm_isdst=0;
  mktime(&etm);
  return etm.tm_wday;
}

#endif
