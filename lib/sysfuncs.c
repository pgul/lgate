/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2002/03/21 11:29:15  gul
 * Cosmetic changes
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#ifdef __OS2__
#define INCL_DOSPROCESS
#include <os2.h>
#endif
#include "libgate.h"

#ifndef HAVE_STRUPR
char *strupr(char *s)
{ char *p;
  for (p=s; *p; *p++=toupper(*p));
  return s;
}

char *strlwr(char *s)
{ char *p;
  for (p=s; *p; *p++=tolower(*p));
  return s;
}
#endif

#if defined(__OS2__)
void dvdelay(unsigned decsec)
{
  DosSleep(decsec*100);
}
#elif defined(UNIX)
void dvdelay(unsigned decsec)
{
  struct timeval tv;
  tv.tv_sec=0;
  tv.tv_usec=decsec*100000;
  select(0, NULL, NULL, NULL, &tv);
}
#endif

#ifdef __WATCOMC__
int kill(pid_t pid, int sig)
{
  return DosKillProcess(DKP_PROCESSTREE, (PID)pid);
}

int waitpid(pid_t pid, int *status, int options)
{ pid_t wpid;
  RESULTCODES res;

  if (DosWaitChild(DCWA_PROCESSTREE,
      (options & WNOHANG) ? DCWW_NOWAIT : DCWW_WAIT, &res, (PPID)&wpid, (PID)pid))
    return 0;
  *status=((res.codeResult & 0xff) << 8) | (res.codeTerminate & 0xff);
  return (int)wpid;
}
#endif

#ifndef HAVE_FILELENGTH
unsigned long filelength(int h)
{
  unsigned long curseek=lseek(h, 0, SEEK_CUR), filelen;
  filelen=lseek(h, 0, SEEK_END);
  lseek(h, curseek, SEEK_SET);
  return filelen;
}
#endif

#if !defined(HAVE_STRICMP) && !defined(HAVE_STRCASECMP)
int stricmp(char *s1, char *s2)
{
  while (*s1 && *s2)
  {
    if (toupper(*s1)<toupper(*s2)) return -1;
    if (toupper(*s1)>toupper(*s2)) return 1;
  }
  if (*s1) return 1;
  if (*s2) return -1;
  return 0;
}
#endif

#if !defined(HAVE_STRNICMP) && !defined(HAVE_STRNCASECMP)
int strnicmp(char *s1, char *s2, int n)
{
  while (*s1 && *s2 && n--)
  {
    if (toupper(*s1)<toupper(*s2)) return -1;
    if (toupper(*s1)>toupper(*s2)) return 1;
  }
  if (n==0) return 0;
  if (*s1) return 1;
  if (*s2) return -1;
  return 0;
}
#endif

#ifndef HAVE_BASENAME
char *basename(char *fname)
{
  char *p;

  if (fname==NULL) return NULL;
  for (p=fname; *p; p++)
  {
    if ((*p=='/')
#ifndef UNIX_
        || (*p=='\\') || (*p==':')
#endif
        )
      fname=p+1;
  }
  return fname;
}
#endif

#ifndef HAVE_MKTIME
time_t mktime(struct tm *ft)
{
   struct date sdate;
   struct time stime;
   struct tm *etm;
   time_t t;

#if 1
   while (ft->tm_sec<0)   ft->tm_sec+=60, ft->tm_min--;
   while (ft->tm_sec>59)  ft->tm_sec-=60, ft->tm_min++;
   while (ft->tm_min<0)   ft->tm_min+=60, ft->tm_hour--;
   while (ft->tm_min>59)  ft->tm_min-=60, ft->tm_hour++;
   while (ft->tm_hour<0)  ft->tm_hour+=60,ft->tm_mday--;
   while (ft->tm_hour>59) ft->tm_hour-=60,ft->tm_mday++;
   while (ft->tm_mday<1)  ft->tm_mon--, ft->tm_mday+=daymon[ft->tm_mon%12];
   while (ft->tm_mday>daymon[ft->tm_mon%12] && ft->tm_mday!=29) /* known bug */
     ft->tm_mday-=daymon[ft->tm_mon%12],ft->tm_mon++;
   while (ft->tm_mon<0)   ft->tm_mon+=12, ft->tm_year--;
   while (ft->tm_mon>11)  ft->tm_mon-=12, ft->tm_year++;
#endif

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
} /* dos2unix */
#endif

#if !defined(HAVE_UTIME_H) && !defined(HAVE_SYS_UTIME_H)
#include "utime.h"

int utime(char *path, struct utimbuf *times)
{
  struct ftime ft;
  struct tm *ftm;
  int h, r;

  ftm=localtime(&times->modtime);
  h=open(path, O_RDWR|O_DENYNONE);
  if (h==-1) return -1;
  ft.ft_tsec=ftm->tm_sec/2;
  ft.ft_min=ftm->tm_min;
  ft.ft_hour=ftm->tm_hour;
  ft.ft_day=ftm->tm_mday;
  ft.ft_month=ftm->tm_mon;
  ft.ft_year=ftm->tm_year-80;
  r=setftime(h, &ft);
  close(h);
  return r;
}
#endif
