#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#if defined(HAVE_UTIME_H)
#include <utime.h>
#elif defined(HAVE_SYS_UTIME_H)
#include <sys/utime.h>
#endif
#include "fidolib.h"

#if !defined(HAVE_UTIME_H) && !defined(HAVE_SYS_UTIME_H)

struct utimbuf
{
        time_t  actime;         /* access time (not used on DOS) */
        time_t  modtime;        /* modification time */
};

static int utime(char * path, struct utimbuf * times)
{
  struct ftime ft;
  struct tm * ftm;
  int h, r;

  ftm=localtime(&times->modtime);
  h=open(path,O_RDWR);
  if (h==-1) return -1;
  ft.ft_tsec=ftm->tm_sec/2;
  ft.ft_min=ftm->tm_min;
  ft.ft_hour=ftm->tm_hour;
  ft.ft_day=ftm->tm_mday;
  ft.ft_month=ftm->tm_mon;
  ft.ft_year=ftm->tm_year-80;
  r=setftime(h,&ft);
  close(h);
  return r;
}
#endif

int touch (char *file)
{
  struct utimbuf utb;
  int i;

  if (access(file,0))
  { i=open(file,O_RDWR|O_CREAT,S_IREAD|S_IWRITE);
    if (i==-1)
      return -1;
    close(i);
    return 0;
  }
  else
  { utb.actime = utb.modtime = time(0);
    return utime (file, &utb);
  }
}
