#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_DOS_H
#include <dos.h> /* for sleep() */
#endif
#include "fidolib.h"

#define WAITSTATE 10 /* 0.5 sec */
#define MAXTRIES  10 /* 10*1=10 sec ждем, после чего сваливаемся */

int myopen(char * filename,unsigned attr)
{
  int i,h;

  for (i=0;;i++)
  { h=open(filename,attr,S_IREAD|S_IWRITE);
    if (h!=-1) return h;
    if (errno!=EACCES) return h; /* permission denied */
    if (i==MAXTRIES) return h;
#ifdef __MSDOS__
    dvdelay(WAITSTATE);
#else
    sleep((WAITSTATE+9)/10);
#endif
  }
}
