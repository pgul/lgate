/*
 * $Id$
 *
 * $Log$
 * Revision 2.2  2004/07/20 17:50:59  gul
 * \r\n -> \n
 *
 * Revision 2.1  2001/01/25 18:41:39  gul
 * myname moved to debug.c
 *
 * Revision 2.0  2001/01/10 20:42:22  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include "libgate.h"

int  debuglevel=-1;
int  debuglog=0;
char *myname;

void debug(int level, char *format,...)
{ va_list arg;
  FILE *flog=NULL;
  static char debugname[FNAME_MAX]="";
  int  first=0;
  time_t curtime;
  struct tm *curtm;
#ifdef HAVE_SNPRINTF
  static char *s=NULL;
  static int  ssize=0;
  int i, j;
#endif

  if (level>debuglevel) return;
  va_start(arg, format);
  if (debuglog)
  {
    if (debugname[0]=='\0')
#ifdef UNIX
    { strcpy(debugname, "/var/log/lgatedbg.log");
      first=1;
    }
#else
    { char *p;
      strcpy(debugname, myname);
      p=strrchr(debugname, '\\');
      if (p && strchr(p, '/')) p=strrchr(p, '/');
      if (p) p[1]='\0';
      else debugname[0]='\0';
      strcat(debugname, "lgatedbg.log");
      first=1;
    }
#endif
    flog=fopen(debugname, "a");
    if (flog==NULL)
    { flog=fopen(debugname, "w");
      if (flog==NULL)
      { fprintf(stderr, "Can't open %s: %s\n", debugname, strerror(errno));
        debuglog=0;
        goto tostderr;
      }
    }
    if (first)
    { curtime=time(NULL);
      curtm=localtime(&curtime);
      fprintf(flog,"\n>>> %s started, debug level %d, %s %u %s %02u %02u:%02u:%02u\n",
              copyright, debuglevel, weekday[curtm->tm_wday],
              curtm->tm_mday, montable[curtm->tm_mon],
              curtm->tm_year%100,
              curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
    }
#ifdef HAVE_SNPRINTF
    for (;;)
    { if (ssize==0)
        s=malloc(ssize=80);
      if (s==NULL)
      { fprintf(stderr, "Not enough memory (requested %d bytes)!\n", ssize);
        return;
      }
      sprintf(s, "(%d) ", level);
      i=strlen(s);
      j=vsnprintf(s+i, ssize-i, format, arg);
      if (j>0) j+=i;
      va_end(arg);
      va_start(arg, format);
      if (j<ssize-2)
        break;
      s=realloc(s, ssize+=80);
    }
    if (j<0)
    { fprintf(stderr, "Can't write to debug.log: %s!\n", strerror(errno));
      return;
    }
    if (s[strlen(s)-1]!='\n')
      strcat(s, "\n");
    fputs(s, flog);
#else
    fprintf(flog, "(%d) ", level);
    vfprintf(flog, format, arg);
    va_end(arg);
    va_start(arg, format);
    if (format[strlen(format)-1]!='\n') fputs("\n", flog); 
#endif
    fclose(flog);
  }
tostderr:
#ifdef HAVE_SNPRINTF
  for (;;)
  { if (ssize==0)
      s=malloc(ssize=80);
    if (s==NULL)
    { fprintf(stderr, "Not enough memory (requested %d bytes)!\n", ssize);
      return;
    }
    j=vsnprintf(s, ssize, format, arg);
    va_end(arg);
    va_start(arg, format);
    if (j<ssize-2)
      break;
    s=realloc(s, ssize+=80);
  }
  if (s[strlen(s)-1]!='\n')
    strcat(s, "\n");
  fputs(s, stderr);
#else
  vfprintf(stderr, format, arg);
  if (format[strlen(format)-1]!='\n') fputs("\n", stderr);
#endif
  va_end(arg);
}
