/*
 * $Id$
 *
 * $Log$
 * Revision 2.3  2001/11/15 12:28:28  gul
 * always put date/time if logstyle==FD_LOG
 *
 * Revision 2.2  2001/01/25 13:14:09  gul
 * quiet var moved to logwrite.c
 *
 * Revision 2.1  2001/01/15 03:37:09  gul
 * Stack overflow in dos-version fixed.
 * Some cosmetic changes.
 *
 * Revision 2.0  2001/01/10 20:42:22  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <time.h>
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include <stdlib.h>
#include "libgate.h"

#define SLOGSIZE  2048

char logname[256]="";
char copyright[256]="";
char loglevel[32]="-$~`&^@=>%#!?*";
logtype logstyle = FD_LOG;
int quiet=0;

void logwrite(char level, char *format,...)
{ va_list arg;
  int flog;
  static int firstlog=1;
  static char *slog=NULL;
  time_t curtime;
  struct tm *curtm;
  char *module, *p;

  curtime=time(NULL);
  curtm=localtime(&curtime);
  if (strstr(copyright, "(Att"))
    module="ATTU";
  else if (strstr(copyright, "(Fid"))
    module="F2UU";
  else
    module="UU2F";
  if (slog==NULL)
  {
    slog = malloc(SLOGSIZE);
    if (slog==NULL)
    { 
      fputs("Can't write to log, not enough memory:\n", stderr);
      va_start(arg, format);
      vfprintf(stderr, format, arg);
      va_end(arg);
      return;
    }
  }
  if (firstlog && strchr(loglevel, level))
  { firstlog=0;
    if (logstyle == FD_LOG)
      logwrite('*', "\n-----------  %s %u %s %02u,  %s\n",
        weekday[curtm->tm_wday], curtm->tm_mday, 
        montable[curtm->tm_mon], curtm->tm_year+1900, copyright);
#ifdef HAVE_SYSLOG_H
    else if (logstyle == SYSLOG_LOG)
    { openlog(module, LOG_PID, LOG_USER);
      logname[0]='\0';
      flog=1;
    }
#endif
  }
  va_start(arg, format);
  slog[0]='\0';
  if (logname[0] && (strchr(loglevel, level) || level=='*'))
  {
    if (access(logname, 0))
      flog=myopen(logname, O_TEXT|O_RDWR|O_CREAT);
    else
      flog=myopen(logname, O_TEXT|O_RDWR|O_APPEND);
    if (flog==-1)
    { fputs("Can't write to log:\n", stderr);
      vfprintf(stderr, format, arg);
      va_end(arg);
      debug(0, "Can't write to log:");
#ifdef HAVE_SNPRINTF
      vsnprintf(slog, SLOGSIZE, format, arg);
#else
      vsprintf(slog, format, arg);
#endif
      debug(0, slog);
      return;
    }
    if (level!='*')
    { if (logstyle == FD_LOG)
        sprintf(slog, "%c  %02u:%02u:%02u  ", level,
                curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
      else
        sprintf(slog, "%c %2d %s %02u:%02u:%02u %s ", level,
                curtm->tm_mday, montable[curtm->tm_mon],
                curtm->tm_hour, curtm->tm_min, curtm->tm_sec, module);
    }
  }
  else
    flog=-1;
  p=slog+strlen(slog);
#ifdef HAVE_SNPRINTF
  vsnprintf(p, SLOGSIZE-(p-slog),
#else
  vsprintf(p,
#endif
            format, arg);
  if (flog!=-1)
  {
#ifdef HAVE_SYSLOG_H
    if (logstyle==SYSLOG_LOG)
    { int syslog_level;
      switch (level)
      { case '?': syslog_level=LOG_ERR;     break;
        case '!': syslog_level=LOG_WARNING; break;
        case '$': syslog_level=LOG_NOTICE;  break;
        case '-': syslog_level=LOG_DEBUG;   break;
        default:  syslog_level=LOG_INFO;    break;
      }
      syslog(syslog_level, "%s", slog);
    }
    else
#endif
    { write(flog, slog, strlen(slog));
      close(flog);
    }
  }
  va_end(arg);
  if (level!='*')
  { if (((level!='?') && (!quiet) && (debuglevel<2)) ||
        ((level=='?') && (debuglevel<0)))
      fputs(p, stderr);
    debug((level=='?') ? 0 : 2, "%s", p);
  }
}
