/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:20  gul
 * We are under CVS for now
 *
 */
#include <string.h>
#include <stdio.h>
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
#include <stdlib.h>
#include <errno.h>
#include "fidolib.h"

#define bsyname _flib_bsyname

extern char bsyname[128];

char * GetLBSOBsyName(ftnaddr *addr, char *domain, char *path)
{
  strcpy(bsyname,path);
  if (bsyname[strlen(bsyname)-1]!=PATHSEP)
    strcat(bsyname,PATHSTR);
  if (domain && domain[0])
  { strcat(bsyname, domain);
    strcat(bsyname, ".");
  }
  sprintf(bsyname+strlen(bsyname), "%u.%u.%u.%u.Busy",
          addr->zone, addr->net, addr->node, addr->point);
  return bsyname;
}

int SetLBSOSem(ftnaddr *addr, char *domain, char *path)
{
  int  h;
#if 0
  int  task;
  char *p;
  static char tmpname[1024];

  if (GetLBSOBsyName(addr,domain,path)==NULL)
    return 2;
  if (access(bsyname, 0)==0)
    return 1;
  strcpy(tmpname, bsyname);
  task=0;
  p=getenv("task");
  if (p)
    task=atoi(p);
  p=strrchr(tmpname,'.')+1;
  for (sprintf(p,"%u",task);access(bsyname,0)==0;sprintf(p,"%u",task))
    task++;
  h=open(tmpname,O_BINARY|O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE);
  if (h==-1)
  { unlink(tmpname);
    return 1;
  }
  close(h);
  if (rename(tmpname,bsyname))
  { unlink(tmpname);
    return 1;
  }
#else
  if (GetLBSOBsyName(addr,domain,path)==NULL)
    return 2;
  if (access(bsyname, 0)==0)
    return 1;
  if ((h=open(bsyname,O_BINARY|O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE))==-1)
    return 1;
  close(h);
#endif  
  return 0;
}

int DelLBSOSem(ftnaddr *addr, char *domain, char *path)
{ int i;

  if (GetLBSOBsyName(addr,domain,path)==NULL)
    return 1;
  for (i=0; (i<10) && (unlink(bsyname)!=0); i++)
  { if (errno!=EACCES) return 1;
    sleep(1);
  }
  if (i<10) return 0;
  return 1;
}
