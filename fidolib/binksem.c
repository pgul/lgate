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
/* for mkdir() */
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#if defined(__EMX__) || defined(UNIX)
#define mkdir(name) mkdir(name, 750)
#endif
#include "fidolib.h"

#define bsyname _flib_bsyname

extern char bsyname[128];

char * GetBinkBsyName(ftnaddr * addr,char * path,uword zone)
{ char * p;

  strcpy(bsyname,path);
  if (bsyname[strlen(bsyname)-1]!=PATHSEP)
    strcat(bsyname,PATHSTR);
  if (addr->zone!=zone)
  { *strrchr(bsyname,PATHSEP)=0;
    p=strrchr(bsyname,PATHSEP);
    if (p==NULL) return NULL;
    p=strchr(p,'.');
    if (p==NULL) p=bsyname+strlen(bsyname);
    sprintf(p,".%03X",addr->zone);
    mkdir(bsyname);
    strcat(p,PATHSTR);
  }
  p=bsyname+strlen(bsyname);
  sprintf(p,"%04x%04x.",addr->net,addr->node);
  if (addr->point==0)
  { strcat(p,"bsy");
    return bsyname;
  }
  strcat(p,"pnt");
  mkdir(bsyname);
  sprintf(bsyname+strlen(bsyname), PATHSTR "%08x.bsy",addr->point);
  return bsyname;
}

int SetBinkSem(ftnaddr * addr,char * path,uword zone)
{
  int  h;
#if 0
  int  task;
  char * p;
  static char tmpname[128];

  if (GetBinkBsyName(addr,path,zone)==NULL)
    return 2;
  if (access(bsyname,0)==0)
    return 1;
  strcpy(tmpname,bsyname);
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
  if (GetBinkBsyName(addr,path,zone)==NULL)
    return 2;
  if (access(bsyname,0)==0)
    return 1;
  if ((h=open(bsyname,O_BINARY|O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE))==-1)
    return 1;
  close(h);
#endif
  return 0;
}

int DelBinkSem(ftnaddr * addr,char * path,uword zone)
{ int i;

  if (GetBinkBsyName(addr,path,zone)==NULL)
    return 1;
  for (i=0; (i<10) && (unlink(bsyname)!=0); i++)
  { if (errno!=EACCES) return 1;
    sleep(1);
  }
  if (i<10) return 0;
  return 1;
}
