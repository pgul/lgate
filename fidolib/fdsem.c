/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
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
#include <string.h>
#include <errno.h>
#include "fidolib.h"

#define bsyname _flib_bsyname

extern char bsyname[];

static void getbsyname(ftnaddr * addr,char * path)
{
static char tmpstr[30];
  char * p;
  int  task;

  strcpy(bsyname,path);
  if (bsyname[strlen(bsyname)-1]!=PATHSEP)
    strcat(bsyname,PATHSTR);
  if (addr->point)
    sprintf(tmpstr,"%u:%u/%u.%u",addr->zone,addr->net,addr->node,addr->point);
  else
    sprintf(tmpstr,"%u:%u/%u",addr->zone,addr->net,addr->node);
  p=getenv("task");
  task=0;
  if (p) task=atoi(p);
  sprintf(bsyname+strlen(bsyname),"%08lx.`%x",crc32(tmpstr),task);
}

int SetFDSem(ftnaddr * addr,char * path)
{ int h;

  getbsyname(addr,path);
  if (access(bsyname,0)==0)
    return 1;
  h=open(bsyname,O_BINARY|O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE);
  if (h==-1)
    return 2;
  close(h);
  return 0;
}

int DelFDSem(ftnaddr * addr,char * path)
{ int i;

  getbsyname(addr,path);
  for (i=0; (i<10) && (unlink(bsyname)!=0); i++)
  { if (errno!=EACCES) return 1;
    sleep(1);
  }
  if (i<10) return 0;
  return 1;
}
