/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "fidolib.h"

int copyfile(char *from, char *to)
{ int fin, fout, r;
  char buf[1024];
  char *buffer;
  int bufsize=16384;

  if (access(to, 0)==0)
    return 1;
  fin=open(from, O_BINARY|O_RDWR);
  if (fin==-1) return 1;
  fout=open(to, O_BINARY|O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
  if (fout==-1)
  { close(fin);
    return 2;
  }
  buffer=malloc(bufsize);
  if (buffer==NULL)
  { buffer=buf;
    bufsize=sizeof(buf);
  }
  while ((r=read(fin,buffer,bufsize))==bufsize)
    if (write(fout,buffer,r)!=r)
    { close(fin);
      close(fout);
      unlink(to);
      if (buffer!=buf) free(buffer);
      return 3;
    }
  if (r)
    if (write(fout,buffer,r)!=r)
    { close(fin);
      close(fout);
      unlink(to);
      if (buffer!=buf) free(buffer);
      return 4;
    }
  close(fin);
  close(fout);
  if (buffer!=buf) free(buffer);
  return 0;
}
