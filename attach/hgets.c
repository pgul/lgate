/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:16  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include "fidolib.h"

unsigned ibuf;
unsigned bufsize=0;
char * buffer;
static unsigned potolok;

static int hgetc(int h)
{
  if (bufsize==0)
    return EOF;
  if ((ibuf==0) || (ibuf==potolok))
  { potolok=read(h, buffer, bufsize);
    ibuf=0;
    if (potolok==0)
      return EOF;
  }
  return buffer[ibuf++];
}

int hgets(char *str, unsigned strsize, int h, char eol)
{
  int i, r;

  for (i=0; i<strsize-1;)
  {
    r=hgetc(h);
    if (r==EOF)
    { str[i]=0;
      return i;
    }
    str[i++]=(char)r;
    if (r==eol)
    { str[i]=0;
      return i;
    }
  }
  str[i]=0;
  return i;
}

long hseek(int h, long offset)
{ long l;

  if (ibuf==0)
    return lseek(h, offset, SEEK_CUR);
  if (((long)ibuf+offset>0) && (ibuf+offset<=potolok))
  { ibuf=(int)(ibuf+offset);
    return lseek(h, 0, SEEK_CUR)-potolok+ibuf;
  }
  l=lseek(h, offset-potolok+ibuf, SEEK_CUR);
  ibuf=0;
  return l;
}
