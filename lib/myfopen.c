/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:50:59  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#ifdef HAVE_SHARE_H
#include <share.h>
#endif

/* это все только из-за share :( */

#if defined(HAVE_SHARE_H) && defined(HAVE_SOPEN)

FILE *myfopen(char *filename, char *sattr)
{
  int  h, attr, shflag;
  FILE *f;

  if (strchr(sattr, 'w'))
  { attr=O_RDWR|O_CREAT;
    shflag=SH_DENYRW;
  }
  else if (strchr(sattr, '+')) /* "r+", "a+" */
  { attr=O_RDWR;
    shflag=SH_DENYWR;
  }
  else
  { attr=O_RDONLY;
    shflag=SH_DENYNO;
  }
  if (strchr(sattr, 'a'))
    attr|=O_APPEND;
  if (strchr(sattr, 'b'))
    attr|=O_BINARY;
  h=sopen(filename, attr, shflag, S_IREAD | S_IWRITE);
  if (h==-1) return NULL;
  if (strchr(sattr, 'w'))
    chsize(h, 0);
  f=fdopen(h, sattr);
  if (f==NULL) close(h);
  return f;
}

#endif
