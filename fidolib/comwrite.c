/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:58:32  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#include <io.h>
#include <fcntl.h>
#include <dos.h>
#include "fidolib.h"

int comwrite(void * var,unsigned size)
{ unsigned u;
  static int hcom=-2;

  if (hcom==-1)
    return 7;
  if (hcom==-2)
  { hcom=open(_argv[0],O_BINARY|O_RDWR|O_DENYALL);
    if (hcom==-1)
      return 7;
    read(hcom,&u,2);
    if (u==0x5A4D)
    { close(hcom);
      return 9;
    }
  }
  lseek(hcom,(unsigned)var - 0x100,SEEK_SET);
  if (write(hcom,var,size)!=size)
  { close(hcom);
    return 8;
  }
  return 0;
}
