#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include "fidolib.h"

int move(char *oldname, char *newname)
{
  if (access(newname, 0)==0)
    return 1;
#ifdef UNIX
#ifdef HAVE_LINK
  if (link(oldname, newname)==0)
  { if (unlink(oldname))
    { if (access(oldname, 0))
        return 0;
      unlink(newname);
      return 1;
    }
    return 0;
  }
#else
  { int fout=open(newname, O_BINARY|O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
    if (fout==-1)
      return 1;
    close(fout);
  }
  if (rename(oldname, newname)==0)
    return 0;
  unlink(newname);
#endif
#else
  if (rename(oldname, newname)==0)
    return 0;
#endif
  if (copyfile(oldname, newname))
    return 1;
  if (unlink(oldname))
  { if (access(oldname, 0))
      return 0;
    unlink(newname);
    return 1;
  }
  return 0;
}
