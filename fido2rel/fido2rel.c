/* Scan NetMail */
/* find unsend msgs to myaddr with names contains '@' and "uucp" */
/* send its, remove and write to log */
/* split long lines with smart process quoting (2nd pass) */
/* insert '>' before "From " in beginnig of lines (2nd pass) */
/* deny binary data (optional), */
/* msgs to specified addresses (except from privel users) */
/* change some addresses (for example, my ;) */
/* encoding fileattaches to MIME (base64) (optional) */

/*
 * $Id$
 *
 * $Log$
 * Revision 2.5  2004/07/20 18:47:18  gul
 * \r\n -> \n
 *
 * Revision 2.4  2003/02/16 09:41:57  gul
 * bugfix: sometimes extra NUL-bytes occured at the end of pkt
 *
 * Revision 2.3  2002/01/15 18:48:37  gul
 * Remove nkillattfiles=32 limitation
 *
 * Revision 2.2  2001/01/19 17:55:17  gul
 * Cosmetic changes
 *
 * Revision 2.1  2001/01/15 03:37:09  gul
 * Stack overflow in dos-version fixed.
 * Some cosmetic changes.
 *
 * Revision 2.0  2001/01/10 20:42:17  gul
 * We are under CVS for now
 *
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include <time.h>
#include "gate.h"

void term(int signo);

extern int  retcode, frescan;
struct attfiletype *killattfiles;
int nkillattfiles=0;
unsigned long mypid;

static void killtmpatt(void)
{ int i;

  if (getpid() != mypid) return;
  for (i=0; i<nkillattfiles; i++)
  { if (killattfiles[i].attr & msgSENT)
    { if (strchr(killattfiles[i].name, PATHSEP))
        str[0]='\0';
      else
        strcpy(str, tmpdir);
      strcat(str, killattfiles[i].name);
      if (killattfiles[i].attr & msgKFS)
      { if (unlink(str))
          logwrite('!', "Can't unlink sent file %s: %s!\n", str, strerror(errno));
        else
          debug(4, "File %s deleted", str);
      }
      else if (killattfiles[i].attr & msgTFS)
      { int h=open(str, O_BINARY|O_RDWR);
        if (h==-1)
          logwrite('!', "Can't truncate sent file %s: %s!\n", str, strerror(errno));
        else
        { chsize(h, 0);
          close(h);
          debug(4, "File %s truncated", str);
        }
      }
    }
    else
      logwrite('!', "File %s attached to nobody!\n", killattfiles[i].name);
    free(killattfiles[i].name);
  }
  nkillattfiles=0;
}

int main(int argc, char * argv[])
{
  retcode=0;
  buffer=malloc(BUFSIZE);
  if (buffer==NULL)
  { puts("Not enough memory!");
    return RET_ERR;
  }
  header=malloc(MAXHEADER);
  if (header==NULL)
  { puts("Not enough memory!");
    return RET_ERR;
  }
  strcpy(copyright, NAZVA);
  strcat(copyright, " (Fido2Rel)");
  if (params(argc, argv))
    return 0;
  if (fake)
    return saveargs(argc, argv);
  debug(1, "Fido2Rel Started");
#ifdef __MSDOS__
  debug(6, "farcoreleft()=%ld bytes", farcoreleft());
#endif
  if (config())
    return RET_ERR;
  if (tossbad)
    retoss();
  h=-1;
  mypid=getpid();
  atexit(closepkt);
  atexit(killtmpatt);
#ifdef SIGPIPE
  signal(SIGPIPE, SIG_IGN);
#endif
#ifdef SIGBREAK
  signal(SIGBREAK, term);
#endif
#ifdef SIGINT
  signal(SIGINT, term);
#endif
#ifdef SIGTERM
  signal(SIGTERM, term);
#endif
  findlet();
  rclose();
  killtmpatt();
  if (frescan && rescan[0])
    touch(rescan);
  debug(1, "Exiting");
  return retcode;
}
