/* Просматривает NetMail */
/* находит непосланные письма на myaddr с именами с '@' и "uucp" */
/* посылает их, убивает, пишет в log */
/* попутно разбивает длинные строки с обработкой цитирования (2nd pass) */
/* вставляет '>' перед "From " в начале строки (2nd pass) */
/* отсекает бинарную информацию (optional) */
/* письма на заданные адреса (кроме privel users) */
/* перекодирует некоторые адреса (напр, мой ;) */
/* гейтует аттачи в base64 (optional) */

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
struct attfiletype killattfiles[NKILLATTFILES];
int nkillattfiles=0;

static void killtmpatt(void)
{ int i;

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
  strcpy(copyright,NAZVA);
  strcat(copyright," (Fido2Rel)");
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
