/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:58:33  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:20  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <share.h>
#include <errno.h>

#define MAXTRY 60

extern char seqf[];

unsigned long getmsgid(void)
{
  int h, try, len;
  char line[20];
  static unsigned long num = 0;

  for (try = 0; try < MAXTRY; try++)
  {
    /* read current number from seqf file */
    h = sopen(seqf, O_RDWR, SH_DENYRW, S_IREAD|S_IWRITE);
    if (h != -1)
    {
      len = read(h, line, sizeof(line));
      line[len] = '\0';
      sscanf(line, "%lu", &num);
      lseek(h, 0, SEEK_SET);
    }
    else if (errno == ENOENT)
      /* file does not exists - create it */
      h = sopen(seqf, O_WRONLY|O_CREAT, SH_DENYRW, S_IREAD|S_IWRITE);
    else if (errno == EACCES)
    {
      /* file locked by another process, waiting */
      sleep(1);
      continue;
    }
    if (h == -1)
      fprintf(stderr, "Can't open %s: %s\n", seqf, strerror(errno));
    break;
  }
  if (try == MAXTRY)
    fprintf(stderr, "File %s locked, can't read it\n", seqf);
  /* increase current seqf */
  /* if we didn't read number from seqf file and it's first call,
     init seqf by unixtime */
  if (num++ == 0)
    num = time(NULL);
  /* write increased num to file */
  if (h != -1)
  {
    sprintf(line, "%lu", num);
    write(h, line, len=strlen(line));
    chsize(h, len);
    close(h);
  }
  return num;
}

#if 1
char seqf[]="seqf";
int main(void)
{ unsigned long l=getmsgid();
  printf("0x%08lX   %lu\n", l, l);
  return 0;
}
#endif
