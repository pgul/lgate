/*
 * $Id$
 *
 * $Log$
 * Revision 2.4  2001/04/23 09:02:47  gul
 * create savefiles in homedir
 *
 * Revision 2.3  2001/04/22 16:03:03  gul
 * create script executable (mode 0755)
 *
 * Revision 2.2  2001/04/18 21:59:21  gul
 * Bugfix
 *
 * Revision 2.1  2001/04/18 21:46:38  gul
 * Translate comments
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <string.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#ifdef __OS2__
#define INCL_DOSFILEMGR
#include <os2.h>
#endif
#include "libgate.h"

#if defined(__MSDOS__)
#define EXT "bat"
#elif defined(__OS2__)
#define EXT "cmd"
#else
#define EXT "sh"
#endif

static char namebat[FNAME_MAX], nametxt[FNAME_MAX], calldir[FNAME_MAX];

int isfile(int h)
{
#ifdef __MSDOS__
  if (ioctl(h,0) & 0xA0)
#elif defined (__OS2__)
  unsigned long l, pipetype;
  DosQueryHType(h, &pipetype, &l);
  if (pipetype!=0)
#else
  struct stat st;
  if (fstat(h, &st) || (st.st_mode & S_IFREG)==0)
#endif
    return 0;
  return 1;
}

int saveargs(int argc, char *argv[])
{
  char *p;
  long l;
  FILE *f;
  int  c;
  int  n;
  char *str;

  str=malloc(CMDLINELEN);
  if (str==NULL) return 1;
#ifndef UNIX
  strncpy(calldir, argv[0], sizeof(calldir));
  p=strrchr(calldir, PATHSEP);
  if (p==NULL) p=strrchr(calldir, ':');
  if (p==NULL) p=calldir;
  else p++;
  *p='\0';
#else
#if defined(GETPWUID) && defined(GETEUID)
  { struct stat st;
    struct password *pw;
    calldir[0] = '\0';
    pw = getpwuid(geteuid());
    if (pw)
    { strncpy(calldir, pw->pw_dir, sizeof(calldir));
      calldir[sizeof(calldir)-2] = '\0';
      if (access(calldir, W_OK))
        calldir[0] == '\0';
      else
        addslash(calldir);
    }
  }
  if (calldir[0] == '\0')
#endif
  strcpy(calldir, "/tmp/");
#endif
  /* find free *.bat */
  for (l=1; l<999999l; l++)
  {
    sprintf(namebat, "%s%ld." EXT, calldir, l);
    sprintf(nametxt, "%s%ld.txt", calldir, l);
    if (access(namebat, 0) && access(nametxt, 0))
      break;
  }
  f=fopen(namebat, "w");
  if (f==NULL) return 3;
#ifdef __OS2__
  if ((!isatty(fileno(stdin))) && (!isfile(fileno(stdin))))
    /* pipe */
    fprintf(f, "type %s|", nametxt);
#elif UNIX
  fchmod(fileno(f), 0755);
  if ((!isatty(fileno(stdin))) && (!isfile(fileno(stdin))))
    fprintf(f, "cat %s|", nametxt);
#endif
  for (c=0; c<argc; c++)
  { if ((argv[c][0]=='-') || (argv[c][0]=='/'))
      if (stricmp(argv[c]+1, "fake")==0)
        continue;
    if (c>0) fprintf(f, " ");
    n=0;
    if (strchr(argv[c], ' ')) str[n++]='\"';
    for (p=argv[c]; *p; p++)
    {
#ifdef UNIX
      if (strchr("\"\'!~$<>|;[]*?()&`#\\", *p))
#else
      if (*p=='\"')
#endif
        str[n++]='\\';
      str[n++] = *p;
#ifndef UNIX
      if (*p=='%') str[n++] = *p;
#endif
    }
    if (strchr(argv[c], ' ')) str[n++]='\"';
    str[n]='\0';
    fputs(str, f);
  }
  fputs("\n", f);
  if (isatty(fileno(stdin)))
  { fclose(f);
    return 0;
  }
#if defined(UNIX) || defined(__OS2__)
  if (isfile(fileno(stdin)))
#endif
    fprintf(f, "<%s\n", nametxt);
  fclose(f);
  f=fopen(nametxt, "wb");
  setmode(fileno(stdin), O_BINARY);
  while ((c=fgetc(stdin))!=EOF)
    fputc(c, f);
  fclose(f);
  return 0;
}
