/*
 * $Id$
 *
 * $Log$
 * Revision 2.0.2.1  2002/10/02 09:53:45  gul
 * Fix syntax error
 *
 * Revision 2.0  2001/01/10 20:42:16  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <stdio.h>
#include <string.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#include <fidolib.h>
#ifdef __MSDOS__
#include "exec.h"
#endif
#ifdef __OS2__
#define INCL_DOSFILEMGR
#define INCL_DOSQUEUES
#define INCL_DOSPROCESS
#include <os2.h>
#endif
#include "gate.h"

int nosend,norcv,bypipe,quiet,fake,nocrc;
#ifdef __MSDOS__
int share;
#endif
static char signame[80], cmdline[FNAME_MAX];

int params(int argc, char * argv[])
{ int help, i;
  char *p, *p1;

  myname=argv[0];
#ifdef __OS2__
  { PPIB pib;
    PTIB tib;
    DosGetInfoBlocks(&tib, &pib);
    if (pib)
    { for (myname=pib->pib_pchenv; myname[0] || myname[1]; myname++);
      myname+=2;
    }
  }
#endif
  nconf[0]=0;
  nosend=norcv=bypipe=help=nglobal=quiet=fake=nocrc=0;
  inconfig=1;
  for (i=1;i<argc;i++)
  {
    if ((argv[i][0]!='-') && (argv[i][0]!='/'))
    { fprintf(stderr,"Incorrect parameter \"%s\" ignored!\n",argv[i]);
      continue;
    }
    if (stricmp(argv[i]+1, "nosend")==0)
    { nosend=1;
      continue;
    }
    if (stricmp(argv[i]+1, "norcv")==0)
    { norcv=1;
      continue;
    }
    if (stricmp(argv[i]+1, "fake")==0)
    { fake=1;
      continue;
    }
    if (stricmp(argv[i]+1, "nocrc")==0)
    { nocrc=1;
      continue;
    }
    if ((stricmp(argv[i]+1, "help")==0) || (stricmp(argv[i]+1, "-help")==0) ||
        (stricmp(argv[i]+1, "h")==0) || (stricmp(argv[i]+1, "?")==0))
    { help=1;
      continue;
    }
    if ((stricmp(argv[i]+1, "c")==0) && (i<argc-1))
    { if (i<argc-1)
      {
        i++;
        strcpy(nconf, argv[i]);
        continue;
      }
      else
      { fprintf(stderr, "No config name found after \"%s\" switch!\n", argv[i]);
        retcode|=RET_WARN;
        continue;
      }
    }
    if (tolower(argv[i][1])=='c')
    { strcpy(nconf, argv[i]+2);
      continue;
    }
    if (tolower(argv[i][1])=='l')
    { /* действительно ли by pipe? */
#ifdef __MSDOS__
      if (ioctl(fileno(stdin), 0) & 0xA0)
      { fprintf(stderr, "Incorrect used switch \"%s\" ignored!\n", argv[i]);
        retcode|=RET_WARN;
      }
      else /* disk file text mode */
#endif
        bypipe=1;
      continue;
    }
    if (stricmp(argv[i]+1, "q")==0)
    { quiet=1;
      continue;
    }
    if (tolower(argv[i][1])=='d')
    {
      p1=argv[i]+2;
      if (*p1==0)
      { if (i+1<argc)
          p1=argv[++i];
        else
        { fprintf(stderr, "Incorrect %s switch ignored!\n", argv[i]);
          retcode|=RET_WARN;
          continue;
        }
      }
      p=strchr(p1, '=');
      if (p)
      { *p++=0;
        setglobal(p1, p);
      }
      else
      { fprintf(stderr, "Incorrect %s swicth ignored!\n", argv[i]);
        retcode|=RET_WARN;
      }
      continue;
    }
    if (tolower(argv[i][1])=='x')
    { if (argv[i][1]=='X') debuglog=1;
      if (argv[i][2])
        p1=argv[i]+2;
      else
        p1=argv[++i];
      if ((p1==NULL) || !isdigit(*p1))
        fprintf(stderr, "Incorrect -x %s swicth ignored!\n", p1);
      else
        debuglevel=atoi(p1);
      continue;
    }
    fprintf(stderr, "Unknown switch \"%s\" ignored!\n", argv[i]);
    retcode|=RET_WARN;
  }
  if (help)
  {
    puts(COPYRIGHT);
    puts("FTN -> Internet -> FTN  Gate");
    puts("Copyright (C) Pavel Gulchouck 2:463/68 aka gul@gul.kiev.ua");
    puts("   Usage:");
    puts("attuucp" EXEEXT " [<switches>]");
    puts("   Switches:");
    puts("-nosend         - don't send attaches");
    puts("-norcv          - don't decode received attaches");
    puts("-nocrc          - don't check crc32");
    puts("-c<filename>    - config file (default is gate.cfg)");
    puts("-l              - for usage by pipe");
    puts("-q              - be quiet");
    puts("-d<var>=<value> - set variable for config");
    puts("-[x|X]<level>   - debug level");
    puts("-fake           - do nothing, only save params and stdin");
    puts("-?, -h          - this help");
  }
  if (help && (!nosend) && (!norcv) && (nconf[0]==0))
  { /* только /? */
    return 1;
  }
#if HAVE_GETUID && HAVE_GETEUID && HAVE_GETGID && HAVE_GETEGID
  if (nconf[0] && (getuid()!=geteuid() || getgid()!=getegid())
  { puts("You do not allowed to use -c switch\n";
    return RET_ERR;
  }
#endif
#ifdef __MSDOS__
  /* share.exe installation check */
  _AX=0x1000;
  geninterrupt(0x2f);
  if (_AL!=0xff)
  { share=0;
    debug(2, "share not installed");
  }
  else
  { share=1;
    debug(4, "share installed");
  }
#endif
  setglobal("[", "[");
  setglobal("`", "`");
  setglobal("OS", SYSTEM);
  return retcode;
}

int mktempname(char *sample, char *dest)
{
  int  i, k, l1, l2, l3;
  long l;
  char *p;

  if (strchr(sample, PATHSEP))
    dest[0]='\0';
  else
  { strcpy(dest, tmpdir);
    addslash(dest);
  }
  strcat(dest, sample);
  p=strchr(dest, '?');
  if (p==NULL)
  { debug(9, "mktempname(%s) returns %s", sample, dest);
    return !access(dest, 0);
  }
  for (i=0,l=10; p[++i]=='?'; l*=10)
    if (l>0x10000l) l=0x7fff;
  if (l>0x10000l) l=0x7fff;
  for (k=i; p[k]; k++)
    if (p[k]=='?')
      p[k]='0';
  l1=l2=(int)(rand()*l/RAND_MAX);
  for (;;)
  { l3=l1;
    for (k=i-1; k>=0; k--)
    { p[k]=l3%10+'0';
      l3/=10;
    }
    if (access(dest, 0))
    { debug(9, "mktempname(%s) returns %s", sample, dest);
      return 0;
    }
    l1=(l1+1)%(int)l;
    if (l1==l2)
    { debug(9, "mktempname(%s) failed", sample, dest);
      return 1;
    }
  }
}

void chsubstr(char *str, char *from, char *to)
{
  char *p;
  int  i;

  p=str;
  while ((p=strstr(p, from))!=NULL)
  {
    strcpy(p, p+strlen(from));
    for (i=strlen(p); i>=0; i--)
      p[i+strlen(to)]=p[i];
    strncpy(p, to, strlen(to));
    p+=strlen(to);
  }
}

void movebad(char *fname, long attrib)
{ int r;
  static char badname[80];

  debug(2, "MoveBad %s", fname);
  makename(fname, badname, badmail);
  debug(4, "MoveBad: new name is %s", badname);
  if (attrib & (msgKFS | msgTFS))
  { r=move(fname, badname);
    if (!(attrib & msgKFS))
      touch(fname);
  }
  else
    r=copyfile(fname, badname);
  if (r)
    logwrite('?', "Can't move %s to badmail!\n", fname);
}

int checkpgpsig(char *fname, char *pgpsig, char *from)
{ /* pgpsig is base64-coded binary detached signature */
  /* return 0 if ok */
  int len, h, r, good;
  FILE *f;
  char *p;
#ifdef __MSDOS__
  static char outname[80];
#endif

  len=str_unbase64(pgpsig, pgpsig);
  if (len<=0)
  { logwrite('!', "Bad pgp signature format!\n");
    return 1;
  }
  mktempname("temp????.sig", signame);
  h=open(signame, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
  if (h==-1)
  { logwrite('!', "Can't create %s: %s!\n", signame, strerror(errno));
    return 1;
  }
  write(h, pgpsig, len);
  close(h);
#ifdef __MSDOS__
  mktempname("temp????.pgp", outname);
  sprintf(cmdline, "%s > %s", pgpcheck_fmt, outname);
#else
  strcpy(cmdline, pgpcheck_fmt);
#endif
  chsubstr(cmdline, "%filename", fname);
  chsubstr(cmdline, "%signame", signame);
#ifdef __MSDOS__
  r=swap_system(cmdline);
  unlink(signame);
  if (r)
  { unlink(outname);
    return 2;
  }
  f=fopen(outname, "r");
  if (f==NULL)
  { unlink(outname);
    return 2;
  }
#else
  r=pipe_system(NULL, &h, cmdline);
  if ((h==-1) || (r<0))
  { unlink(signame);
    return 2;
  }
  f=fdopen(h, "r");
#endif
  good=3;
  while (fgets(cmdline, sizeof(cmdline), f))
  { if (strnicmp(cmdline, "Good signature from ", 20)==0)
    { p=strrchr(cmdline, '<');
      if (p==NULL) continue;
      p++;
      if (strnicmp(p, from, strlen(from)))
        continue;
      if (p[strlen(from)]=='>')
        good=0;
    }
  }
  fclose(f);
#ifdef __MSDOS__
  unlink(outname);
#else
  waitpid(r, &r, 0);
  r&=0xffff;
  if (r) good = 2;
  unlink(signame);
#endif
  return good;
}

char *getsign(char *fname)
{
  int r, siglen;
  FILE *f;
  static char myaddr[80];

#ifdef __MSDOS__
  mktempname("temp????.sig", signame);
  sprintf(cmdline, "%s >%s <%s", pgpsign_fmt, signame, fname);
#else
  int allocated, h;
  sprintf(cmdline, "%s <%s", pgpsign_fmt, fname);
#endif
  sprintf(myaddr, "%s@%s", user, local);
  chsubstr(cmdline, "%myaddr", myaddr);
#ifdef __MSDOS__
  r=swap_system(cmdline);
  if (r)
  { logwrite('?', "Can't create pgp signature!\n");
    unlink(signame);
    return NULL;
  }
  f=fopen(signame, "rb");
  if (f==NULL)
  { logwrite('?', "Can't create pgp signature!\n");
    unlink(signame);
    return NULL;
  }
  siglen=(int)fseek(f, 0, SEEK_END);
  fseek(f, 0, SEEK_SET);
  pgpsig=malloc(siglen*3+4);
  if (pgpsig==NULL)
  { logwrite('?', "Not enough memory for pgp signature!\n");
    fclose(f);
    unlink(signame);
    return NULL;
  }
  fread(pgpsig+2*siglen+4, siglen, 1, f);
  fclose(f);
  unlink(signame);
#else
  r=pipe_system(NULL, &h, cmdline);
  if (r<=0)
  { logwrite('?', "Can't create pgp signature!\n");
    unlink(signame);
    return NULL;
  }
  setmode(h, O_BINARY);
  f=fdopen(h, "rb");
  siglen=0;
  allocated=0;
  pgpsig=NULL;
  while (!feof(f))
  { if (allocated==siglen)
    pgpsig=realloc(pgpsig, allocated+=256);
    if (pgpsig==NULL)
    { while (fgetc(f)!=EOF);
      break;
    }
    siglen+=fread(pgpsig+siglen, 1, allocated-siglen, f);
  }
  if (pgpsig)
    pgpsig=realloc(pgpsig, siglen*3+4);
  if (pgpsig)
    memcpy(pgpsig+2*siglen+4, pgpsig, siglen);
  waitpid(r, &r, 0);
  r&=0xffff;
  if (r || pgpsig==NULL)
  { if (pgpsig) free(pgpsig);
    pgpsig=NULL;
    logwrite('?', "Can't create pgp signature!\n");
    return NULL;
  }
#endif
  if (!quiet) fputs("\n", stderr);
  str_base64(pgpsig+2*siglen+4, pgpsig, siglen);
  pgpsig=realloc(pgpsig, strlen(pgpsig)+1);
  return pgpsig;
}
