/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:18  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <string.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "gate.h"

void importpath(char *host, char const *cannon, char const *remote);

char spool_dir[FNAME_MAX];
char rnews[FNAME_MAX], compress[FNAME_MAX], cmdline[256];

static FILE *fnews=NULL;
static char s[128];
static char *p;
#ifndef UNIX
static char *p1;
static char namec[FNAME_MAX], namex[FNAME_MAX];
#endif
static char named[FNAME_MAX];
static char lastto[128]="";
static int  r, lasttype;
static long l, curbatchsize;
static int  saveout, hnews;
#ifdef __MSDOS__
static int  hin, savein;
static char mybuf[4096];
#else
static int  gzip_pid, uux_pid;
#endif
char int2ext_tab[128];

void int2ext(char *s)
{
  for(p=s;*p;p++)
    if (*p & 0x80)
      *p=int2ext_tab[*p & 0x7f];
}

int rsend(char *to, VIRT_FILE *fin, int type)
{
  debug(5, "rsend: to=%s, type=%d", to, type);
  if (fnews)
    if (curbatchsize>=maxcnews*1024l || strcmp(to,lastto) || type!=lasttype)
    { debug(6, "rsend: run rclose");
      if (rclose())
        return 5;
    }
  strcpy(lastto, to);
  lasttype=type;
  /* 1. Создаем D-файл */
  if (fnews==NULL)
  {
#ifdef __MSDOS__
    mktempname(TMPUNZNAME, named);
    fnews=fopen(named, "wb+");
    if (fnews==NULL)
    { logwrite('?', "Can't create %s: %s!\n", named, strerror(errno));
      return 1;
    }
#else
    if (byuux && (lasttype==G_CNEWS))
    { /* run uux */
      sprintf(cmdline, rnews, lastto);
      debug(5, "ropen: execute %s", cmdline);
      uux_pid=pipe_system0(&hnews, NULL, cmdline, "rnews");
      if (uux_pid==-1)
      { logwrite('?', "Can't execute '%s'!\n", cmdline);
        return 4;
      }
      setmode(hnews, O_BINARY);
      named[0]='\0';
    }
    else
    { if (lasttype==G_DIR)
      { /* store packet */
        for (l=time((time_t *)&l);;l++)
        { sprintf(named, "%s%08lx.001", lastto, l);
          if (access(named, 0)) break;
        }
        debug(5, "ropen: put to file %s", named);
      }
#ifndef UNIX
      else
      { /* put direct to spool */
        strcpy(named, spool_dir);
        removeslash(named);
        mkdir(named);
        addslash(named);
        p=named+strlen(named);
        strcpy(p,lastto);
        mkdir(named);
        p1=p+strlen(p);
        strcpy(p1, "\\c");
        mkdir(named);
        p1[1]='d';
        mkdir(named);
        *p=0;
        strcpy(s, "D.");
        strcat(s, local);
        l=time((time_t *)&l);
        p1=s+strlen(s);
        do
        { sprintf(p1, "%u", (uword)++l);
          importpath(p, s, lastto);
        }
        while (!access(named, 0));
        debug(5, "ropen: D-file name %s", named);
        strcpy(namec, s); /* unix-name */
      }
#endif
      hnews=open(named, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
      if (hnews==-1)
      { logwrite('?', "Can't create %s: %s!\n", named, strerror(errno));
        return 6;
      }
    }
    if (compress[0])
    { if (write(hnews, "#! cunbatch\n", 12)!=12)
      { logwrite('?', "Can't write cnews-packet!\n");
killuux:
        close(hnews);
        goto killuux1;
      }
      sprintf(s, compress, "");
      fflush(stdout);
      saveout=dup(fileno(stdout));
      dup2(hnews, fileno(stdout));
      close(hnews);
      debug(5, "ropen: run %s", s);
      gzip_pid=pipe_system(&hnews, NULL, s);
      dup2(saveout, fileno(stdout));
      close(saveout);
      if (gzip_pid==-1)
      { logwrite('?', "Can't execute '%s'!\n", s);
        goto killuux;
      }
      setmode(hnews, O_BINARY);
    }
    fnews=fdopen(hnews, "wb");
    if (fnews==NULL)
    { logwrite('?', "Can't fdopen pipe: %s!\n", strerror(errno));
      goto killuux;
    }
#endif
    curbatchsize=0;
  }
  sprintf(s, "#! rnews %lu\n", msgsize);
  if (fputs(s, fnews) == EOF)
  {
rputserr:
    logwrite('?', "Can't write to %s: %s!\n", named[0] ? named : "pipe",
             strerror(errno));
    fclose(fnews);
    fnews=NULL;
#ifndef __MSDOS__
killuux1:
    if (gzip_pid!=-1)
    { kill(gzip_pid, SIGINT);
      waitpid(gzip_pid, &r, 0);
      r &= 0xffff;
      r = ((r << 8 ) | (r >> 8)) & 0xffff;
      logwrite('!', "compress retcode %u\n", r);
    }
    if (uux_pid!=-1)
    { kill(uux_pid, SIGINT);
      waitpid(uux_pid, &r, 0);
      r &= 0xffff;
      r = ((r << 8 ) | (r >> 8)) & 0xffff;
      logwrite('!', "uux retcode %u\n", r);
    }
    else
#endif
      unlink(named);
    return 1;
  }
  curbatchsize+=strlen(s);
  while (virt_fgets(s, sizeof(s), fin))
    if (fputs(s, fnews)==EOF)
      goto rputserr;
  curbatchsize+=msgsize;
  debug(5, "rsend: done");
  return 0;
}

int rclose(void)
{
  debug(5, "rclose");
  if (fnews==NULL) return 0;
#ifdef __MSDOS__
  /* пакуем и добавляем #! cunbatch\n */
  strcpy(namec, named);
  if (lasttype==G_DIR)
  { for (l=time((time_t *)&l);;l++)
    { sprintf(named, "%s%08lx.001", lastto, l);
      if (access(named, 0)) break;
    }
  }
  else if (byuux)
  { strcat(named, "z");
    if (access(named, 0)==0)
      unlink(named);
  }
  else
  { strcpy(named, spool_dir);
    addslash(named);
    p=named+strlen(named);
    strcpy(p, lastto);
    mkdir(named);
    p1=p+strlen(p);
    strcpy(p1, "\\c");
    mkdir(named);
    p1[1]='d';
    mkdir(named);
    *p=0;
    strcpy(s, "D.");
    strcat(s, local);
    l=time((time_t *)&l);
    p1=s+strlen(s);
    do
    { sprintf(p1, "%u", (unsigned)++l);
      importpath(p, s, lastto);
    }
    while (!access(named, 0));
    debug(7, "rclose: make filename %s", named);
  }
  fflush(fnews);
  hin=dup(fileno(fnews));
  fclose(fnews);
  fnews=NULL;
  if ((compress[0]==0) && byuux && (lasttype==G_CNEWS))
  { hnews=hin;
    hin=-1;
    lseek(hnews, 0, SEEK_SET);
    strcpy(named, namec);
    debug(8, "rclose: don't compressing batch (via rnews)");
    goto comprdone;
  }
  hnews=myopen(named, O_BINARY|O_RDWR|O_CREAT|O_DENYALL);
  if (hnews==-1)
  { logwrite('?', "ERROR: Can't create %s: %s!\n", named, strerror(errno));
    close(hin);
    return 1;
  }
  lseek(hin, 0, SEEK_SET);
  if (compress[0]==0)
  { debug(8, "rclose: don't compressing batch");
    goto uncompr;
  }
  write(hnews, "#! cunbatch\n", 12);
  /* делаем из hnews stdout, из fnews - stdin */
  if (!quiet)
    puts("Compressing cnews packet...");
  fflush(stdin);
  fflush(stdout);
  savein=dup(fileno(stdin));
  saveout=dup(fileno(stdout));
  dup2(hin, fileno(stdin));
  dup2(hnews, fileno(stdout));
  close(hnews);
  close(hin);
  /* Не вполне честно - просто игнорируем параметр %s и передаем на stdin */
  sprintf(cmdline, compress, "");
  debug(6, "rclose: run %s", cmdline);
  r=swap_system(cmdline);
  /* возвращаем на место stdin и stdout */
  hnews=dup(fileno(stdout));
  hin=dup(fileno(stdin));
  dup2(savein, fileno(stdin));
  close(savein);
  dup2(saveout, fileno(stdout));
  close(saveout);
  if (r)
  { logwrite('!', "Can't pack cnews-packet, gzip retcode %d!\n", r);
    fprintf(stderr, "Can't pack cnews packet, gzip retcode %d!\n", r);
    /* просто копируем hin в hnews */
    lseek(hnews, 0, SEEK_SET);
    lseek(hin, 0, SEEK_SET);
    chsize(hnews, 0);
uncompr:
    if ((lasttype==G_CNEWS) && byuux)
    { close(hnews);
      unlink(named);
      hnews=hin;
      hin=-1;
      strcpy(named, namec);
      namec[0]='\0';
    }
    else
    {
      do
      { r=read(hin, mybuf, sizeof(mybuf));
        if (write(hnews, mybuf, r)!=r)
        { logwrite('?', "Can't write to %s: %s!\n", named, strerror(errno));
          close(hin);
          close(hnews);
          unlink(named);
          return 6;
        }
      }
      while (r);
    }
  }
  close(hin);
  unlink(namec);
  if (lasttype==G_DIR)
  { close(hnews);
    debug(5, "rclose: done");
    return 0;
  }
  if (byuux)
  {
comprdone:
    sprintf(cmdline, rnews, lastto);
    savein=dup(fileno(stdin));
    lseek(hnews, 0, SEEK_SET);
    dup2(hnews, fileno(stdin));
    close(hnews);
    debug(5, "rclose: run %s", cmdline);
    r=swap_system(cmdline);
    hnews=dup(fileno(stdin));
    dup2(savein, fileno(stdin));
    close(savein);
    close(hnews);
    if (r)
    { logwrite('?', "Can't send cnews-packet: rnews retcode %d!\n", r);
      return 1;
    }
    unlink(named);
    debug(5, "rclose: done");
    return 0;
  }
  close(hnews);
#else
  if (fclose(fnews))
  { logwrite('?', "Can't write to file: %s!\n",
             (errno>=0) ? strerror(errno) : "reason unknown");
    return 5;
  }
  fnews=NULL;
  if (gzip_pid!=-1)
  { 
    debug(15, "rclose: waiting for gzip (pid %d)", gzip_pid);
    waitpid(gzip_pid, &r, 0);
    r&=0xffff;
    r=(r << 8) | (r >> 8);
    r&=0xffff;
    if (r)
    { logwrite('?', "Can't compress cnews-packet: gzip retcode %u!\n", r);
      return 4;
    }
    debug(5, "rclose: gzip finished successfully");
  }
  if (uux_pid!=-1)
  { 
    debug(15, "rclose: waiting for rnews (pid %d)", uux_pid);
    waitpid(uux_pid, &r, 0);
    r&=0xffff;
    r=(r << 8) | (r >> 8);
    r&=0xffff;
    if (r)
    { logwrite('?', "Can't send cnews-packet: rnews retcode %u!\n", r);
      return 4;
    }
    debug(5, "rclose: rnews finished successfully");
  }
  if ((lasttype!=G_CNEWS) || byuux)
  { debug(5, "rclose: done");
    return 0;
  }
#endif
#ifndef UNIX
  /* формируем X-пакет */
  strcpy(named, s);
  strcpy(namex, spool_dir);
  addslash(namex);
  p=namex+strlen(namex);
  do
  { sprintf(p1, "%u", (unsigned)++l);
    importpath(p, s, lastto);
  }
  while (!access(namex, 0));
  debug(7, "rclose: make X-file name %s", namex);
  fnews=fopen(namex, "wb");
  if (fnews==NULL)
  { logwrite('?', "ERROR: Can't create %s: %s!\n", namex, strerror(errno));
    return 8;
  }
  fprintf(fnews,"U uucp %s\n"
                "F %s\n"
                "I %s\n"
                "C rnews\n",
                local, named, named);
  fclose(fnews);
  /* Формируем C-пакет */
  strcpy(namec, named);
  named[0]='C';
  strcpy(namec, spool_dir);
  addslash(namec);
  p=namec+strlen(namec);
  importpath(p, named, lastto);
  debug(7, "rclose: make C-file name %s", namec);
  named[0]='D';
  fnews=fopen(namec, "w");
  if (fnews==NULL)
  { logwrite('?', "Can't create %s: %s!\n", namec, strerror(errno));
    return 9;
  }
  if (fprintf(fnews,"S %s %s uucp - %s 0666 uucp\n"
                    "S %s X%s uucp - %s 0666 uucp\n",
                    named, named, named,
                    s, s+1, s)==EOF)
  { logwrite('?', "Can't write to %s, %s!\n", namec, strerror(errno));
    fclose(fnews);
    unlink(namec);
    fnews=NULL;
    return 10;
  }
  fclose(fnews);
  fnews=NULL;
  debug(5, "rclose: done");
#endif
  return 0;
}

#ifndef __MSDOS__
int msend(char *cmd, VIRT_FILE *f)
{ int r;
  int  mpipe, sendmail_pid;

  debug(5, "msend: cmd=%s", cmd);
  sendmail_pid=pipe_system(&mpipe, NULL, cmd);
  if (sendmail_pid==-1 || mpipe==-1)
    return -1;
/* sleep(2); r=0; */
  setmode(mpipe, O_BINARY);
  while (virt_fgets(s, sizeof(s), f))
  {
    if (write(mpipe, s, strlen(s))!=strlen(s))
    {
      r=0;
      if (errno>=0)
        logwrite('?',"Can't write to pipe: %s!\n", strerror(errno));
      else
        logwrite('?',"Can't write to pipe: unknown error!\n");
      close(mpipe);
#if 1
      kill(sendmail_pid, SIGINT);
      waitpid(sendmail_pid, &r, 0);
#else
      if (waitpid(sendmail_pid, &r, WNOHANG)==0)
      { kill(sendmail_pid, SIGINT);
        waitpid(sendmail_pid, &r, 0);
      }
#endif
      return r ? r : -1;
    }
  }
  close(mpipe);
  waitpid(sendmail_pid, &r, 0);
  debug(5, "msend: done");
  return r;
}
#endif
