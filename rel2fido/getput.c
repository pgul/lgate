/*
 * $Id$
 *
 * $Log$
 * Revision 2.4  2002/01/07 09:39:32  gul
 * Public textline()
 *
 * Revision 2.3  2001/09/05 13:44:25  gul
 * Set envelope-from to '<>' in reject msgs under unix
 *
 * Revision 2.2  2001/01/24 01:59:18  gul
 * Bugfix: sometimes put msg into pktin dir with 'pkt' extension
 *
 * Revision 2.1  2001/01/23 11:19:48  gul
 * translate comments adn cosmetic changes
 *
 * Revision 2.0  2001/01/10 20:42:24  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <errno.h>
#include <ctype.h>
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef __OS2__
#define INCL_DOSFILEMGR
#define INCL_DOSPROCESS
#include <os2.h>
#endif
#include "gate.h"

int packnews=0;
char namedel[MAXPACK][FNAME_MAX];
unsigned naddr=0;
int  seqf=0;
char uncompress[128];
char cmdline[CMDLINELEN];
#ifndef __MSDOS__
void *regbufmsg = NULL;
#endif
static int  maxmsg;
static int  tomaster, tpl;
static char *p;
static long l;

static int tpl_cont;

static void reset_badaddr(void)
{ int r;

  hrewind();
  tpl_cont=0;
  if (bypipe) return;
  /* ignore From_ line */
  do
    r=hgets();
  while (r && (strpbrk(str, "\n\r")==NULL));
}

int textline(char *s, unsigned size)
{ char *p;
  int  r;

  r=hgets();
  if (r==0) return r;
  for (p=str; *p; p++)
    if (*p=='\r')
      *p='\n';
  if (s!=str)
    strncpy(s, str, size);
  if (tpl_cont==2) return r; /* it's message body */
  if (strchr(str, '\n')==NULL)
  { tpl_cont=1;
    return r;
  }
  if (strcmp(s, "\n"))
  { tpl_cont=0;
    return r;
  }
  if (tpl_cont)
  { tpl_cont=0;
    return r;
  }
  tpl_cont=2; /* message body */
  return 0;
}

static void setvars(int reason)
{
  time_t curtime;
  struct tm *curtm;

  curtime=time(NULL);
  curtm=localtime(&curtime);
  setvar("From", fromaddr[0] ? fromaddr : envelope_from);
  debug(8, "SetVars: From is %s", getvar("From"));
  setvar("Sender", envelope_from);
  debug(8, "SetVars: Sender is %s", getvar("Sender"));
  setvar("Master", postmast);
  debug(8, "SetVars: Master is %s", getvar("Master"));
  strcpy(str, "MAILER-DAEMON@");
  strcat(str, localdom);
  setvar("Gate", str);
  debug(8, "SetVars: Gate is %s", getvar("Gate"));
  setvar("To", addr);
  debug(8, "SetVars: To is %s", getvar("To"));
  sprintf(str, "%02u %s %02u", curtm->tm_mday, montable[curtm->tm_mon],
          curtm->tm_year%100);
  setvar("localdate", str);
  debug(8, "SetVars: LocalDate is %s", getvar("LocalDate"));
  sprintf(str, "%02u:%02u:%02u",
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
  setvar("localtime", str);
  debug(8, "SetVars: LocalTime is %s", getvar("LocalTime"));
  sprintf(str, "%lu", filelength(f));
  setvar("Size", str);
  debug(8, "SetVars: Size is %s", getvar("Size"));
  setvar("Multipart", "No");
  sprintf(str, "%02u%02u%04u%02u%02u%02u%04x%02d/%s",
          curtm->tm_mday, curtm->tm_mon, curtm->tm_year+1900,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          (unsigned)getpid(), seqf++, localdom);
  setvar("Boundary", str);
  debug(8, "SetVars: Boundary is %s", getvar("Boundary"));
  switch (reason)
  { case BADADDR:  setvar("reason", "BadAddress");
                   sprintf(str, "%s: incorrect address", addr);
                   break;
    case ITWIT:    setvar("reason", "ITwit");
                   sprintf(str, "Returned mail: access denied");
                   break;
    case ITWITTO:  setvar("reason", "ITwit-To");
                   sprintf(str, "Returned mail: access denied");
                   break;
    case ITWITFROM:setvar("reason", "ITwit-From");
                   sprintf(str, "Returned mail: access denied");
                   break;
    case ITWITVIA: setvar("reason", "ITwit-Via");
                   sprintf(str, "Returned mail: access denied");
                   break;
    case MANYHOPS: setvar("reason", "TooManyHops");
                   sprintf(str, "%d", curhops);
                   setvar("hops", str);
                   sprintf(str, "%d", maxhops);
                   setvar("MaxHops", str);
                   sprintf(str, "Returned mail: too many hops %d (%d max)",
                           curhops, maxhops);
                   break;
    case REJ_ATTACH:
                   setvar("reason", "FileAttach");
                   sprintf(str, "Returned mail: sending fileattaches denied");
                   break;
    case REJ_HUGE: setvar("reason", "TooLarge");
                   sprintf(str, "Returned mail: message too large");
                   break;
    case EXTERNAL: setvar("reason", "External");
                   sprintf(str, "Returned mail: can't send message");
                   break;
  }
  debug(8, "SetVars: Reason is %s", getvar("Reason"));
  setvar("Subject", str);
  debug(8, "SetVars: Subject is %s", getvar("Subject"));
}

void reject(int reason)
{
#ifdef __MSDOS__
  static char tmpfile[80];
#else
  int  pid;
#endif
  static char bound[80];
  int  r;
  FILE *fout;
  time_t curtime;
  struct tm *curtm;

  debug(4, "Reject(%d)", reason);
  hrewind();
  tpl=init_tpl(badaddr_tpl);
  for (tomaster=0; tomaster<2; tomaster++)
  {
    if ((tomaster==0) && (envelope_from[0]==0) && (fromaddr[0]==0))
    { logwrite('!', "From address not specified, reject message not sent!\n");
      continue;
    }
    gettextline=voidgets;
    reset_text=voidfunc;
    /* set variables for template */
    setvars(reason);
    if (tomaster)
      setvar("ToMaster", "yes");
    else
      setvar("ToMaster", "no");
    if ((attrib & msgRETREC) && (tomaster==0))
      setvar("DontSend", "yes");
    tplout=0;
    if (tpl==0)
      while (templateline(str, sizeof(str)));
    strcpy(bound, getvar("Boundary"));
    if (getvar("dontsend")==NULL)
    {
#ifdef __MSDOS__
      mktempname(TMPNAME, tmpfile);
      fout=myfopen(tmpfile, "wb");
      if (fout==NULL)
      { logwrite('?', "Can't create %s: %s!\n", tmpfile, strerror(errno));
        close(f);
        f=-1;
        break;
      }
#else /* UNIX, OS/2 */
#ifdef UNIX
      sprintf(str, "%s -f \'<>\' %s", rmail,
           tomaster ? postmast : (envelope_from[0] ? envelope_from : fromaddr));
#else
      if (uupcver!=SENDMAIL)
        sprintf(str, "%s%s -- %s", rmail, (uupcver==KENDRA) ? "" : " -u",
           tomaster ? postmast : (envelope_from[0] ? envelope_from : fromaddr));
      else
        sprintf(str, "%s -f %s@%s %s", rmail, "MAILER-DAEMON", localdom,
           tomaster ? postmast : (envelope_from[0] ? envelope_from : fromaddr));
#endif
      debug(3, "Reject: running '%s'", str);
      pid=pipe_system(&r, NULL, str);
      if (pid==-1)
      { logwrite('?', "Can't execute '%s'!\n", str);
        close_tpl();
        return;
      }
      setmode(r, O_BINARY);
      fout=fdopen(r, "wb");
#endif
      curtime=time(NULL);
      curtm=localtime(&curtime);
#ifndef UNIX
      if (uupcver!=SENDMAIL)
        fprintf(fout, "From MAILER-DAEMON %s %s %02u %02u:%02u:%02u %02u remote from %s\n",
          weekday[curtm->tm_wday], montable[curtm->tm_mon], curtm->tm_mday,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          curtm->tm_year+1900, local);
#endif
      if (getvar("Gate"))
        sprintf(str, "From: %s\n", getvar("Gate"));
      else
        sprintf(str, "From: MAILER-DAEMON@%s\n", localdom);
      altkoi8(str);
      fputs(str, fout);
      if (getvar("Sender"))
        sprintf(str, "To: %s\n", getvar("Sender"));
      else
        sprintf(str, "To: %s\n", envelope_from);
      altkoi8(str);
      fputs(str, fout);
      if (getvar("Subject"))
        sprintf(str, "Subject: %s\n", getvar("Subject"));
      altkoi8(str);
      fputs(str, fout);
      fprintf(fout, "Date: %s, %2u %s %02u %02u:%02u:%02u %c%02u00\n",
        weekday[curtm->tm_wday],
        curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year+1900,
        curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
        (tz<=0) ? '+' : '-', (tz>0) ? tz : -tz);
      fprintf(fout, "Message-Id: <%lx%04x%02d@%s>\n",
              time(NULL)+tomaster, (unsigned)getpid(), seqf++, localdom);
      if (getvar("Multipart")==NULL)
        setvar("Multipart", "No");
      if (tpl==0)
      {
        if (stricmp(getvar("Multipart"), "Yes")==0)
        {
          debug(4, "Reject: generate multipart");
          fprintf(fout, "Mime-Version: 1.0\n");
          fprintf(fout, "Content-Type: multipart/report; boundary=\"%s\"\n\n",
                  bound);
        }
        else
          fprintf(fout, "\n");
        close_tpl();
        init_tpl(badaddr_tpl);
        setvars(reason);
        setvar("Boundary", bound);
        if (tomaster)
          setvar("ToMaster", "yes");
        else
          setvar("ToMaster", "no");
        gettextline=textline;
        reset_text=reset_badaddr;
        tplout=1;
        while (templateline(str, sizeof(str)))
        { altkoi8(str);
#ifdef __OS2__
          if (str[0]=='\x1a')
            str[0]=' ';
#endif
          fputs(str, fout);
        }
      }
      else
      { reset_badaddr();
        if (((errorsto==TO_MASTER) && tomaster) ||
            ((errorsto==TO_SENDER) && (!tomaster)))
        {
          fprintf(fout, "Mime-Version: 1.0\n");
          fprintf(fout, "Content-Type: multipart/report; boundary=\"%s\"\n\n",
                  bound);
          fprintf(fout, "This is a Mime-encapsulated message\n");
          fprintf(fout, "\n--%s\n", bound);
          fprintf(fout, "Content-Type: text/plain; charset=us-ascii\n");
        }
        fprintf(fout, "\nUnrecoverable error:\n");
        switch (reason)
        { case BADADDR:   fprintf(fout, "Address %s is invalid.\n", addr);
                          break;
          case ITWIT:     fprintf(fout, "You can't use this gate.\n");
                          break;
          case ITWITTO:   fprintf(fout, "You can't use this gate.\n");
                          break;
          case ITWITVIA:  fprintf(fout, "You can't use this gate.\n");
                          break;
          case ITWITFROM: fprintf(fout, "You can't use this gate.\n");
                          break;
          case REJ_ATTACH:fprintf(fout, "Sending fileattaches via this gate denied.\n");
                          break;
          case REJ_HUGE:  fprintf(fout, "Message too large.\n");
                          break;
          case MANYHOPS:  fprintf(fout, "Too many hops %d (%d max).\n",
                                  curhops, maxhops);
                          break;
          case EXTERNAL:  fprintf(fout, "Can't send message.\n");
                          break;
          default:        fprintf(fout, "Internal error.\n");
                          break;
        }
        if (((errorsto==TO_MASTER) && tomaster) ||
            ((errorsto==TO_SENDER) && (!tomaster)))
        {
          fprintf(fout, "Original message follows:\n");
          fprintf(fout, "\n--%s\n", bound);
          fprintf(fout, "Content-Type: message/rfc822\n\n");
          while (textline(str, sizeof(str)))
          { altkoi8(str);
            fputs(str, fout);
          }
          fputs("\n", fout);
          while (textline(str, sizeof(str)))
          { altkoi8(str);
#ifdef __OS2__
            if (str[0]=='\x1a')
              str[0]=' ';
#endif
            fputs(str, fout);
          }
          fprintf(fout, "\n--%s--\n", bound);
        }
        else
        { fputs("Original message header:\n------\n", fout);
          while (textline(str, sizeof(str)))
          { altkoi8(str);
            fputs(str, fout);
          }
          fprintf(fout, "\n-- message body suppressed --\n");
        }
      }
      fclose(fout);
      fout=NULL;
#ifdef __MSDOS__
      if (uupcver!=SENDMAIL)
        sprintf(str, "%s%s -- %s <%s", rmail, (uupcver==KENDRA) ? "" : " -u",
                tomaster ? postmast : (envelope_from[0] ? envelope_from : fromaddr), tmpfile);
      else
        sprintf(str, "%s -f %s@%s %s <%s", rmail, "MAILER-DAEMON", localdom,
                tomaster ? postmast : (envelope_from[0] ? envelope_from : fromaddr), tmpfile);
      r=swap_system(str);
      unlink(tmpfile);
#else /* OS/2 */
      waitpid(pid, &r, 0);
      r&=0xffff;
      r=((r>>8) | (r<<8)) & 0xffff;
#endif
      if (r && (r!=48))
        logwrite('?', "Rmail retcode %xh!\n", r);
      else
        debug(4, "Reject: rmail retcode is %d", r);
    }
    close_tpl();
    if (!tomaster)
      init_tpl(badaddr_tpl);
  } /* for */
}

void badnews(void)
{ int i;

  if (fout)
  { fclose(fout);
    fout=NULL;
  }
  for (i=1; i<packnews; i++)
  { debug(4, "BadNews: deleting %s", namedel[i]);
    unlink(namedel[i]);
  }
  if (packnews==0)
    strcpy(namedel[0], msgname);
  else
  { debug(4, "BadNews: deleting %s", msgname);
    unlink(msgname);
  }
  if (begdel==0)
  { debug(4, "BadNews: deleting %s (begdel=0)", namedel[0]);
    unlink(namedel[0]);
  }
  else
  { i=myopen(namedel[0], O_BINARY|O_RDWR|O_EXCL);
    if (i!=-1)
    { chsize(i, begdel);
      lseek(i, begdel, SEEK_SET);
      l=0;
      write(i, &l, 2);
      close(i);
      debug(4, "BadNews: set %s size to %d", namedel[0], begdel);
    }
  }
#ifndef UNIX
  renbad(named);
#endif
  retcode|=RET_ERR;
}

int getletter(void)
{ int r, savein, fsrc;
  DIR *dd;
  struct dirent *df;

  curaka=0;
  debug(6, "GetLetter started");
  if (bypipe)
  {
    packnews=0;
    begdel=0;
    conf=0;
#ifndef UNIX
    if ((uupcver!=KENDRA) && (uupcver!=SENDMAIL))
      funix=0;
    else
#endif
      funix=1;
    setmode(fileno(stdin), O_BINARY);
    ibufsrc=BUFSIZE;
    if (cnews)
    { debug(3, "GetLetter: run rnews");
      if (rnews())
      { badnews();
        retcode|=RET_ERR;
      }
      return 1;
    }
    gotstr[0]=0;
    /* addr filled in params() */
    debug(3, "GetLetter: single message from stdin");
    if (msg_unmime(-1))
    { badnews();
      retcode|=RET_ERR;
    }
    return 1;
  }
#ifndef UNIX
  if (uupcver!=SENDMAIL)
    /* get from spool */
    fromuupcspool();
  funix=((uupcver==KENDRA) || (uupcver==SENDMAIL)) ? 1 : 0;
#else
  funix=1;
#endif
  conf=1;
  cnews=0;
  packnews=0;
  if (noecho)
    return 1;
  if (fout)
    begdel=ftell(fout);
  else
    begdel=0;
  /* box */
  strcpy(named, userbox);
  if ((fsrc=myopen(named, O_BINARY|O_RDONLY))!=-1)
    if (flock(fsrc, LOCK_EX|LOCK_NB))
    { debug(1, "Can't lock %s: %s", named, strerror(errno));
      close(fsrc);
      fsrc=-1;
    }
  if (fsrc!=-1)
  { ibufsrc=BUFSIZE;
    msgsize=-1;
    savein=dup(fileno(stdin));
    dup2(fsrc, fileno(stdin));
    close(fsrc);
    if (!myfgets(gotstr, sizeof(gotstr)))
    { flock(fileno(stdin), LOCK_UN);
      dup2(savein, fileno(stdin));
      close(savein);
      unlink(named);
    }
#ifndef UNIX
    else if (((uupcver==KENDRA) && strcmp(gotstr, UUPCEXTSEP CRLF)) ||
             ((uupcver!=KENDRA) && (isbeg(gotstr)!=0)))
    { flock(fileno(stdin), LOCK_UN);
      dup2(savein, fileno(stdin));
      close(savein);
      logwrite('?', "Incorrect mailbox start, renamed to *.bad!\n");
      renbad(named);
    }
#endif
    else
    { r=1;
      while (
#ifndef UNIX
             (uupcver==KENDRA) ? (strcmp(gotstr, UUPCEXTSEP CRLF)==0) :
#endif
             (isbeg(gotstr)==0))
      { debug(4, "GetLetter: get from mailbox");
        if ((r=msg_unmime(0))!=0)
          break;
      }
      if (!r)
      { lseek(fileno(stdin), 0, SEEK_SET);
        chsize(fileno(stdin), 0);
      }
      flock(fileno(stdin), LOCK_UN);
      dup2(savein, fileno(stdin));
      close(savein);
      if (r)
      { retcode|=RET_ERR;
        badnews();
      }
      else
        unlink(named);
    }
  }
  else
    debug(1, "Can't open %s: %s", named, strerror(errno));
  /* cnews */
  funix=1;
  cnews=1;
  if (dirnews[0])
  { removeslash(dirnews);
    dd=opendir(dirnews);
    addslash(dirnews);
    if (dd==NULL)
      debug(2, "Can't opendir %s: %s", dirnews, strerror(errno));
    else
    {
      while ((df=readdir(dd))!=NULL)
      { if (cmpaddr(df->d_name, "*.B??")==0)
          continue;
        if (df->d_name[0]=='.') continue;
        if (fout)
          begdel=ftell(fout);
        else
          begdel=0;
        packnews=0;
        strcpy(named, dirnews);
        addslash(named);
        strcat(named, df->d_name);
        r=myopen(named, O_BINARY|O_RDWR);
        if (r==-1)
          continue;
        debug(4, "GetLetter: rnews from %s", named);
        savein=dup(fileno(stdin));
        dup2(r, fileno(stdin));
        close(r);
        if (flock(fileno(stdin), LOCK_EX|LOCK_NB))
        { logwrite('!', "Can't lock %s: %s!\n", named, strerror(errno));
          dup2(savein, fileno(stdin));
          close(savein);
          continue;
        }
        r=rnews();
        flock(fileno(stdin), LOCK_UN);
        dup2(savein, fileno(stdin));
        close(savein);
        if (r)
        { badnews();
          retcode|=RET_ERR;
        }
        else
          unlink(named);
      }
      closedir(dd);
    }
  }
  debug(4, "GetLetter: no more messages");
  return 1;
}

static int rnewsbeg(char * str)
{ if (*(word *)str!=((((word)'!')<<8)|(word)'#'))
    return 0;
  for (p=str+2; (*p==' ') || (*p=='\t'); p++);
  if (strncmp(p, "rnews ", 6)==0)
    return 1;
  return 0;
}

#ifdef __OS2__
static void in2out(void *arg)
{ int l=0, l1=0;
  char *buf;
  int *h=arg;
  
  if ((buf=malloc(BUFSIZE))!=NULL)
  {
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
    for (;;)
    {
      l=read(h[0], buf, BUFSIZE);
      if (l<=0) break;
      do
      {
        if ((l1=write(h[1], buf, l)) <= 0)
          break;
        if (l1 != l)
          memcpy(buf, buf+l1, l-l1);
        l-=l1;
      }
      while (l>0);
      if (l1<=0)
        break;
    }
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_DFL);
#endif
    free(buf);
  }
  close(h[1]);
  if (l<=0)
    h[1]=errno;
  else if (l1<=0)
    h[1]=-errno;
  else
    h[1]=0;
  _endthread();
}
#endif

int rnews(void)
{ char *p;
  int  i, r;

  debug(4, "Rnews started");
  conf=1;
  cnews=1;
  funix=1;
  ibufsrc=BUFSIZE;
  msgsize=-1;
  packnews=0;
  for (i=0; i<sizeof(gotstr)-1; i++)
  { if (read(fileno(stdin), gotstr+i, 1)!=1)
      break;
    if (gotstr[i]=='\n')
    { i++;
      break;
    }
  }
  gotstr[i]=0;
  if (strncmp(gotstr, "#!", 2))
  { /* starts not from '#!' */
    debug(4, "rnews: single message");
    return msg_unmime(-1);
  }
  for (p=gotstr+2; (*p==' ') || (*p=='\t'); p++);
  if (strncmp(p, "rnews ", 6)==0)
  { debug(4, "Rnews: batch processing ('%s')", gotstr);
    for (;;)
    { long l=atol(p+6);
      if (l==0)
      { logwrite('?', "Incorrect cnews packet (bad art length)!\n");
        return 1;
      }
      gotstr[0]=0;
      r=msg_unmime(l);
      if (r)
      { logwrite('?', "Incorrect cnews packet!\n");
        return 1;
      }
      msgsize=-1;
      if (!myfgets(gotstr, sizeof(gotstr)))
        return 0;
      debug(8, "First line is %s", gotstr);
      p=strstr(gotstr, "rnews ");
      if ((p==NULL) || (!rnewsbeg(gotstr)))
      { logwrite('?', "Incorrect cnews packet ('#!rnews ...' expected)!\n");
        return 1;
      }
    }
  }
  if (strncmp(p, "cunbatch\n", 9))
  { logwrite('?', "Unknown command in cnews-packet!\n");
    return 1;
  }
  /* remove "unbatch" */
  debug(4, "Rnews: compressed batch processing");
#if defined(__OS2__)
  { int in[2], out, pid, tid;

    sprintf(cmdline, uncompress, "");
    debug(4, "Rnews: run '%s'", cmdline);
    /* stdin can be locked */
    pid=pipe_system(in+1, &out, cmdline);
    if (pid==-1)
    { logwrite('?', "Can't execute gzip for unpack cnews-packet!\n");
      return 1;
    }
/* 
in[0]->in[1] (tid)
in[1]->gzip->(out)->rnews()
*/
    setmode(out, O_BINARY);
    setmode(in[1], O_BINARY);
    in[0]=dup(fileno(stdin));
    dup2(out, fileno(stdin));
    close(out);
    tid=_beginthread(in2out, NULL, STACK_SIZE, in);
    r=rnews();
#if 0
    if (r)
      DosKillProcess(DKP_PROCESSTREE, pid); /* avoid "broken pipe" error */
#endif
    dup2(in[0], fileno(stdin));
    close(in[0]);
    DosWaitThread((PTID)&tid, DCWW_WAIT);
    if (in[1]>0)
    { logwrite('?', "Can't write to pipe: %s!\n", strerror(in[1]));
      r=1;
    }
    else if (in[1]<0)
    { logwrite('?', "Can't read compressed packet: %s!\n", strerror(-in[1]));
      r=1;
    }
    waitpid(pid, &i, 0);
    i&=0xffff;
    i=((i<<8) | (i>>8)) & 0xffff;
    if (r)
      i=r;
    if (i)
    { logwrite('?', "Can't uncompress cnews-archive: gzip retcode %u!\n", i);
      r=1;
    }
    return r;
  }
#elif defined(UNIX)
  { int savein, out;
    pid_t pid;
    sprintf(cmdline, uncompress, "");
    debug(4, "Rnews: run '%s'", cmdline);
    pid=pipe_system(NULL, &out, cmdline);
    if (pid==-1)
    { logwrite('?', "Can't execute gzip for unpack cnews-packet!\n");
      return 1;
    }
    savein=dup(fileno(stdin));
    dup2(out, fileno(stdin));
    close(out);
    r=rnews();
    dup2(savein, fileno(stdin));
    close(savein);
    waitpid(pid, &i, 0);
    i&=0xffff;
    i=((i<<8) | (i>>8)) & 0xffff;
    if (r)
      i=r;
    if (i)
    { logwrite('?', "Can't uncompress cnews-archive: gzip retcode %u!\n", i);
      r=1;
    }
    return r;
  }
#else /* __MSDOS__ */
  { static char tmpzname[SSIZE];
    char tmpname[SSIZE]; /* no static because of recurse! */
    int  savein, saveout, hz;

    /* copy stdin to tmpzname before uncompress - can be locked */
    strcpy(gotstr, tmpdir);
    strcat(gotstr, TMPZNAME);
    mktempname(gotstr, tmpzname);
    hz=open(tmpzname, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
    if (hz==-1)
    { logwrite('?', "Can't create %s: %s!\n", tmpzname, strerror(errno));
      return 1;
    }
    for (;;)
    { int l;
      if ((l=read(fileno(stdin), gotstr, sizeof(gotstr)))<=0)
        break;
      if (write(hz, gotstr, l) != l)
      { logwrite('?', "Can't write %s: %s!\n", tmpzname, strerror(errno));
        close(hz);
        unlink(tmpzname);
        return 1;
      }
    }
    lseek(hz, 0, SEEK_SET);
    strcpy(gotstr, tmpdir);
    strcat(gotstr, TMPUNZNAME);
    mktempname(gotstr, tmpname);
    i=open(tmpname, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
    if (i==-1)
    { logwrite('?', "Can't create %s: %s!\n", tmpname, strerror(errno));
      close(hz);
      unlink(tmpzname);
      return 1;
    }
    saveout=dup(fileno(stdout));
    dup2(i, fileno(stdout));
    close(i);
    savein=dup(fileno(stdin));
    dup2(hz, fileno(stdin));
    close(hz);
    sprintf(cmdline, uncompress, "");
    debug(4, "rnews: run '%s'", cmdline);
    if (!quiet)
    { fputs("Uncompressing cnews-packet...", stderr);
      fflush(stderr);
    }
    r=swap_system(cmdline);
    if (!quiet)
      fputs("\n", stderr);
    dup2(savein, fileno(stdin));
    close(savein);
    unlink(tmpzname);
    i=dup(fileno(stdout));
    dup2(saveout, fileno(stdout));
    close(saveout);
    lseek(i, 0, SEEK_SET);
    if (r>255 || r<0)
    { logwrite('?', "ERROR! Can't execute gzip.exe!\n");
      close(i);
      unlink(tmpname);
      return 1;
    }
    if (r)
    { close(i);
      unlink(tmpname);
      logwrite('?', "Can't unpack cnews-packet, renamed to *.bad!\n");
      return 1;
    }
    ibufsrc=BUFSIZE;
    debug(4, "Rnews: call rnews");
    savein=dup(fileno(stdin));
    dup2(i, fileno(stdin));
    close(i);
    r=rnews();
    dup2(savein, fileno(stdin));
    close(savein);
    unlink(tmpname);
    return r;
  }
#endif
}

static unsigned curpktaka=-1;

char *renamepkt(char *tempname)
{ static long tpktname=0;
  static char realname[FNAME_MAX];

  if (tpktname==0)
    tpktname=time((time_t *)&l);
  sprintf(realname, "%s%08lx.pkt", pktout, tpktname++);
  if (rmove(tempname, realname)==0)
    return realname;
  logwrite('?', "Can't rename %s!\n", tempname);
  return NULL;
}

int closeout(void)
{
  if (fout)
  { int i=0;
    fwrite(&i, 1, 1, fout);
    if (packmail || conf)
      fwrite(&i, 2, 1, fout);
    fflush(fout);
    flock(fileno(fout), LOCK_UN);
    fclose(fout);
    fout=NULL;
    if (packmail || conf)
    { renamepkt(msgname);
      if (newechoflag[0])
        touch(newechoflag);
    }
  }
  return 0;
}

int nextmsg(void)
{ /* save str for holdmsg()! */
  DIR  *dd;
  struct dirent *df;
  int  r;
  struct packet pkt;
  char *realname;

  /* find max msg number in netmail */
  if ((!conf) && (!packmail))
  { if (fout)
    { /* usually fout closed by getletter, but if msg splitting... */
      fwrite("", 1, 1, fout);
      fclose(fout);
      fout=NULL;
    }
    removeslash(netmaildir);
    dd=opendir(netmaildir);
    addslash(netmaildir);
    if (dd)
    { maxmsg=0;
      while ((df=readdir(dd))!=NULL)
      { if (chkregexp(df->d_name, MSGREGEX
#ifndef __MSDOS__
                      , &regbufmsg
#endif
            )) continue;
        r=atoi(df->d_name);
        if (r>maxmsg) maxmsg=r;
      }
      closedir(dd);
    }
    for (r=maxmsg+1; r>0 && r<maxmsg+1000; r++)
    { int h, i;
      sprintf(msgname, "%s%u.msg", netmaildir, maxmsg+1);
      h=open(msgname, O_BINARY|O_RDWR|O_EXCL|O_CREAT, S_IREAD|S_IWRITE);
      if (h==-1)
        continue;
      for (i=0; i<5; i++)
        if (flock(h, LOCK_EX | LOCK_NB))
          sleep(1);
        else
          break;
      if (i==5)
      { logwrite('?', "Can't lock %s: %s!\n", msgname, strerror(errno));
        close(h);
        unlink(msgname);
        continue;
      }
      fout=fdopen(h, "wb");
      if (fout==NULL)
      { logwrite('?', "Can't fdopen %s: %s!\n", msgname, strerror(errno));
        flock(h, LOCK_UN);
        close(h);
        unlink(msgname);
        return 7;
      }
      debug(6, "NextMsg: returning %s", msgname);
      return 0;
    }
    logwrite('?', "Can't create msg: %s!\n", strerror(errno));
    return 7;
  }
  /* pkt */
  if (fout)
  { l=0;
    fwrite(&l, 1, 1, fout);
    if ((ftell(fout)>=pktsize*1024l) || (curaka!=curpktaka))
    { debug(4, "NextMsg: close current pkt (size %ld), make new", ftell(fout));
      curpktaka=-1;
      fwrite(&l, 2, 1, fout);
      if (fflush(fout))
      { fout=NULL;
        logwrite('?', "Can't fflush file: %s!\n", strerror(errno));
        badnews();
        if (f!=-1)
          close(f);
        f=-1;
        return 1;
      }
      flock(fileno(fout), LOCK_UN);
      fclose(fout);
      fout=NULL;
      if ((realname = renamepkt(msgname)) == NULL)
      { badnews();
        if (f!=-1) close(f);
        f=-1;
        return 1;
      }
      if (packnews!=MAXPACK)
        strcpy(namedel[packnews++], realname);
    }
    else
      return 0;
  }
  { int i, h;
    i=0;
    l=time((time_t *)&l);
    do
    { sprintf(msgname, "%s%08lx.pkt", tmpdir, l++);
      h=open(msgname, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
      i++;
    }
    while ((h==-1) && (i<1000));
    if (i==1000)
    { logwrite('?', "Can't create %s: %s!\n", msgname, strerror(errno));
      return 7;
    }
    for (i=0; i<5; i++)
      if (flock(h, LOCK_EX | LOCK_NB))
        sleep(1);
      else
        break;
    if (i==5)
    { logwrite('?', "Can't lock %s: %s!\n", msgname, strerror(errno));
      close(h);
      unlink(msgname);
      return 7;
    }
    fout=fdopen(h, "wb");
    if (fout==NULL)
    { logwrite('?', "Can't fdopen %s: %s!\n", msgname, strerror(errno));
      flock(h, LOCK_UN);
      close(h);
      unlink(msgname);
      return 7;
    }
  }
  debug(4, "NextMsg: new packet name is %s", msgname);
  curpktaka=curaka;
  pkthdr.OrigZone=pkthdr.OrigZone_=myaka[curaka].zone;
  pkthdr.OrigNet=myaka[curaka].net;
  pkthdr.OrigNode=myaka[curaka].node;
  pkthdr.OrigPoint=myaka[curaka].point;
  memcpy(&pkt, &pkthdr, sizeof(pkt));
  pkthdr_byteorder(&pkt);
  fwrite(&pkt, sizeof(pkt), 1, fout);
  return 0;
}

void writehdr(void)
{ int two=2;
  struct message msg;
  memcpy(&msg, &msghdr, sizeof(msg));
  msghdr_byteorder(&msg);
  if ((!conf) && (!packmail))
  {
    fwrite(&msg, sizeof(msg), 1, fout);
    return;
  }
  /* pkt */
  two=chorders(htons(two));
  fwrite(&two, 2, 1, fout);
  fwrite(&msg.orig_node, 2, 1, fout);
  fwrite(&msg.dest_node, 2, 1, fout);
  fwrite(&msg.orig_net, 2, 1, fout);
  fwrite(&msg.dest_net, 2, 1, fout);
  fwrite(&msg.attr, 2, 1, fout);
  fwrite(&msg.cost, 2, 1, fout);
  fwrite(msghdr.date, strlen(msghdr.date)+1, 1, fout);
  fwrite(msghdr.to, strlen(msghdr.to)+1, 1, fout);
  fwrite(msghdr.from, strlen(msghdr.from)+1, 1, fout);
  fwrite(msghdr.subj, strlen(msghdr.subj)+1, 1, fout);
}
