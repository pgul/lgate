/*
 * $Id$
 *
 * $Log$
 * Revision 2.5  2011/08/28 21:04:21  gul
 * Minor bugs fixed
 *
 * Revision 2.4  2004/07/20 18:29:25  gul
 * \r\n -> \n
 *
 * Revision 2.3  2002/11/17 20:55:26  gul
 * New option "tid" in gate.cfg
 *
 * Revision 2.2  2001/01/25 18:41:38  gul
 * myname moved to debug.c
 *
 * Revision 2.1  2001/01/21 10:20:00  gul
 * new cfg param 'fromtop'
 *
 * Revision 2.0  2001/01/10 20:42:15  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <string.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include <time.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef __OS2__
#include <os2.h>
#endif
#include "exec.h"
#include <fidolib.h>
#include "gate.h"

#define MAXINCL 5

#ifdef UNIX
#define fullpath(str)  (*(str)=='/')
#else
#define fullpath(str)  (*(str) && (str)[1]==':' && (str)[2]=='\\')
#endif

char uupcdir[FNAME_MAX];
char remote[80],local[80];
char rmail[FNAME_MAX];
char postmaster[80];
char filebox[FNAME_MAX];
char user[80];
char tmpdir[FNAME_MAX];
char incomplete[FNAME_MAX], sentdir[FNAME_MAX];
char pktout[FNAME_MAX];
char unsecure[FNAME_MAX];
char binkout[FNAME_MAX];
char tboxes[FNAME_MAX];
#ifndef __MSDOS__
char lbso[FNAME_MAX], tlboxes[FNAME_MAX], longboxes[FNAME_MAX];
static char mydomain[32];
#endif
char badmail[FNAME_MAX];
char semdir[FNAME_MAX];
char uuencode_fmt[FNAME_MAX], uudecode_fmt[FNAME_MAX];
char pgpenc_fmt[FNAME_MAX], pgpdec_fmt[FNAME_MAX];
char pgpcheck_fmt[FNAME_MAX], pgpsign_fmt[FNAME_MAX];
char precedence[80];
int  tz, use_swap;
unsigned maxuue;
char nconf[FNAME_MAX];
static char mailext[80];
static char maildir[FNAME_MAX];
static char confdir[FNAME_MAX];
static unsigned long curconfirm, confirm_fail;
ftnaddr my;
int  uupcver;

static char *ignore[]={
"reject-tpl=",
"held-tpl=",
"badaddr-tpl=",
"by-uux=",
"uucode=",
"organization=",
"conference",
"group",
"cnewssize=",
"fidosystem=",
"route-to",
"to-ifmail",
"no-route",
"pktin=",
"pack=",
"pktsize=",
"user=",
"send-to=",
"free=",
"no-send=",
"uplink=",
"chaddr=",
"chdomain",
"sysop=",
"privel=",
"twit=",
"pktpwd=",
"maxsize=",
"maxline=",
"size=",
"attrib=",
"echolog=",
"rcv2via=",
"savehdr=",
"golded=",
"no-twit=",
"domain-id=",
"message-id=",
"holdpath=",
"holdsize=",
"to-uucp=",
"errors-to=",
"upper=",
"alias",
"moderator",
"tabsize=",
"resend-bad=",
"maxhops=",
"max-received=",
"itwit=",
"itwit-",
"uncompress=",
"compress=",
"rel2fido-chk",
"rel2fido-flt",
"fido2rel-chk",
"fido2rel-flt",
"myorigin=",
"gatevia=",
"hide-tearline=",
"hide-origin=",
"softCR=",
"8bit-header=",
"x-comment-to=",
"via=",
"replyto=",
"attach-from=",
"log=",
"decode-attach=",
"del-transit-files=",
"rnews=",
"newsdir=",
"charset=",
"charsets-dir=",
"charsets-alias=",
"charset-alias=",
"extcharset=",
"extsetname=",
"intsetname=",
"fido-charset=",
"put-chrs=",
"split-multipart=",
"write-reason=",
"local=",
"kill-vcard=",
"honour-alternate=",
"hold-huge=",
"split-reports=",
"fsp-1004=",
"bangfrom=",
"env-chaddr=",
"fido2rel-chk-pl=",
"rel2fido-chk-pl=",
"inb-dir=",
"fromtop=",
"tid="
};

static void canondir(char *dir)
{
#if defined(__MSDOS__) || defined(__OS2__)
  char *p;

  if ((dir[1]==':') && dir[0])
  { str[0]=dir[0]|0x20;
    p=dir+2;
  }
  else
  { getcwd(str, sizeof(str));
    p=dir;
  }
  str[1]=':';
  str[2]=0;
  if (*p!=PATHSEP)
  { str[2]=PATHSEP;
#ifdef __OS2__
    { int i=sizeof(str)-3;
      DosQueryCurrentDir(tolower(str[0])-'a'+1, str+3, (unsigned long *)&i);
    }
#else
    getcurdir(tolower(str[0])-'a'+1, str+3);
#endif
    if (str[3]) strcat(str, PATHSTR);
  }
  strcat(str, p);
  if (str[strlen(str)-1]==PATHSEP && strlen(str)>DISKPATH+1)
    str[strlen(str)-1]='\0';
  strcpy(dir, str);
#else
  if (*dir!=PATHSEP)
  { getcwd(str, sizeof(str));
    strcat(str, PATHSTR);
    strcat(str, dir);
    strcpy(dir, str);
  }
  if (dir[strlen(dir)-1]==PATHSEP && strlen(str)>DISKPATH+1)
    dir[strlen(dir)-1]='\0';
#endif
}

int config(void)
{ int i;
  char *p, *p1;
  FILE *fout;

  if (nconf[0]==0)
  {
#ifdef UNIX
    strcpy(nconf, GATECFG);
    setpath(nconf);
#else
    strcpy(nconf, myname);
    p=strrchr(nconf, PATHSEP);
    if (p==NULL) p=nconf;
    else p++;
    strcpy(p, GATECFG);
#endif
  }
  tplout=0;
  setglobal("Module", "Attuucp");
  if (init_tpl(nconf))
    return RET_ERR;
  tmpdir[0]=0;
  p=getenv("TEMP");
  if (p==NULL)
    p=getenv("TMP");
  if (p)
    strcpy(tmpdir, p);
  if (tmpdir[0]==0)
    getcwd(tmpdir, sizeof(tmpdir));
  canondir(tmpdir);
  tz=0;
  p1=getenv("TZ");
  if (p1) getmytz(p1, &tz);
  filebox[0]=uupcdir[0]=rmail[0]=netdir[0]=logname[0]=pktout[0]=binkout[0]=0;
#ifndef __MSDOS__
  lbso[0]=tlboxes[0]=longboxes[0]='\0';
#endif
  tboxes[0]='\0';
  newechoflag[0]=unsecure[0]=badmail[0]=semdir[0]=user[0]=0;
  maildir[0]=0;
  sentdir[0]=incomplete[0]=0;
  uuencode_fmt[0]=uudecode_fmt[0]=precedence[0]=0;
  pgpenc_fmt[0]=pgpdec_fmt[0]=pgpcheck_fmt[0]=pgpsign_fmt[0]=0;
  local[0]=0;
  strcpy(postmaster, "postmaster");
  nhosts=0;
#ifdef __MSDOS__
  use_swap=-1;
#endif
  maxuue=0;
  flo_only=1;
  my.zone=my.net=0;
#ifdef UNIX
  uupcver=SENDMAIL;
#else
  uupcver=5;
#endif
  curconfirm=12*3600l;     /* 12h */
  confirm_fail=3*24l*3600; /*  3d */
  while (configline(str, sizeof(str)))
  { 
    if ((strnicmp(str, "route-files", 11)==0) ||
        (strnicmp(str, "route-uue", 9)==0) ||
        (strnicmp(str, "route-split", 11)==0))
      nhosts++;
    if (strnicmp(str, "log=", 4)==0)
    {
#ifdef UNIX
      if (strchr(str+4, '/'))
        strcpy(logname, str+4);
      else
      { strcpy(logname, "/var/log/");
        strcat(logname, str+4);
      }
#else
      if (strpbrk(str+4, "\\:/")) /* !!! */
        strcpy(logname, str+4);
      else
      { /* if path not specified - to run dir */
        strcpy(logname, myname);
        p=strrchr(logname, PATHSEP);
        if (p==NULL) p=logname;
        else p++;
        strcpy(p, str+4);
      }
#endif
      continue;
    }
    if (strnicmp(str, "logstyle=", 9) == 0)
    { if (stricmp(str+9, "fd")==0)
        logstyle=FD_LOG;
      else if (stricmp(str+9, "bink")==0)
        logstyle=FE_LOG;
#ifdef HAVE_SYSLOG_H
      else if (stricmp(str+9, "syslog")==0)
        logstyle=SYSLOG_LOG;
#endif
      continue;
    }
  }
  close_tpl();
  
  if (logname[0]=='\0')
#ifdef UNIX
    strcpy(logname, "/var/log/lgate.log");
#else
  { strcpy(logname, myname);
    p=strrchr(logname, PATHSEP);
    if (p==NULL) p=logname;
    else p++;
    strcpy(p, "lgate.log");
  }
#endif
  if (access(logname, 0) && logstyle!=SYSLOG_LOG)
  { fout=myfopen(logname, "w");
    if (fout==NULL)
    { puts("Can't create log-file!");
      closeall();
      return RET_ERR;
    }
    fclose(fout);
  }
  if (nhosts)
  { 
#ifdef __MSDOS__
    if (nhosts*(long)sizeof(hosts[0])>=0x8000)
    { fputs("Too many ROUTE-FILES and ROUTE-UUE commands!\n", stderr);
      return RET_ERR;
    }
#endif
    hosts=malloc(nhosts*sizeof(hosts[0]));
    if (hosts==NULL)
    { logwrite('?', "Not enough memory!\n");
      return RET_ERR;
    }
  }

  nhosts=0;
  init_tpl(nconf);
  tplout=1;
  while (configline(str, sizeof(str)))
  {
    if (strnicmp(str, "display ", 8)==0)
    { logwrite('$', "%s\n", str+8);
      continue;
    }
    if (strnicmp(str, "filebox=", 8)==0)
    { strcpy(user, str+8);
      continue;
    }
    if ((strnicmp(str, "route-files", 11)==0) ||
        (strnicmp(str, "route-uue", 9)==0) ||
        (strnicmp(str, "route-split", 11)==0))
    { for (p=strpbrk(str, " \t"); (*p==' ') || (*p=='\t'); p++);
      /* route-uue [/Mime] fnet@gate.uanet.kharkov.ua 2:461/21 [path] */
      hosts[nhosts].enc=ENC_UUE;
      hosts[nhosts].size=0;
      hosts[nhosts].pgpsig=0;
      hosts[nhosts].thebat=0;
      hosts[nhosts].confirm=0;
      hosts[nhosts].passwd[0]='\0';
      p1=strpbrk(p, " \t");
      if (p1==NULL) p1=p+strlen(p);
      while (*p=='/')
      {
        if (strnicmp(p, "/mime", 5)==0 || strnicmp(p, "/base64", 7)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/base64\" switch in route-files command ignored\n");
          else
          { if (p1==NULL)
              goto invcommand;
            hosts[nhosts].enc=ENC_BASE64;
          }
        }
        else if (strnicmp(p, "/sign", 5)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/sign\" switch in route-files command ignored\n");
          else
          { if (p1==NULL)
              goto invcommand;
            hosts[nhosts].pgpsig=1;
          }
        }
        else if (strnicmp(p, "/thebat", 7)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/thebat\" switch in route-files command ignored\n");
          else
          { if (p1==NULL)
              goto invcommand;
            hosts[nhosts].thebat=1;
          }
        }
        else if (strnicmp(p, "/confirm", 8)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/confirm\" switch in route-files command ignored\n");
          else
          { if (p1==NULL)
              goto invcommand;
            if (cmpaddr(p+8, "/^=[1-9][0-9]*[dh],[1-9][0-9]*[dh] /"))
            { if (!isspace(p[8]))
                logwrite('!', "Incorrect \"/confirm\" params ignored!\n");
            }
            else
            { p+=9;
              curconfirm=atol(p);
              curconfirm*=3600;
              while (isdigit(*p)) p++;
              if (tolower(*p++)=='d') curconfirm*=24;
              p++;
              confirm_fail=atol(p);
              confirm_fail*=3600;
              while (isdigit(*p)) p++;
              if (tolower(*p++)=='d') confirm_fail*=24;
            }
            hosts[nhosts].confirm=curconfirm;
            hosts[nhosts].confirm_fail=confirm_fail;
          }
        }
        else if (strnicmp(p, "/pgp", 4)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/pgp\" switch in route-files command ignored\n");
          else
          { if (p1==NULL)
              goto invcommand;
            hosts[nhosts].enc=ENC_PGP;
          }
        }
        else if (strnicmp(p, "/Split=", 7)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/Split\" switch in route-files command ignored\n");
          else if (strnicmp(str, "route-split", 11)==0)
            logwrite('!', "Incorrect \"/Split\" switch in route-split command ignored\n");
          else if (!isdigit(p[7]))
            logwrite('!', "Incorrect \"/Split\" switch ignored\n");
          else
            hosts[nhosts].size=atoi(p+7);
        }
        else if (strnicmp(p, "/Password=", 10)==0)
        { if (strnicmp(str, "route-files", 11)==0)
            logwrite('!', "Incorrect \"/Password\" switch in route-files command ignored\n");
          else
          { p+=10;
            strncpy(hosts[nhosts].passwd, p, sizeof(hosts[0].passwd)-1);
            if (p1-p>=sizeof(hosts[0].passwd))
            { logwrite('!', "Password too long, truncated\n");
              hosts[nhosts].passwd[sizeof(hosts[0].passwd)-1]='\0';
            }
            else
              hosts[nhosts].passwd[(unsigned)(p1-p)]='\0';
          }
        }
        else
        { char c=*p1;
          *p1='\0';
          logwrite('!', "Incorrect switch \"%s\" ignored!\n", p);
          *p1=c;
        }
        for (p=p1; (*p==' ') || (*p=='\t'); p++);
        p1=strpbrk(p," \t");
        if (p1==NULL) p1=p+strlen(p);
      }
      if (strnicmp(str, "route-split", 11)==0)
      {
        if (p1==NULL)
        { 
invcommand:
          logwrite('!', "Incorrect command: %s\n", str);
          continue;
        }
        if (!isdigit(*p))
          goto invcommand;
        hosts[nhosts].size=atoi(p);
        for(p=p1; (*p==' ') || (*p=='\t'); p++);
        p1=strpbrk(p, " \t");
      }
      if (p1==NULL)
        goto invcommand;
      *p1=0;
      strcpy(hosts[nhosts].host, p);
      *p1=' ';
      for(p=p1+1; (*p==' ') || (*p=='\t'); p++);
      if (getfaddr(p, &hosts[nhosts].addr, my.zone, my.net))
        goto invcommand;
      hosts[nhosts].dir[0]=0;
      if (strnicmp(str, "route-files", 11)==0)
        hosts[nhosts].enc=ENC_UUCP;
#ifndef __MSDOS__
      hosts[nhosts].domain[0]='\0';
      for (; *p && *p!='@' && *p!=' ' && *p!='\t'; p++);
      if (*p=='@')
      { p++;
        for (p1=p; *p1 && !isspace(*p1); p1++);
        i=(p1-p>sizeof(hosts->domain)-1) ? sizeof(hosts->domain)-1 : p1-p;
        strncpy(hosts[nhosts].domain, p, i);
        hosts[nhosts].domain[i]='\0';
      }
#endif
      p1=strpbrk(p, " \t");
      if (p1)
      { for (p=p1+1; (*p==' ') || (*p=='\t'); p++);
        p1=strpbrk(p, " \t");
        if (p1) *p1=0;
        if ((p[strlen(p)-1]==PATHSEP) && (strlen(p)>DISKPATH+1))
          p[strlen(p)-1]='\0';
        strncpy(hosts[nhosts].dir, p, sizeof(hosts[0].dir)-1);
        hosts[nhosts].dir[sizeof(hosts[0].dir)-1]='\0';
        if (p1) *p1=' ';
      }
      nhosts++;
      continue;
    }
    if (strnicmp(str, "uupc=", 5)==0)
    {
#ifndef UNIX
      if (!fullpath(str+5))
        goto notfull;
      strcpy(uupcdir, str+5);
      addslash(uupcdir);
#endif
      continue;
    }
    if (strnicmp(str, "rmail=", 6)==0)
    { strcpy(rmail, str+6);
      continue;
    }
    if (strnicmp(str, "postmaster=", 11)==0)
    { strcpy(postmaster, str+11);
      continue;
    }
    if (strnicmp(str, "netmail=", 8)==0)
    { if (!fullpath(str+8))
      {
notfull:
        *strchr(str, '=')='\0';
        logwrite('?', "You must specify FULL path to your %s directory!\n", str);
        closeall();
        return RET_ERR;
      }
      strcpy(netdir, str+8);
      if ((netdir[strlen(netdir)-1]==PATHSEP) && (strlen(netdir)>DISKPATH+1))
        netdir[strlen(netdir)-1]='\0';
      continue;
    }
    if (strnicmp(str, "binkout=", 8)==0)
    { if (!fullpath(str+8))
        goto notfull;
      strcpy(binkout, str+8);
      addslash(binkout);
      continue;
    }
    if (strnicmp(str, "longbso=", 8)==0)
    {
#ifdef __MSDOS__
      logwrite('?', "LongBSO not supported in MSDOS version!\n");
#else
      if (!fullpath(str+8))
        goto notfull;
      strcpy(lbso, str+8);
      addslash(lbso);
#endif
      continue;
    }
    if (strnicmp(str, "longboxes=", 10)==0)
    {
#ifdef __MSDOS__
      logwrite('?', "LongBoxes not supported in MSDOS version!\n");
#else
      if (!fullpath(str+10))
        goto notfull;
      strcpy(longboxes, str+10);
      addslash(longboxes);
#endif
      continue;
    }
    if (strnicmp(str, "tlboxes=", 8)==0)
    {
#ifdef __MSDOS__
      logwrite('?', "TLBoxes not supported in MSDOS version!\n");
#else
      if (!fullpath(str+8))
        goto notfull;
      strcpy(tlboxes, str+8);
      addslash(tlboxes);
#endif
      continue;
    }
    if (strnicmp(str, "tboxes=", 7)==0)
    { if (!fullpath(str+7))
        goto notfull;
      strcpy(tboxes,str+7);
      addslash(tboxes);
      continue;
    }
    if (strnicmp(str, "pktout=", 7)==0)
    { if (!fullpath(str+7))
        goto notfull;
      strcpy(pktout, str+7);
      addslash(pktout);
      continue;
    }
    if (strnicmp(str, "unsecure=", 9)==0)
    { if (!fullpath(str+9))
        goto notfull;
      strcpy(unsecure, str+9);
      addslash(unsecure);
      continue;
    }
    if (strnicmp(str, "temp=", 5)==0)
    { if (str[5])
      { strcpy(tmpdir, str+5);
        canondir(tmpdir);
      }
      continue;
    }
    if (strnicmp(str, "rescan=", 7)==0)
    { strcpy(rescan, str+7);
      continue;
    }
    if (strnicmp(str, "uuencode=", 9)==0)
    { strcpy(uuencode_fmt, str+9);
      continue;
    }
    if (strnicmp(str, "uudecode=", 9)==0)
    { strcpy(uudecode_fmt, str+9);
      continue;
    }
    if (strnicmp(str, "pgp-encode=", 11)==0)
    { strcpy(pgpenc_fmt, str+11);
      continue;
    }
    if (strnicmp(str, "pgp-decode=", 11)==0)
    { strcpy(pgpdec_fmt, str+11);
      continue;
    }
    if (strnicmp(str, "pgp-check=", 10)==0)
    { strcpy(pgpcheck_fmt, str+10);
      continue;
    }
    if (strnicmp(str, "pgp-sign=", 9)==0)
    { strcpy(pgpsign_fmt, str+9);
      continue;
    }
    if (strnicmp(str, "newecho=", 8)==0)
    { strcpy(newechoflag, str+8);
      continue;
    }
    if (strnicmp(str, "timezone=", 9)==0)
    { if (getmytz(str+9, &tz))
      { 
invparam:
        logwrite('!', "Incorrect string ignored: %s\n", str);
        continue;
      }
      continue;
    }
    if (strnicmp(str, "swap=", 5)==0)
    { 
#ifdef __MSDOS__
      use_swap=USE_FILE;
      for (p=str+5; *p; p++)
        switch(tolower(*p))
        { case 'f':  use_swap|=USE_FILE; continue;
          case 'e':  use_swap|=USE_EMS;
                     if (use_swap & USE_XMS) use_swap|=XMS_FIRST;
                     continue;
          case 'x':  use_swap|=USE_XMS;  continue;
          case ' ':
          case '\t':
          case '\n': continue;
          default:   logwrite('!', "Unknown swap method %c ignored.\n", *p);
                     continue;
        }
#endif
      continue;
    }
    if (strnicmp(str, "maxuue=", 7)==0)
    { maxuue=atoi(str+7);
      continue;
    }
    if ((strnicmp(str, "address=", 8)==0) ||
       (strnicmp(str, "aka=", 4)==0))
    { if (my.zone) continue;
      p=strchr(str, '=');
      if (getfaddr(p+1, &my, 0, 0))
      { logwrite('!', "%s is incorrect fido address!\n", p);
        continue;
      }
#ifndef __MSDOS__
      p=strpbrk(p, "%@");
      if (p==NULL) continue;
      strncpy(mydomain, p+1, sizeof(mydomain));
      mydomain[sizeof(mydomain)-1]='\0';
      for (p=mydomain; *p; p++)
      { if (isspace(*p) || *p=='.' || *p=='%' || *p=='@')
        { *p='\0';
          break;
        }
      }
#endif
      continue;
    }
    if (strnicmp(str, "norm-only=", 10)==0)
    { for (p=str+10; (*p==' ') || (*p=='\t'); p++);
      if ((p[0]|0x20)=='y')
        flo_only=1;
      else if ((p[0]|0x20)=='n')
        flo_only=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "uupcver=", 8)==0)
    { 
#ifndef UNIX
      if ((strnicmp(str+8, "6.14h", 5)==0) || (strncmp(str+8, "6.15", 4)==0)
          || (strncmp(str+8, "7", 1)==0))
        uupcver=6;
      else if (strnicmp(str+8, "Kendra",6)==0)
        uupcver=KENDRA;
      else if (strnicmp(str+8, "sendmail", 8)==0)
        uupcver=SENDMAIL;
      else if ((str[8]!='5') && (str[8]!='6'))
        goto invparam;
#endif
      continue;
    }
    if (strnicmp(str, "badmail=", 8)==0)
    { for (p=str+8; (*p==' ') || (*p=='\t'); p++);
      strcpy(badmail, p);
      canondir(badmail);
      continue;
    }
    if (strnicmp(str, "precedence=", 11)==0)
    { strcpy(precedence, str+11);
      continue;
    }
    if (strnicmp(str, "semdir=", 7)==0)
    { for (p=str+7; (*p==' ') || (*p=='\t'); p++);
      strcpy(semdir, p);
      canondir(semdir);
      continue;
    }
    if (strnicmp(str, "domain=", 7)==0)
    { strcpy(local, str+7);
      continue;
    }
    if (strnicmp(str, "maildir=", 8)==0)
    { strcpy(maildir, str+8);
      addslash(maildir);
      continue;
    }
    if (strnicmp(str, "logstyle=", 9) == 0)
    { if (stricmp(str+9, "fd") && stricmp(str+9, "bink"))
        goto invparam;
      continue;
    }
    if (strnicmp(str, "sentdir=", 8)==0)
    { for (p=str+8; (*p==' ') || (*p=='\t'); p++);
      strcpy(sentdir, p);
      canondir(sentdir);
      continue;
    }
    if (strnicmp(str, "incomplete=", 11)==0)
    { for (p=str+11; (*p==' ') || (*p=='\t'); p++);
      strcpy(incomplete, p);
      canondir(incomplete);
      continue;
    }
    for (i=0; i<sizeof(ignore)/sizeof(ignore[0]); i++)
      if (strnicmp(str, ignore[i], strlen(ignore[i]))==0)
        break;
    if (i<sizeof(ignore)/sizeof(ignore[0]))
      continue;
    logwrite('!', "Unknown line in %s ignored: %s\n", nconf, str);
  }
  close_tpl();
  /* разбираемся, чего не хватает */
  if (netdir[0]==0)
  { logwrite('?', "Parameter NETMAIL not specified!\n");
    return RET_ERR;
  }
  if (pktout[0]==0)
  { logwrite('?', "Parameter PKTOUT not specified!\n");
    return RET_ERR;
  }
  if ((uupcdir[0]==0) && (uupcver!=SENDMAIL))
  { logwrite('?', "Parameter UUPC not specified!\n");
    return RET_ERR;
  }
  if (rmail[0]==0)
  { if (uupcver==SENDMAIL)
      strcpy(rmail, "sendmail" EXEEXT " -i");
    else
      strcpy(rmail, "rmail" EXEEXT);
  }
#ifndef UNIX
  if ((rmail[1]!=':') || (rmail[2]!='\\')) 
    if (uupcver!=SENDMAIL)
    { p=strrchr(rmail, '\\');
      if (p==NULL)
      { p=strrchr(rmail, ':');
        if (p==NULL)
          p=rmail;
      }
      strcpy(str, p);
      strcpy(rmail, uupcdir);
      strcat(rmail, str);
    }
#if 0
    else
    { p=strrchr(rmail, '\\');
      if (p==NULL)
      { p=strrchr(rmail, ':');
        if (p==NULL)
          p=rmail;
      }
      strcpy(str, p);
#ifdef __OS2__
      expand_path(str, rmail);
#endif
    }
#ifdef __MSDOS__
  if (uupcver!=SENDMAIL)
#endif
  { p=strpbrk(rmail, " \t");
    if (p) *p='\0';
    if (access(rmail, 0))
    { logwrite('?', "Can't find %s!\n", rmail);
      return RET_ERR;
    }
    if (p) *p=' ';
  }
#endif
  debug(6, "Config: rmail is '%s'", rmail);
  if (uupcdir[0]==0)
  { for (i=0; i<nhosts; i++)
    if (hosts[i].enc==ENC_UUCP)
    { logwrite('?', "You must specify UUPC= if you use route-files!\n");
      return RET_ERR;
    }
  }
#endif
  if (pgpenc_fmt[0]==0)
  { for (i=0; i<nhosts; i++)
    if (hosts[i].enc==ENC_PGP)
    { logwrite('?', "You must specify pgp-encode= if you use /pgp!\n");
      return RET_ERR;
    }
  }
  if (pgpcheck_fmt[0]==0 || pgpsign_fmt[0]==0)
  { for (i=0; i<nhosts; i++)
    if (hosts[i].pgpsig)
    { logwrite('?', "You must specify pgp-check and pgp-sign if you use /sign!\n");
      return RET_ERR;
    }
  }  

#ifndef UNIX
  if (uupcdir[0])
  {
    if (uupcver==KENDRA)
    { p=getenv("UUPCSYSRC");
      if (p==NULL)
      { logwrite('?', "Environment variable UUPCSYSRC must be specified!\n");
        return 1;
      }
      strcpy(str, p);
      strcpy(confdir, p);
      p=strrchr(confdir, PATHSEP);
      if (p) p[1]='\0';
    }
    else
    { strcpy(str, uupcdir);
      strcat(str, "conf" PATHSTR "uupc.rc");
    }
    inconfig=2;
    debug(6, "Config: uupc sys rc is '%s'", str);
    if (init_tpl(str))
      return RET_ERR;
    mailext[0]='\0';
    filebox[0]='\0';
    while (configline(str, sizeof(str)))
    {
      if ((strnicmp(str, "domain=", 7)==0) && (local[0]==0))
      { for (p=str+7; (*p==' ') || (*p=='\t'); p++);
        strcpy(local, p);
        p=strpbrk(local, " \t\n\r");
        if (p) *p=0;
        continue;
      }
      if ((strnicmp(str, "tz=", 3)==0) && (tz==0))
      { if (getmytz(str+3, &tz))
          goto invparam;
        debug(6, "Config: GetTZ('%s') is %d", str+9, tz);
        continue;
      }
      if (uupcver==KENDRA)
      { if (strnicmp(str, "mailext=", 8)==0)
        { for (p=str+8; (*p==' ') || (*p=='\t'); p++);
          strcpy(mailext, p);
          p=strpbrk(mailext, " \t\n\r");
          if (p) *p=0;
          continue;
        }
        if (strnicmp(str, "confdir=", 8)==0)
        { for (p=str+8; (*p==' ') || (*p=='\t'); p++);
          strcpy(confdir, p);
          p=strpbrk(confdir, " \t\n\r");
          if (p) *p=0;
          addslash(confdir);
          continue;
        }
        if (strnicmp(str, "postmaster=", 11)==0)
        { if (stricmp(postmaster, "postmaster"))
            continue;
          for (p=str+11; (*p==' ') || (*p=='\t'); p++);
          strcpy(postmaster, p);
          p=strpbrk(postmaster, " \t\n\r");
          if (p) *p=0;
          continue;
        }
      }
      if ((strnicmp(str, "maildir=", 8)==0) && (maildir[0]==0))
      { if (user[0]=='\0')
          continue;
        for (p=str+8; (*p==' ') || (*p=='\t'); p++);
        strcpy(maildir, p);
        p=strpbrk(maildir, " \t\n\r");
        if (p) *p=0;
        addslash(maildir);
        if ((uupcver!=6) && (uupcver!=KENDRA) && (uupcver!=SENDMAIL))
          strcat(maildir, "boxes" PATHSTR);
        continue;
      }
#ifdef __MSDOS__
      if (use_swap==-1 && strnicmp(str, "swap=", 5)==0)
      { use_swap = USE_FILE;
        for (p=str+5; *p; p++)
          switch(tolower(*p))
          { case 'd':
            case 'f':  use_swap|=USE_FILE; continue;
            case 'e':  use_swap|=USE_EMS;
                       if (use_swap & USE_XMS) use_swap|=XMS_FIRST;
                       continue;
            case 'x':  use_swap|=USE_XMS;  continue;
            case ' ':
            case '\t':
            case '\n': continue;
            default:   logwrite('!', "Unknown swap method %c ignored\n", tolower(*p));
                       continue;
          }
      }
#endif
    }
    close_tpl();
    if (maildir[0]==0)
    { strcpy(maildir, uupcdir);
      strcat(maildir, "mail" PATHSTR);
      if (uupcver!=KENDRA)
        strcat(maildir, "boxes" PATHSTR);
    }
  }
#endif
  if (user[0]==0)
  { logwrite('!', "Parameter filebox not defined!\n");
    strcpy(user, postmaster);
  }
  else
  { if (maildir[0])
    { strcpy(filebox, maildir);
      strcat(filebox, user);
      if (mailext[0])
      { strcat(filebox, ".");
        strcat(filebox, mailext);
      }
    }
  }
  if (filebox[0])
    debug(6, "Config: filebox is '%s'", filebox);
  if (local[0]==0)
  { strcpy(local, "localhost");
    if (uupcver!=SENDMAIL)
      strcat(local, ".uucp");
    logwrite('!', "Local domain not defined, set to %s\n", local);
  }
  debug(6, "Config: local domain is '%s'", local);
#ifndef __MSDOS__
  if (mydomain[0])
  { for(i=0; i<nhosts; i++)
      if (hosts[i].domain[0]=='\0')
      { strncpy(hosts[i].domain, mydomain, sizeof(hosts[i].domain));
        hosts[i].domain[sizeof(hosts[i].domain)-1]='\0';
      }
  }
#endif
  if (uupcver==112)
  { /* set UUPCUSRRC */
    strcpy(str,"UUPCUSRRC=");
    p=str+strlen(str);
    strcat(str, confdir);
    strcat(str, user);
    strcat(str, ".rc");
    if (access(p, 0))
    { logwrite('?', "Can't find %s!\n", p);
      return 1;
    }
    putenv(strdup(str));
    debug(6, "Config: putenv %s", str);
  }
  if (badmail[0]=='\0')
    strcpy(badmail, tmpdir);
  if (sentdir[0]=='\0')
  { strcpy(sentdir, tmpdir);
    addslash(sentdir);
    strcat(sentdir, "sent");
    mkdir(sentdir);
  }
  if (incomplete[0]=='\0')
  { strcpy(incomplete, tmpdir);
    addslash(incomplete);
    strcat(incomplete, "partial");
    mkdir(incomplete);
  }
  if (tz==0)
  { time_t ltime, curtime; 
    struct tm *ltm;
    tzset();
    curtime = time(NULL);
    ltm = localtime(&curtime);
    ltm->tm_isdst=0;
    ltime = mktime(ltm);
    ltm = gmtime(&curtime);
    ltm->tm_isdst=0;
    curtime = mktime(ltm);
    tz = (int)((curtime-ltime)/3600);
    debug(6, "Set TZ=%d", tz);
  }
#ifdef __MSDOS__
  if (use_swap==-1)
    use_swap=USE_ALL;
#endif
  srand(getpid()+(int)time(NULL));
  return 0;
}
