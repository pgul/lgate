/*
 * $Id$
 *
 * $Log$
 * Revision 2.5  2002/11/17 20:55:26  gul
 * New option "tid" in gate.cfg
 *
 * Revision 2.4  2002/03/21 13:43:26  gul
 * Remove dest addr list length limitation
 *
 * Revision 2.3  2001/01/21 10:20:00  gul
 * new cfg param 'fromtop'
 *
 * Revision 2.2  2001/01/19 17:52:59  gul
 * Translate comments and cosmetic changes
 *
 * Revision 2.1  2001/01/15 03:37:08  gul
 * Stack overflow in dos-version fixed.
 * Some cosmetic changes.
 *
 * Revision 2.0  2001/01/10 20:42:17  gul
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
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include <time.h>
#include <errno.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#if defined(__MSDOS__)
#include "exec.h"
#elif defined(__OS2__)
#include <os2.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#include "lib.h"
#include "import.h"
#include "gate.h"

#include "koi8-r.h"
#include "koi8-u.h"
#include "cp866.h"
#include "cp1125.h"
#include "cp1251.h"

#ifdef UNIX
#define fullpath(str)  (*(str)=='/')
#else
#define fullpath(str)  (*(str) && (str)[1]==':' && (str)[2]=='\\')
#endif

unsigned lines;
char remote[80], local[80];
char badmail[FNAME_MAX];
char fidosystem[80]="fidonet"; /* only for "From " field */
unsigned maxcnews;
int  tz;
char echolog, fscmsgid;
int  uucode, rcv2via, savehdr, touucp, byuux, deltransfiles;
int  use_swap;
int  nonet, noecho, tossbad, fake;
int  hdr8bit=1;
#ifndef UNIX
int  uupcver;
#endif
char nconf[FNAME_MAX], tpl_name[FNAME_MAX];
char extsetname[128], intsetname[128];
int  notid;
static char s[64];
static char localdom[80];
#ifndef UNIX
static char postmast[80], conf_dir[FNAME_MAX]="";
static char uupcdir[FNAME_MAX];
#endif
static char uux[FNAME_MAX];
static char _Far *echonames;
static long lechonames;
static int fout;
static uword z, nt, nd, pt;
static char extcharset[FNAME_MAX];
#ifdef DO_PERL
char perlfile[FNAME_MAX] = "";
#endif

extern char charset[];
extern int  validlen;

static char *ignore[]={
"held-tpl=",
"badaddr-tpl=",
"maxhops=",
"pktsize=",
"user=",
"route-files",
"route-uue",
"filebox=",
"newecho=",
"size=",
"attrib=",
"maxuue=",
"golded=",
"domain-id=",
"holdpath=",
"holdsize=",
"errors-to=",
"upper=",
"norm-only=",
"tabsize=",
"resend-bad=",
"itwit=",
"itwit-",
"uncompress=",
"rel2fido-chk",
"rel2fido-flt",
"fido2rel-flt",
"myorigin=",
"route-split",
"unsecure=",
"uudecode=",
"uuencode=",
"softCR=",
"precedence=",
"semdir=",
"via=",
"replyto=",
"log=",
"decode-attach=",
"maildir=",
"newsdir=",
"split-multipart=",
"kill-vcard=",
"honour-alternate=",
"hold-huge=",
"split-reports=",
"pgp-",
"sentdir=",
"incomplete=",
"rel2fido-chk-pl=",
"put-chrs="
};

static void addftncharset(char *ftn, char *rfc)
{
  struct ftnchrs_type *fp;
  
  if (ftnchrs == NULL)
  { ftnchrs=malloc(sizeof(*fp)+strlen(ftn)+strlen(rfc)+2);
    fp=ftnchrs;
  }
  else
  { for (fp=ftnchrs; fp->next; fp=fp->next);
    fp->next=malloc(sizeof(*fp)+strlen(ftn)+strlen(rfc)+2);
    fp=fp->next;
  }
  if (fp==NULL)
  { logwrite('!', "Not enough memory for fido-charset!\n");
    return;
  }
  fp->next=NULL;
  fp->ftnchrs=(char *)fp+sizeof(*fp);
  strcpy(fp->ftnchrs, ftn);
  fp->rfcchrs=fp->ftnchrs+strlen(ftn)+1;
  strcpy(fp->rfcchrs, rfc);
}

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
  if (*p!='\\')
  { str[2]='\\';
#ifdef __OS2__
    { int i=sizeof(str)-3;
      DosQueryCurrentDir(tolower(str[0])-'a'+1, str+3, (unsigned long *)&i);
    }
#else
    getcurdir(tolower(str[0])-'a'+1, str+3);
#endif
    if (str[3]) strcat(str, "\\");
  }
  strcat(str, p);
  if (str[strlen(str)-1]!='\\')
    strcat(str, "\\");
  strcpy(dir, str);
#else
  if (*dir!='/')
  { getcwd(str, sizeof(str));
    strcat(str, "/");
    strcat(str, dir);
    strcpy(dir, str);
  }
  if (dir[strlen(dir)-1]!='/')
    strcat(dir, "/");
#endif
}

#ifndef UNIX
static void canonuucpdir(char *dir)
{ char *p;

  if ((dir[1]==':') && dir[0])
  { str[0]=dir[0]|0x20;
    p=dir+2;
  }
  else
  { str[0]=uupcdir[0];
    p=dir;
  }
  str[1]=':';
  str[2]=0;
  if (*p!=PATHSEP)
    strcpy(str+2, uupcdir+2);
  strcat(str, p);
  addslash(str);
  strcpy(dir, str);
  debug(10, "CanonUucpDir: canonical name for %s is %s", dir, str);
  return;
}
#endif

static void *galloc(long bytes)
{
  if (bytes==0)
    return (void *)1; /* anything but not NULL */
#ifdef __MSDOS__
  if (bytes>=0x8000)
    return NULL;
#endif
  return malloc((int)bytes);
}

int gettwitstr(char *str, struct addrtype *twit)
{ char *p, *p1;

  p=strchr(str, '=')+1;
  while ((*p==' ') || (*p=='\t')) p++;
  if ((*p==0) || (*p=='\n'))
  {
errtwit:
    logwrite('?', "Invalid string in config: %s\n", str);
    return 3;
  }
  /* twit=2:463/83 Sergey Babitch */
  /* twit=2:463/68 */
  p1=strpbrk(p, " \t");
  if (p1)
    *p1=0;
  if (getfidomask(p, (ftnaddr *)twit, myaka[0].zone))
    goto errtwit;
  twit->from[0]=0;
  if (p1==NULL)
    return 0;
  p=p1+1;
  while ((*p==' ') || (*p=='\t')) p++;
  if ((*p=='\n') || (*p==0))
    return 0;
  strcpy(twit->from, p);
  p=twit->from+strlen(twit->from);
  while ((*p=='\n') || (*p==' ') || (*p=='\t'))
    p--;
  *(p+1)=0;
  return 0;
}
      
#ifdef __MSDOS__
static void setswap(char *str)
{
  use_swap=USE_FILE;
  for (; *str; str++)
    switch(tolower(*str))
    { case 'f':  use_swap|=USE_FILE; continue;
      case 'e':  use_swap|=USE_EMS;
                 if (use_swap & USE_XMS) use_swap|=XMS_FIRST;
                 continue;
      case 'x':  use_swap|=USE_XMS;  continue;
      case ' ':
      case '\t':
      case '\n': continue;
      default:   logwrite('!', "Unknown swap method %c ignored\n", tolower(*str));
                 continue;
    }
}
#endif

int config(void)
{ int i;
  char *p, *p1;

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
  tmpdir[0]=0;
  p=getenv("TEMP");
  if (p==NULL)
    p=getenv("TMP");
  if (p)
    strcpy(tmpdir, p);
  if (tmpdir[0]==0)
#ifdef UNIX
    strcpy(tmpdir, "/tmp");
#else
    getcwd(tmpdir, sizeof(tmpdir));
#endif
  canondir(tmpdir);
#ifndef UNIX
  uupcdir[0]=0;
#endif
  rmail[0]=netmaildir[0]=logname[0]=pktin[0]=pktout[0]=badmail[0]=0;
  organization[0]=master[0]=pktpwd[0]=binkout[0]=tpl_name[0]=0;
#ifndef __MSDOS__
  lbso[0]=tlboxes[0]=longboxes[0]='\0';
#endif
  tboxes[0]='\0';
  local[0]=remote[0]=extcharset[0]=0;
  extsetname[0]=intsetname[0]=0;
  maxrcv=0;
  naka=0;
  ngroups=0;
  ncaddr=npaddr=ncdomain=ntwit=nnotwit=nalias=nmoder=nchecker=nattfrom=0;
  nsend=nrej=nfree=0;
  lechonames=0;
  ngates=0;
  nuplink=0;
  maxcnews=100;
  uucode=0;
  rcv2via=1;
  savehdr=1;
  deltransfiles=0;
  touucp=1;
  byuux=1;
  fscmsgid=0;
  tz=0;
  gatevia=1;
  xcomment=0;
  echolog=0;
#ifndef UNIX
  uupcver=5;
#endif
  bangfrom=1;
  env_chaddr=0;
  fromtop=0;
#ifdef __MSDOS__
  use_swap=-1;
#endif
  compress[0]=uux[0]=rnews[0]=inb_dir[0]='\0';
  hidetear=hideorigin=fsp1004=0;
  charsetsdir[0]=charsetalias[0]='\0';
  notid=0;
  p1=getenv("TZ");
  if (p1)
    getmytz(p1, &tz);
  to=malloc(sizeto=128);
  gw_to=malloc(sizegw_to=128);
  if (to==NULL || gw_to==NULL) goto memory;

  /***** first pass - count ncaddr, nechoes etc. *****/
  tplout=0;
  if (init_tpl(nconf))
    return 2;
  setglobal("Module", "Fido2Rel");
  while (configline(str, sizeof(str)))
  {
    if (strnicmp(str, "group", 5)==0)
    { ngroups++;
      naka++;
      continue;
    }
    if (strnicmp(str, "conference", 10)==0)
    { /* format: "conference <rfc-name> <ftn-name>" */
      if (ngroups==0) continue;
      for (p=str+10; (*p==' ') || (*p=='\t'); p++);
      p1=strpbrk(p, " \t");
      if (p1==NULL) continue;
      *p1=0;
      strupr(p);
      lechonames+=strlen(p)+1;
      *p1=' ';
      for (p=p1+1; (*p==' ') || (*p=='\t'); p++);
      p1=strpbrk(p, " \t");
      if (p1) continue;
      lechonames+=strlen(p)+1;
      nechoes++;
      continue;
    }
    if ((strnicmp(str, "route-to", 8)==0) ||
        (strnicmp(str, "to-ifmail", 9)==0) ||
        (strnicmp(str, "no-route", 8)==0))
    { ngates++;
      continue;
    }
    if (strnicmp(str, "chdomain", 8)==0)
    { ncdomain++;
      continue;
    }
    if (strnicmp(str, "send-to=", 8)==0)
    { nsend++;
      continue;
    }
    if (strnicmp(str, "free=", 5)==0)
    { nfree++;
      continue;
    }
    if (strnicmp(str, "no-send=", 8)==0)
    { nrej++;
      continue;
    }
    if ((strnicmp(str, "address=", 8)==0) ||
        (strnicmp(str, "aka=", 4)==0))
    { naka++;
      continue;
    }
    if (strnicmp(str, "uplink=", 7)==0)
    { nuplink++;
      continue;
    }
    if (strnicmp(str, "chaddr=", 7)==0)
    { ncaddr++;
      continue;
    }
    if (strnicmp(str, "privel=", 7)==0)
    { npaddr++;
      continue;
    }
    if (strnicmp(str, "twit=", 5)==0)
    { ntwit++;
      continue;
    }
    if (strnicmp(str, "no-twit=", 8)==0)
    { nnotwit++;
      continue;
    }
    if (strnicmp(str, "attach-from=", 12)==0)
    { nattfrom++;
      continue;
    }
    if (strnicmp(str, "alias", 5)==0)
    { nalias++;
      continue;
    }
    if (strnicmp(str, "moderator", 9)==0)
    { nmoder++;
      continue;
    }
    if (strnicmp(str, "fido2rel-chk", 12)==0)
    { nchecker++;
      continue;
    }
    if (strnicmp(str, "charsets-dir=", 13)==0)
    { strcpy(charsetsdir, "nul");
      continue;
    }
    if (strnicmp(str, "log=", 4)==0)
    { if (strpbrk(str+4, "\\:/"))
        strcpy(logname, str+4);
      else
      { /* if path not specified, to start dir */
#ifdef UNIX
        strcpy(logname, "/var/log/");
#else
        strcpy(logname, myname);
#endif
        p=strrchr(logname, PATHSEP);
        if (p==NULL) p=logname;
        else p++;
        strcpy(p, str+4);
      }
      continue;
    }
    if (strnicmp(str, "logstyle=", 9) == 0)
    { if (stricmp(str+9, "fd")==0)
        logstyle=FD_LOG;
      else if (stricmp(str+9, "bink")==0)
        logstyle=FE_LOG;
      continue;
    }
  }
  close_tpl();
  if (logname[0]==0)
  {
#ifdef UNIX
    strcpy(logname, "/var/log/");
#else
    strcpy(logname, myname);
#endif
    p=strrchr(logname, PATHSEP);
    if (p==NULL) p=logname;
    else p++;
    strcpy(p, "lgate.log");
  }
  if (access(logname, 0))
  { fout=myopen(logname, O_RDWR|O_CREAT);
    if (fout==-1)
    { puts("Can't create log-file!");
      return 3;
    }
    close(fout);
  }
  /* allocate memory */
  uplink=galloc(nuplink*(long)sizeof(uplink[0]));
  if (uplink==NULL)
  {
memory:
    logwrite('?', "Not enough memory!\n");
    return 7;
  }
  send_to=galloc(nsend*(long)sizeof(send_to[0]));
  if (send_to==NULL) goto memory;
  rej=galloc(nrej*(long)sizeof(rej[0]));
  if (rej==NULL) goto memory;
  sfree=galloc(nfree*(long)sizeof(sfree[0]));
  if (sfree==NULL) goto memory;
  group=galloc(ngroups*(long)sizeof(group[0]));
  if (group==NULL) goto memory;
  if (nechoes)
  { 
#ifdef __MSDOS__
    echoes=farmalloc(nechoes*(long)sizeof(echoes[0]));
    echonames=farmalloc(lechonames);
#else
    echoes=malloc(nechoes*sizeof(echoes[0]));
    echonames=malloc((int)lechonames);
#endif
    if (echoes==NULL || echonames==NULL) goto memory;
  }
  gates=galloc(ngates*(long)sizeof(gates[0]));
  if (gates==NULL) goto memory;
  cdomain=galloc(ncdomain*(long)sizeof(cdomain[0]));
  if (cdomain==NULL) goto memory;
  caddr=galloc(ncaddr*(long)sizeof(caddr[0]));
  if (caddr==NULL) goto memory;
  paddr=galloc(npaddr*(long)sizeof(paddr[0]));
  if (paddr==NULL) goto memory;
  twit=galloc(ntwit*(long)sizeof(twit[0]));
  if (twit==NULL) goto memory;
  notwit=galloc(nnotwit*(long)sizeof(notwit[0]));
  if (notwit==NULL) goto memory;
  attfrom=galloc(nattfrom*(long)sizeof(attfrom[0]));
  if (attfrom==NULL) goto memory;
  myaka=galloc(naka*(long)sizeof(myaka[0]));
  if (myaka==NULL) goto memory;
  alias=galloc(nalias*(long)sizeof(alias[0]));
  if (alias==NULL) goto memory;
  moderator=galloc(nmoder*(long)sizeof(moderator[0]));
  if (moderator==NULL) goto memory;
  checker=galloc(nchecker*(long)sizeof(checker[0]));
  if (checker==NULL) goto memory;
  if (naka)
    myaka[0].zone=2;
  else
  { logwrite('?', "Address not specified!\n");
    return 3;
  }
  nuplink=nsend=nrej=nfree=ngroups=nechoes=ngates=ncdomain=ncaddr=
          npaddr=ntwit=nnotwit=naka=nalias=nmoder=nchecker=nattfrom=0;
  lechonames=0;

  /***** second pass - all the rest *****/
  if (init_tpl(nconf))
    return 2;
  tplout=1;
  while (configline(str, sizeof(str)))
  {
    if (strnicmp(str, "display ", 8)==0)
    { logwrite('$', "%s\n", str+8);
      continue;
    }
#ifndef UNIX
    if (strnicmp(str, "uupc=", 5)==0)
    { if (!fullpath(str+5))
        goto notfull;
      strcpy(uupcdir, str+5);
      removeslash(uupcdir);
      continue;
    }
    if (strnicmp(str, "uupcver=", 8)==0)
    { if (strnicmp(str+8, "kendra", 6)==0)
      { strcpy(charset, DOSCHARSEXT);
        validlen=VALIDLEN_EXT;
        uupcver=KENDRA;
      }
      else if (strncmp(str+8, "5", 1)==0)
      { strcpy(charset, DOSCHARS5);
        validlen=VALIDLEN_ACHE;
        uupcver=5;
      }
      else if (strncmp(str+8, "6.14h", 5)==0)
      { strcpy(charset, DOSCHARS614H);
        validlen=VALIDLEN_ACHE;
        uupcver=614;
      }
      else if (strncmp(str+8, "6.15", 4)==0)
      { strcpy(charset, DOSCHARS614H);
        validlen=VALIDLEN_ACHE;
        uupcver=615;
      }
      else if (strncmp(str+8, "6", 1)==0)
      { strcpy(charset, DOSCHARS6);
        validlen=VALIDLEN_ACHE;
        uupcver=6;
      }
      else if (strncmp(str+8, "7", 1)==0)
      { uupcver=615;
        strcpy(charset, DOSCHARS614H);
        validlen=VALIDLEN_ACHE;
      }
      else if (strnicmp(str+8, "sendmail", 8)==0)
        uupcver=SENDMAIL;
      else
        goto invparam;
      continue;
    }
#endif
    if (strnicmp(str, "rmail=", 6)==0)
    { strcpy(rmail, str+6);
      continue;
    }
    if (strnicmp(str, "timezone=", 9)==0)
    { if (getmytz(str+9, &tz))
invparam:
        logwrite('!', "Invalid value %s ignored!\n", str);
      continue;
    }
    if (strnicmp(str, "uucode=", 7)==0)
    { if (tolower(str[7])=='y')
        uucode=1;
      else if (tolower(str[7])=='n')
        uucode=0;
      else
        goto invparam;
      continue;
    }
#ifndef UNIX
    if (strnicmp(str, "by-uux=", 7)==0)
    { if (tolower(str[7])=='y')
        byuux=1;
      else if (tolower(str[7])=='n')
        byuux=0;
      else
        goto invparam;
      continue;
    }
#endif
    if (strnicmp(str, "echolog=", 8)==0)
    { if (tolower(str[8])=='y')
        echolog=1;
      else if (tolower(str[8])=='n')
        echolog=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "rcv2via=", 8)==0)
    { if (tolower(str[8])=='y')
        rcv2via=1;
      else if (tolower(str[8])=='n')
        rcv2via=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "gatevia=", 8)==0)
    { if (tolower(str[8])=='n' || tolower(str[8])=='y')
        gatevia=0;
      else if (tolower(str[8])=='a')
        gatevia=1;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "to-uucp=", 8)==0)
    { if (tolower(str[8])=='y')
        touucp=1;
      else if (tolower(str[8])=='n')
        touucp=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "message-id=", 11)==0)
    { if (strnicmp(str+11, "fsc", 3)==0)
        fscmsgid=1;
      else if (strnicmp(str+11, "if", 2)==0)
        fscmsgid=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "savehdr=", 8)==0)
    { if (tolower(str[8])=='y')
        savehdr=1;
      else if (tolower(str[8])=='n')
        savehdr=0;
      else if (tolower(str[8])=='a')
        savehdr=2;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "hide-tearline=", 14)==0)
    { if (tolower(str[14])=='y')
        hidetear=3;
      else if (tolower(str[14])=='n' && tolower(str[15])=='e')
        hidetear=1; /* netmail */
      else if (tolower(str[14])=='n')
        hidetear=0;
      else if (tolower(str[14])=='e')
        hidetear=2;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "hide-origin=", 12)==0)
    { if (tolower(str[12])=='y')
        hideorigin=3;
      else if (tolower(str[12])=='n' && tolower(str[13])=='e')
        hideorigin=1; /* netmail */
      else if (tolower(str[12])=='n')
        hideorigin=0;
      else if (tolower(str[12])=='e')
        hideorigin=2;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "pack=", 5)==0)
    { if (tolower(str[5])=='y')
        packmail=1;
      else if (tolower(str[5])=='n')
        packmail=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "netmail=", 8)==0)
    { if (!fullpath(str+8))
      { 
notfull:
        *strchr(str, '=')='\0';
        logwrite('?', "You must specify FULL path to your %s directory!\n", str);
        closeall();
        return 3;
      }
      strcpy(netmaildir, str+8);
      removeslash(netmaildir);
      continue;
    }
    if (strnicmp(str, "binkout=", 8)==0)
    {
      if (!fullpath(str+8))
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
    {
      if (!fullpath(str+7))
        goto notfull;
      strcpy(tboxes, str+7);
      addslash(tboxes);
      continue;
    }
    if (strnicmp(str, "badmail=", 8)==0)
    {
      if (!fullpath(str+8))
        goto notfull;
      strcpy(badmail, str+8);
      removeslash(badmail);
      continue;
    }
    if (strnicmp(str, "pktin=", 6)==0)
    {
      if (!fullpath(str+6))
        goto notfull;
      strcpy(pktin, str+6);
      addslash(pktin);
      continue;
    }
    if (strnicmp(str, "pktout=", 7)==0)
    {
      if (!fullpath(str+7))
        goto notfull;
      strcpy(pktout, str+7);
      addslash(pktout);
      continue;
    }
    if (strnicmp(str, "inb-dir=", 8)==0)
    {
      if (!fullpath(str+8))
        goto notfull;
      strcpy(inb_dir, str+8);
      addslash(inb_dir);
      continue;
    }
    if (strnicmp(str, "organization=", 13)==0)
    { strcpy(organization, str+13);
      continue;
    }
    if (strnicmp(str, "temp=", 5)==0)
    { strcpy(tmpdir, str+5);
      canondir(tmpdir);
      continue;
    }
    if (strnicmp(str, "cnewssize=", 10)==0)
    { i=atoi(str+10);
      if (i==0)
        goto invparam;
      maxcnews=i;
      continue;
    }
    if (strnicmp(str, "group", 5)==0)
    { /* format:  "group <distribution> <remote> [<switches>]" */
      /* switches: /feed, /cnews, /dir /noseenby, /nosubj, /net=fidonet.org,
                   /extmsgid, /aka=2:463/68.128@fidonet.carrier.kiev.ua
      */
      group[ngroups].distrib[0]=group[ngroups].newsserv[0]=0;
      group[ngroups].domain[0]=0;
      group[ngroups].sb=1;
      group[ngroups].aka=0;
      group[ngroups].extmsgid=0;
      for(p=p1=str+5; p1; )
      { for (p=p1; (*p==' ') || (*p=='\t'); p++);
        if (*p=='\"')
          p1=strchr(++p, '\"');
        else
          p1=strpbrk(p, " \t");
        if (p1) *p1=0;
        if (*p!='/' || group[ngroups].newsserv[0]=='\0')
        { if (group[ngroups].distrib[0]==0)
          { strncpy(group[ngroups].distrib, p, sizeof(group[0].distrib)-1);
            if (p1) *p1=' ';
            continue;
          }
          if (group[ngroups].newsserv[0])
          { if (p1) *p1=' ';
            logwrite('?', "Incorrect GROUP string: %s\n", str);
            return 9;
          }
          strncpy(group[ngroups].newsserv, p, sizeof(group[0].newsserv)-1);
          if (p1) *p1=' ';
          if (strchr(group[ngroups].newsserv, PATHSEP))
            group[ngroups].type=G_DIR;
          else if (strchr(group[ngroups].newsserv, '@'))
            group[ngroups].type=G_FEED;
          else
            group[ngroups].type=G_CNEWS;
          continue;
        }
        p++;
        if (stricmp(p, "noseenby")==0)
        { group[ngroups].sb=0;
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "feed")==0)
        { group[ngroups].type=G_FEED;
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "cnews")==0)
        { group[ngroups].type=G_CNEWS;
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "dir")==0)
        { group[ngroups].type=G_DIR;
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "noxc")==0)
        { if (p1) *p1=' ';
          continue;
        }
        if (strnicmp(p, "net=", 4)==0)
        { strncpy(group[ngroups].domain, p+4, sizeof(group[0].domain)-1);
          if (p[4]==0)
            strcpy(group[ngroups].domain, "@");
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "nosubj")==0)
        { if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "extmsgid")==0)
        { group[ngroups].extmsgid=1;
          if (p1) *p1=' ';
          continue;
        }
        if (strnicmp(p, "aka=", 4))
        { logwrite('!', "Incorrect switch %s in group line ignored!\n", p-1);
          if (p1) *p1=' ';
          continue;
        }
        /* aka */
        if (getfidoaddr(&z, &nt, &nd, &pt, p+4))
        { printf("Incorrect fido address in switch %s ignored!\n", p-1);
          if (p1) *p1=' ';
          continue;
        }
        p+=4;
        if (strpbrk(p, "%@"))
          strcpy(s, strpbrk(p, "%@")+1);
        else
          s[0]=0;
        if (p1) *p1=' ';
        /* find this aka */
        for (i=0; i<naka; i++)
        { if ((z!=myaka[i].zone) || (nt!=myaka[i].net) ||
             (nd!=myaka[i].node) || (pt!=myaka[i].point))
            continue;
          if (s[0]==0)
            break;
          if (stricmp(s, myaka[i].domain)==0)
            break;
        }
        if (i<naka)
        { group[ngroups].aka=i;
          continue;
        }
        if (s[0]==0)
        { logwrite('?', "%u:%u/%u.%u is not my aka, domain is requied!\n",
                   z, nt, nd, pt);
          continue;
        }
        logwrite('!', "%u:%u/%u.%u%c%s is not my aka!\n", z, nt, nd, pt,
                     strchr(s, '@') ? '@' : '%', s);
        myaka[naka].zone=z;
        myaka[naka].net=nt;
        myaka[naka].node=nd;
        myaka[naka].point=pt;
        strncpy(myaka[naka].domain, s, sizeof(myaka[0].domain)-1);
        group[ngroups].aka=naka;
        naka++;
        continue;
      }
      if (naka==0)
      { logwrite('?', "No address specified before GROUP string!\n");
        return 9;
      }
      if (group[ngroups].newsserv[0]==0)
      { logwrite('?', "Incorrect GROUP string %s!\n", str);
        return 9;
      }
      if (group[ngroups].domain[0]==0)
        strcpy(group[ngroups].domain, myaka[group[ngroups].aka].domain);
      p=strpbrk(group[ngroups].domain, "%@");
      if (p) *p='\0';
      if (group[ngroups].type==G_DIR)
      { p1=group[ngroups].newsserv+strlen(group[ngroups].newsserv)-1;
        if (*p1==PATHSEP)
          *p1=0;
        else
          p1++;
        mkdir(group[ngroups].newsserv);
        strcpy(p1, PATHSTR);
      }
      ngroups++;
      continue;
    }
    if (strnicmp(str, "conference", 10)==0)
    { /* format: "conference <rfc-name> <ftn-name>" */
      if (ngroups==0)
      { logwrite(9, "Conference group not defined!\n");
        return 9;
      }
      for (p=str+10; (*p==' ') || (*p=='\t'); p++);
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      *p1=0;
      strupr(p);
      echoes[nechoes].fido=(char _Far *)((char _Huge *)echonames+lechonames);
      strcpy(echoes[nechoes].fido, p);
      lechonames+=strlen(p)+1;
      *p1=' ';
      for (p=p1+1; (*p==' ') || (*p=='\t'); p++);
      p1=strpbrk(p, " \t");
      if (p1)
        goto invparam;
      echoes[nechoes].usenet=(char _Far *)((char _Huge *)echonames+lechonames);
      strcpy(echoes[nechoes].usenet, p);
      lechonames+=strlen(p)+1;
      echoes[nechoes].group=ngroups-1;
      nechoes++;
      continue;
    }
    if (strnicmp(str, "fidosystem=", 11)==0)
    { strcpy(fidosystem, str+11);
      /* fidosystem[8]=0; */
      continue;
    }
    if ((strnicmp(str, "route-to", 8)==0) ||
        (strnicmp(str, "to-ifmail", 9)==0))
    {
      for (p=str+9; (*p==' ') || (*p=='\t'); p++);
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      *p1=0;
      strncpy(gates[ngates].domain, p, sizeof(gates[0].domain)-1);
      gates[ngates].domain[sizeof(gates[0].domain)-1]=0;
      *p1=' ';
      for (p=p1+1; (*p==' ') || (*p=='\t'); p++);
      if (getfidomask(p, (ftnaddr *)(gates+ngates), myaka[0].zone))
      { puts("Incorrect route-to command:");
        puts(str);
        continue;
      }
      gates[ngates].pktfor.zone=gates[ngates].pktfor.net=
        gates[ngates].pktfor.node=gates[ngates].pktfor.point=0;
      gates[ngates].pktfor.ftndomain[0]=0;
      for (p++; (*p!=' ') && (*p!='\t') && *p; p++); /* skip mask */
      if (*p)
        for (p++; (*p==' ') || (*p=='\t'); p++);
      if (strnicmp(p, "/for=", 5)==0)
      { if (getfidoaddr(&(gates[ngates].pktfor.zone), &(gates[ngates].pktfor.net),
                        &(gates[ngates].pktfor.node), &(gates[ngates].pktfor.point),
                        p+5))
          goto invparam;
        else if (gates[ngates].pktfor.zone==0)
          gates[ngates].pktfor.zone= (naka ? myaka[0].zone : 2);
        for (;*p && !isspace(*p) && *p!='@'; p++);
        if (*p=='@')
        { strncpy(gates[ngates].pktfor.ftndomain, p+1, sizeof(gates->pktfor.ftndomain));
          gates[ngates].pktfor.ftndomain[sizeof(gates->pktfor.ftndomain)-1]='\0';
          for (p=gates[ngates].pktfor.ftndomain; *p && !isspace(*p); p++);
          if (isspace(*p)) *p='\0';
        }
      }
      else if (*p)
        goto invparam;
/* Fine, but there can be different /for=  :-(
      if (gates[ngates].zone==(unsigned)-1)
      { memcpy(gates, gates+ngates, sizeof(gates[0]));
        ngates=0;
      }
*/
      if (strnicmp(str, "route-to", 8)==0)
        gates[ngates].yes=1;
      else
        gates[ngates].yes=2; /* to-ifmail */
      ngates++;
      continue;
    }
    if (strnicmp(str, "no-route", 8)==0)
    {
      for (p=str+8; (*p==' ') || (*p=='\t'); p++);
      if (getfidomask(p, (ftnaddr *)(gates+ngates), myaka[0].zone))
        goto invparam;
      gates[ngates].pktfor.zone=gates[ngates].pktfor.net=
        gates[ngates].pktfor.node=gates[ngates].pktfor.point=0;
      gates[ngates].domain[sizeof(gates[0].domain)-1]=0;
      for (p++; (*p!=' ') && (*p!='\t') && *p; p++); /* skip mask */
      if (*p)
        for (p++; (*p==' ') || (*p=='\t'); p++);
      if (strnicmp(p, "/for=", 5)==0)
      { if (getfidoaddr(&(gates[ngates].pktfor.zone), &(gates[ngates].pktfor.net),
                        &(gates[ngates].pktfor.node), &(gates[ngates].pktfor.point),
                        p+5))
          goto invparam;
        else if (gates[ngates].pktfor.zone==0)
          gates[ngates].pktfor.zone= (naka ? myaka[0].zone : 2);
        for (;*p && !isspace(*p) && *p!='@'; p++);
        if (*p=='@')
        { strncpy(gates[ngates].pktfor.ftndomain, p+1, sizeof(gates->pktfor.ftndomain));
          gates[ngates].pktfor.ftndomain[sizeof(gates->pktfor.ftndomain)-1]='\0';
          for (p=gates[ngates].pktfor.ftndomain; *p && !isspace(*p); p++);
          if (isspace(*p)) *p='\0';
        }
      }
      else if (*p)
        goto invparam;
/*
      if (gates[ngates].zone==(unsigned)-1)
      { ngates=0;
        continue;
      }
*/
      gates[ngates].domain[0]=0;
      gates[ngates].yes=0;
      ngates++;
      continue;
    }
    if (strnicmp(str, "chdomain", 8)==0)
    { p=strpbrk(str, " \t");
      if (p==NULL)
        goto invparam;
      if (p!=str+8)
        goto invparam;
      while ((*p==' ') || (*p=='\t')) p++;
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      if (p1-p>=sizeof(cdomain[0].relcom))
      { strncpy(cdomain[ncdomain].relcom, p, sizeof(cdomain[0].relcom)-1);
        cdomain[ncdomain].relcom[sizeof(cdomain[0].relcom)-1]=0;
      }
      else
      { strncpy(cdomain[ncdomain].relcom, p, (unsigned)(p1-p));
        cdomain[ncdomain].relcom[(unsigned)(p1-p)]=0;
      }
      for (p=p1; (*p==' ') || (*p=='\t'); p++);
      if (strpbrk(p, " \t"))
      if (p1==NULL)
        goto invparam;
      if (strlen(p)>=sizeof(cdomain[0].fido))
      { strncpy(cdomain[ncdomain].fido, p, sizeof(cdomain[0].fido)-1);
        cdomain[ncdomain].fido[sizeof(cdomain[0].fido)-1]=0;
      }
      else
        strcpy(cdomain[ncdomain].fido, p);
      ncdomain++;
      continue;
    }
    if (strnicmp(str, "alias", 5)==0)
    { p=strpbrk(str, " \t");
      if (p==NULL)
        goto invparam;
      if (p!=str+5)
        goto invparam;
      while ((*p==' ') || (*p=='\t')) p++;
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      if (p1-p>=sizeof(alias[0].from))
      { strncpy(alias[nalias].from, p, sizeof(alias[0].from)-1);
        alias[nalias].from[sizeof(alias[0].from)-1]=0;
      }
      else
      { strncpy(alias[nalias].from, p, (unsigned)(p1-p));
        alias[nalias].from[(unsigned)(p1-p)]=0;
      }
      for (p=p1; (*p==' ') || (*p=='\t'); p++);
      if (strpbrk(p, " \t"))
      if (p1==NULL)
        goto invparam;
      if (strlen(p)>=sizeof(alias[0].to))
      { strncpy(alias[nalias].to, p, sizeof(alias[0].to)-1);
        alias[nalias].to[sizeof(alias[0].to)-1]=0;
      }
      else
        strcpy(alias[nalias].to, p);
      nalias++;
      continue;
    }
    if (strnicmp(str, "moderator", 9)==0)
    { p=strpbrk(str, " \t");
      if (p==NULL)
        goto invparam;
      if (p!=str+9)
        goto invparam;
      while ((*p==' ') || (*p=='\t')) p++;
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      *p1=0;
      for (i=0; i<nechoes; i++)
        if (stricmp(p, echoes[i].usenet)==0)
          break;
      if (i==nechoes)
      { *p1=' ';
        logwrite('!', "Unknown echo \"%s\" in string %s!\n", p, str);
        continue;
      }
      *p1=' ';
      moderator[nmoder].echo=i;
      for (p=p1; (*p==' ') || (*p=='\t'); p++);
      if (strpbrk(p, " \t"))
      if (p1==NULL)
        goto invparam;
      *p1=0;
      if (strlen(p)>=sizeof(moderator[0].moderator))
      { strncpy(moderator[nmoder].moderator, p, sizeof(moderator[0].moderator)-1);
        moderator[nmoder].moderator[sizeof(moderator[0].moderator)-1]=0;
      }
      else
        strcpy(moderator[nmoder].moderator, p);
      nmoder++;
      continue;
    }
    if (strnicmp(str, "send-to=", 8)==0)
    {
      strcpy(send_to[nsend], str+8);
      nsend++;
      continue;
    }
    if (strnicmp(str, "free=", 5)==0)
    {
      strcpy(sfree[nfree], str+5);
      nfree++;
      continue;
    }
    if (strnicmp(str, "no-send=", 8)==0)
    {
      strcpy(rej[nrej], str+8);
      nrej++;
      continue;
    }
    if ((strnicmp(str, "address=", 8)==0) ||
        (strnicmp(str, "aka=", 4)==0))
    {
      p=strchr(str, '=');
      if (getfidoaddr(&myaka[naka].zone, &myaka[naka].net,
                      &myaka[naka].node, &myaka[naka].point, p+1))
      { logwrite('!', "%s is incorrect fido address!\n", p+1);
        continue;
      }
      p1=strchr(p, '@');
      if (p==NULL)
      { logwrite('?', "You must specify domain at ADDR/AKA string!\n");
        return 9;
      }
      p=strpbrk(p, "%@");
      strncpy(myaka[naka].domain, p+1, sizeof(myaka[0].domain)-1);
      myaka[naka].domain[sizeof(myaka[0].domain)-1]=0;
      while (*p && !isspace(*p)) p++;
      if (isspace(*p))
      { while (isspace(*p)) p++;
        strncpy(myaka[naka].ftndomain, myaka[naka].domain, sizeof(myaka->ftndomain));
        myaka[naka].ftndomain[sizeof(myaka->ftndomain)-1]='\0';
        strncpy(myaka[naka].domain, p, sizeof(myaka[0].domain)-1);
        myaka[naka].domain[sizeof(myaka[0].domain)-1]=0;
      }
      else
      { strncpy(myaka[naka].ftndomain, myaka[naka].domain, sizeof(myaka->ftndomain));
        myaka[naka].ftndomain[sizeof(myaka->ftndomain)-1]='\0';
        p=strchr(myaka[naka].ftndomain, '.');
        if (p) *p='\0';
      }
      naka++;
      continue;
    }
    if (strnicmp(str, "uplink=", 7)==0)
    {
      if (getfidoaddr(&uplink[nuplink].zone, &uplink[nuplink].net,
                      &uplink[nuplink].node, &uplink[nuplink].point, str+7))
      { logwrite('!', "%s is incorrect fido address!\n", str+7);
        continue;
      }
      nuplink++;
      continue;
    }
    if (strnicmp(str, "rescan=", 7)==0)
    { strcpy(rescan, str+7);
      continue;
    }
    if (strnicmp(str, "swap=", 5)==0)
    {
#ifdef __MSDOS__
      setswap(str+5);
#endif
      continue;
    }
    if (strnicmp(str, "chaddr=", 7)==0)
    { p=str+7;
      while ((*p==' ') || (*p=='\t')) p++;
      if (*p==0)
        goto invparam;
/* chaddr="Pavel Gulchouck" 2:463/68 gul@mercury.kiev.ua (Pavel Gulchouck) */
/* chaddr=SysOp 2:463/68 postmaster@mercury.kiev.ua (System Administrator) */
      if (*p=='\"')
      { p1=strchr(p+1, '\"');
        if (p1==NULL) goto invparam;
        *p1=0;
        strcpy(caddr[ncaddr].from, p+1);
        *p1='\"';
        p=p1+1;
      }
      else
      { p1=strpbrk(p, " \t");
        if (p1==NULL) goto invparam;
        *p1=0;
        strcpy(caddr[ncaddr].from, p);
        *p1=' ';
        p=p1+1;
      }
      while((*p==' ') || (*p=='\t'))
        p++;
      if ((*p==0) || (*p=='\n'))
        goto invparam;
      p1=strpbrk(p, " \t");
      if (p1==NULL) goto invparam;
      *p1=0;
      if (getfidoaddr(&(caddr[ncaddr].zone), &(caddr[ncaddr].net),
                      &(caddr[ncaddr].node), &(caddr[ncaddr].point), p))
      { *p1=' ';
        goto invparam;
      }
      *p1=' ';
      p=p1+1;
      while ((*p==' ') || (*p=='\t')) p++;
      if ((*p=='\n') || (*p==0)) goto invparam;
      strcpy(caddr[ncaddr].to, p);
      p=caddr[ncaddr].to+strlen(caddr[ncaddr].to);
      while ((*p=='\n') || (*p==' ') || (*p=='\t'))
        p--;
      *(p+1)=0;
      ncaddr++;
      continue;
    }
    if (strnicmp(str, "sysop=", 6)==0)
    { if (getfidoaddr(&mastzone, &mastnet, &mastnode, &mastpoint, str+6))
      { puts("Incorrect fido address in string:");
        puts(str);
        continue;
      }
      p=str+6;
      while ((*p==' ') || (*p=='\t')) p++;
      p=strpbrk(p, " \t");
      if (p==NULL)
        strcpy(master, "SysOp");
      while ((*p==' ') || (*p=='\t')) p++;
      if (*p==0)
        strcpy(master, "SysOp");
      else
        strcpy(master, p);
      continue;
    }
    if (strnicmp(str, "privel=", 7)==0)
    { if (gettwitstr(str, paddr+npaddr))
        return 3;
      npaddr++;
      continue;
    }
    if (strnicmp(str, "twit=", 5)==0)
    { if (gettwitstr(str, twit+ntwit))
        return 3;
      ntwit++;
      continue;
    }
    if (strnicmp(str, "no-twit=", 8)==0)
    { if (gettwitstr(str, notwit+nnotwit))
        return 3;
      nnotwit++;
      continue;
    }
    if (strnicmp(str, "attach-from=", 12)==0)
    { if (gettwitstr(str, attfrom+nattfrom))
        return 3;
      nattfrom++;
      continue;
    }
    if (strnicmp(str, "pktpwd=", 7)==0)
    { strncpy(pktpwd, str+7, 8);
      pktpwd[8]=0;
      strupr(pktpwd);
      continue;
    }
    if (strnicmp(str, "maxsize=", 8)==0)
    { if (!isdigit(str[8]))
      { logwrite('!', "Incorrect string in config: %s\n", str);
        logwrite('!', "Max message size set to default (%u Kb)\n", maxsize);
        continue;
      }
      maxsize=atoi(str+8);
      continue;
    }
    if (strnicmp(str, "max-received=", 13)==0)
    { i=atoi(str+13);
      if (i<0)
        goto invparam;
      maxrcv=i;
      continue;
    }
    if (strnicmp(str, "maxline=", 8)==0)
    { i=atoi(str+8);
      if ((i<30) || (i>160))
        goto invparam;
      maxline=i;
      continue;
    }
    if (strnicmp(str, "compress=", 9)==0)
    { strcpy(compress, str+9);
      if (compress[0]==0)
        strcpy(compress, "nul");
      continue;
    }
    if (strnicmp(str, "rnews=", 6)==0)
    { strcpy(rnews, str+6);
      continue;
    }
    if (strnicmp(str, "fido2rel-chk-pl=", 16)==0)
    {
#ifdef DO_PERL
      if (!fullpath(str+16))
        goto notfull;
      strcpy(perlfile, str+16);
#endif
      continue;
    }
    if (strnicmp(str, "fido2rel-chk", 12)==0)
    { p=strpbrk(str, " \t");
      if (p==NULL)
        goto invparam;
      if (p!=str+12)
        goto invparam;
      while ((*p==' ') || (*p=='\t')) p++;
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      *p1=0;
      strncpy(checker[nchecker].mask, p, sizeof(checker[0].mask));
      if ((stricmp(p, "any")==0) || (stricmp(p, "all")==0))
        strcpy(checker[nchecker].mask, "any");
      *p1=' ';
      while ((*p1==' ') || (*p1=='\t'))
        p1++;
      if (*p1==0)
        checker[nchecker].cmdline[0]='\0';
      else
        strncpy(checker[nchecker].cmdline, p1, sizeof(checker[0].cmdline));
      nchecker++;
      continue;
    }
    if (strnicmp(str, "reject-tpl=", 11)==0)
    { strcpy(tpl_name, str+11);
      setpath(tpl_name);
      continue;
    }
    if (strnicmp(str, "8bit-header=", 12)==0)
    { if (tolower(str[12])=='y')
        hdr8bit=1;
      else if (tolower(str[12])=='n')
        hdr8bit=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "x-comment-to=", 13)==0)
    { if (tolower(str[13])=='y')
        xcomment=1;
      else if (tolower(str[13])=='n')
        xcomment=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "del-transit-files=", 18)==0)
    { if (tolower(str[18])=='y')
        deltransfiles=1;
      else if (tolower(str[18])=='n')
        deltransfiles=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "postmaster=", 11)==0)
    { strcpy(gatemaster, str+11);
      continue;
    }
    if (strnicmp(str, "domain=", 7)==0)
    { strcpy(localdom, str+7);
      continue;
    }
    if (strnicmp(str, "local=", 6)==0)
    { strcpy(local, str+6);
      continue;
    }
    if (strnicmp(str, "extcharset=", 11)==0)
    { if (charsetsdir[0])
        logwrite('!', "charsets-dir defined, extcharset ignored\n");
      else
        strcpy(extcharset, str+11);
      continue;
    }
    if (strnicmp(str, "extsetname=", 11)==0)
    { strcpy(extsetname, str+11);
      continue;
    }
    if (strnicmp(str, "intsetname=", 11)==0)
    { strcpy(intsetname, str+11);
      continue;
    }
    if (strnicmp(str, "charsets-dir=", 13)==0)
    { if (!fullpath(str+13))
        goto notfull;
      strcpy(charsetsdir, str+13);
      addslash(charsetsdir);
      continue;
    }
    if (strnicmp(str, "charsets-alias=", 15)==0)
    { if (!fullpath(str+15))
        goto notfull;
      strcpy(charsetalias, str+15);
      continue;
    }
    if (strnicmp(str, "charset=", 8)==0)
    { if (charsetsdir[0])
      { logwrite('!', "charsets-dir defined, charset ignored\n");
        continue;
      }
      p=strpbrk(str+8, " \t");
      if (p==NULL)
      { logwrite('!', "Incorrect \"charset\" param ignored in " GATECFG ": %s\n", str);
        continue;
      }
      *p++='\0';
      for (; (*p==' ') || (*p=='\t'); p++);
      if (*p=='\0')
      { str[strlen(str)]=' ';
        logwrite('!', "Incorrect \"charset\" param ignored in " GATECFG ": %s\n", str);
        continue;
      }
      setcharset(str+8, p);
      continue;
    }
    if (strnicmp(str, "charset-alias=", 14)==0)
    {
      p=strpbrk(str+14, " \t");
      if (p==NULL)
      { logwrite('!', "Incorrect \"charset-alias\" param ignored in " GATECFG ": %s\n", str);
        continue;
      }
      *p++='\0';
      for (;(*p==' ') || (*p=='\t'); p++);
      if (*p=='\0')
      { str[strlen(str)]=' ';
        logwrite('!', "Incorrect \"charset-alias\" param ignored in " GATECFG ": %s\n", str);
        continue;
      }
      addchsalias(str+14, p);
      continue;
    }
    if (strnicmp(str, "fido-charset=", 13)==0)
    {
      for (p=str+13; *p && !isspace(*p); p++);
      if (!*p) goto invparam;
      *p++='\0';
      for (; *p && isspace(*p); p++);
      if (!*p)
      { str[strlen(str)]=' ';
        goto invparam;
      }
      addftncharset(str+13, p);
      continue;
    }
    if (strnicmp(str, "write-reason=", 13)==0)
    { if (tolower(str[13])=='y')
        writereason=1;
      else if (tolower(str[13])=='n')
        writereason=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "fsp-1004=", 9)==0)
    { if (tolower(str[9])=='y')
        fsp1004=1;
      else if (tolower(str[9])=='n')
        fsp1004=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "bangfrom=", 9)==0)
    { if (tolower(str[9])=='y')
        bangfrom=1;
      else if (tolower(str[9])=='n')
        bangfrom=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "env-chaddr=", 11)==0)
    { if (tolower(str[11])=='y')
        env_chaddr=1;
      else if (tolower(str[11])=='n')
        env_chaddr=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "fromtop=", 8)==0)
    { if (tolower(str[8])=='y')
        fromtop=1;
      else if (tolower(str[8])=='n')
        fromtop=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "logstyle=", 9) == 0)
    { if (stricmp(str+9, "fd") && stricmp(str+9, "bink"))
        goto invparam;
      continue;
    }
    if (strnicmp(str, "tid=", 4)==0)
    { if (tolower(str[4])=='y')
        notid=0;
      else if (tolower(str[4])=='n')
        notid=1;
      else
        goto invparam;
      continue;
    }
    for (i=0; i<sizeof(ignore)/sizeof(ignore[0]); i++)
      if (strnicmp(str, ignore[i], strlen(ignore[i]))==0)
        break;
    if (i<sizeof(ignore)/sizeof(ignore[0]))
      continue;
    logwrite('!', "Unknown line in %s ignored: %s\n", curtplname, str);
  }
  close_tpl();
  /* check, what required params is not specified */
  if (netmaildir[0]==0)
  { logwrite('?', "Parameter NETMAIL not specified!\n");
    return 3;
  }
  if (nuplink==0)
  { logwrite('?', "Parameter UPLINK not specified!\n");
    return 3;
  }
  if ((pktin[0]==0) && (binkout[0]==0) &&
#ifndef __MSDOS__
      (lbso[0]==0) && (longboxes[0]==0) && (tlboxes[0]==0) &&
#endif
      (tboxes[0]==0))
  { logwrite('?', "Parameter PKTIN or any outbound not specified!\n");
    return 3;
  }
  if (pktout[0]==0)
  { logwrite('?', "Parameter PKTOUT not specified!\n");
    return 3;
  }
#ifndef UNIX
  if ((uupcdir[0]==0) && (uupcver!=SENDMAIL))
  { logwrite('?', "Parameter UUPC not specified!\n");
    return 3;
  }
#endif
  if (organization[0]==0)
  { logwrite('?', "Parameter ORGANIZATION not specified!\n");
    return 3;
  }
  if (naka==0)
  { logwrite('?', "Parameter ADDRESS not specified!\n");
    return 3;
  }
  if (master[0]==0)
  { logwrite('?', "Parameter SYSOP not specified!\n");
    return 3;
  }
  if (rmail[0]==0)
  {
#ifdef UNIX
    strcpy(rmail, "sendmail -i");
#else
    if (uupcver==SENDMAIL)
      strcpy(rmail, "sendmail.exe -i");
    else
      strcpy(rmail, "rmail.exe");
#endif
  }
#ifndef UNIX
  if ((rmail[1]!=':') || (rmail[2]!='\\')) 
    if (uupcver!=SENDMAIL)
    { p=strrchr(rmail, PATHSEP);
      if (p==NULL)
      { p=strrchr(rmail, ':');
        if (p==NULL)
          p=rmail;
        else p++;
      }
      else p++;
      strcpy(str, p);
      strcpy(rmail, uupcdir);
      if (rmail[3])
        strcat(rmail, PATHSTR);
      strcat(rmail, str);
    }
#if 0
    else
    { p=strrchr(rmail, '\\');
      if (p==NULL)
      { p=strrchr(rmail, ':');
        if (p==NULL)
          p=rmail;
        else p++;
      }
      else p++;
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
      return 3;
    }
    if (p) *p=' ';
  }
#endif
  debug(6, "Config: rmail is '%s'", rmail);
  if (uupcdir[0])
  { /* get names local and remote */
    strcpy(str, uupcdir);
    addslash(str);
    strcpy(spool_dir, str);
    strcat(spool_dir, "spool" PATHSTR);
    if (uupcver==KENDRA)
    { char *p=getenv("UUPCSYSRC");
      if (p==NULL)
      { logwrite('?', "Environment variable UUPCSYSRC must be specified!\n");
        return 1;
      }
      postmast[0]='\0';
      strcpy(str, p);
      strcpy(conf_dir, p);
      p=strrchr(conf_dir, PATHSEP);
      if (p) p[1]='\0';
      else *conf_dir='\0';
    }
    else
      strcat(str, "conf" PATHSTR "uupc.rc");
    debug(6, "Config: uupc sys rc is %s", str);
    if ((p=getenv("nodename"))!=NULL && local[0]==0) 
      strcpy(local, p);
    if ((p=getenv("compress"))!=NULL && compress[0]==0)
    { strcpy(compress, p);
      if (compress[0]==0)
        strcpy(compress, "nul");
    }
    if ((p=getenv("extcharset"))!=NULL && (extcharset[0]==0) && charsetsdir[0]=='\0')
      strcpy(extcharset, p);
    if ((p=getenv("ExtSetName"))!=NULL && extsetname[0]==0) 
      strcpy(extsetname, p);
    if ((p=getenv("IntSetName"))!=NULL && intsetname[0]==0) 
      strcpy(intsetname, p);
#ifdef __MSDOS__
    if (use_swap==-1 && (p=getenv("swap"))!=NULL)
      setswap(p);
#endif
    inconfig=2;
    if (init_tpl(str))
      return 3;
    /* read uupc.rc */
    while (configline(str, sizeof(str)))
    { if ((strnicmp(str, "nodename=", 9)==0) && (local[0]==0))
      { for (p=str+9; (*p==' ') || (*p=='\t'); p++);
        strcpy(local, p);
        p=strchr(local, '\n');
        if (p) *p=0;
        stripspc(local);
      }
      if (strnicmp(str, "mailserv=", 9)==0)
      { for (p=str+9; (*p==' ') || (*p=='\t'); p++);
        strcpy(remote, p);
        p=strchr(remote, '\n');
        if (p) *p=0;
        stripspc(remote);
      }
      if (strnicmp(str, "spooldir=", 9)==0)
      { for (p=str+9; (*p==' ') || (*p=='\t'); p++);
        strcpy(spool_dir, p);
        p=strchr(spool_dir, '\n');
        if (p) *p=0;
        stripspc(spool_dir);
        removeslash(spool_dir);
      }
      if ((strnicmp(str, "compress=", 9)==0) && (compress[0]==0))
      { for (p=str+9; (*p==' ') || (*p=='\t'); p++);
        strcpy(compress, p);
        p=strchr(compress, '\n');
        if (p) *p=0;
        stripspc(compress);
        if (compress[0]==0)
          strcpy(compress, "nul");
      }
      if (strnicmp(str, "batchmail=", 10)==0)
      { for (p=str+10; (*p==' ') || (*p=='\t'); p++);
        strcpy(uux, p);
        p=strchr(uux, '\n');
        if (p) *p=0;
        stripspc(uux);
      }
      if ((strnicmp(str, "extcharset=", 11)==0) && (extcharset[0]==0) && charsetsdir[0]=='\0')
      { for (p=str+11; (*p==' ') || (*p=='\t'); p++);
        strcpy(extcharset, p);
        p=strchr(extcharset, '\n');
        if (p) *p=0;
        stripspc(extcharset);
        canonuucpdir(extcharset);
        extcharset[strlen(extcharset)-1]='\0'; /* last '\\' */
        continue;
      }
      if ((strnicmp(str, "extsetname=", 11)==0) && (extsetname[0]==0))
      { for (p=str+11; (*p==' ') || (*p=='\t'); p++);
        strcpy(extsetname, p);
        p=strchr(extsetname, '\n');
        if (p) *p=0;
        stripspc(extsetname);
        continue;
      }
      if ((strnicmp(str, "intsetname=", 11)==0) && (intsetname[0]==0))
      { for (p=str+11; (*p==' ') || (*p=='\t'); p++);
        strcpy(intsetname, p);
        p=strchr(intsetname, '\n');
        if (p) *p=0;
        stripspc(intsetname);
        continue;
      }
      if (strnicmp(str, "charset=", 8)==0 && charsetsdir[0]=='\0')
      { for (p=str+8; (*p==' ') || (*p=='\t'); p++);
        p1=strpbrk(p, " \t");
        if (p1==NULL) goto incorrcharset;
        *p1++='\0';
        for (; (*p1==' ') || (*p1=='\t'); p1++);
        stripspc(p1);
        if (*p1=='\0')
        { str[strlen(str)]=' ';
incorrcharset:
          logwrite('!', "Incorrect \"charset\" param ignored in uupc.rc: %s\n", str);
          continue;
        }
        setcharset(p, p1);
        continue;
      }
      if ((strnicmp(str, "tz=", 3)==0) && (tz==0))
      { if (getmytz(str+3, &tz))
          goto invparam;
        debug(6, "Config: GetTZ('%s') is %d", str+9, tz);
        continue;
      }
      if (strnicmp(str, "domain=", 7)==0)
      { for (p=str+7; (*p==' ') || (*p=='\t'); p++);
        strcpy(localdom, p);
        p=strchr(localdom, '\n');
        if (p) *p='\0';
      }
      if (strnicmp(str, "bangfrom=", 9)==0)
      { if (tolower(str[9])=='y' || tolower(str[9])=='t')
          bangfrom=1;
        else if (tolower(str[9])=='n' || tolower(str[9])=='f')
          bangfrom=0;
        else
          logwrite('?', "Unknown value in uupc.rc ignored: %s", str);
        continue;
      }
      if (uupcver==KENDRA)
      { if (strnicmp(str, "postmaster=", 11)==0)
        { for (p=str+11; (*p==' ') || (*p=='\t'); p++);
          strcpy(postmast, p);
          p=strchr(postmast, '\n');
          if (p) *p=0;
          stripspc(postmast);
        }
      }
      if (strnicmp(str, "confdir=", 8)==0)
      { for (p=str+8; (*p==' ') || (*p=='\t'); p++);
        strcpy(conf_dir, p);
        p=strchr(conf_dir, '\n');
        if (p) *p=0;
        stripspc(conf_dir);
        addslash(conf_dir);
      }
#ifdef __MSDOS__
      if (use_swap==-1 && strnicmp(str, "swap=", 5)==0)
        setswap(str+5);
#endif
    }
    close_tpl();
    if ((p=getenv("mailserv"))!=NULL)
      strcpy(remote, p);
    if ((p=getenv("spooldir"))!=NULL)
    { strcpy(spool_dir, p);
      addslash(spool_dir);
    }
    if ((p=getenv("batchmail"))!=NULL)
      strcpy(uux, p);
    if ((p=getenv("domain"))!=NULL)
      strcpy(localdom, p);
    if (uupcver==KENDRA)
    {
      if ((p=getenv("postmaster"))!=NULL) 
        strcpy(postmast, p);
    }
    if ((p=getenv("confdir"))!=NULL)
    { strcpy(conf_dir, p);
      addslash(conf_dir);
    }
    if ((p=getenv("bangfrom"))!=NULL)
    { if (tolower(*p)=='y' || tolower(*p)=='t')
        bangfrom=1;
      else if (tolower(*p)=='n' || tolower(*p)=='f')
        bangfrom=0;
      else
        logwrite('?', "Unknown bangfrom value ignored: %s", p);
    }
    if (uupcver!=KENDRA)
    {
      if (conf_dir[0]=='\0')
      { strcpy(conf_dir, uupcdir);
        addslash(conf_dir);
        strcat(conf_dir, "conf" PATHSTR);
      }
      strcpy(str, conf_dir);
      addslash(str);
      strcat(str, "sendmail.cf");
      inconfig=2;
      if (init_tpl(str))
        return 3;
      /* ищем строки "charset?=" */
      while (configline(str, sizeof(str)))
      { if (strlen(str)<9) continue;
        if ((strnicmp(str, "charset", 7)==0) && (str[8]=='=' || str[9]=='=') && charsetsdir[0]=='\0')
        { for (p=strchr(str, '=')+1; (*p==' ') || (*p=='\t'); p++);
          p1=strpbrk(p, " \t");
          if (p1==NULL) goto in1corrcharset;
          *p1++='\0';
          for (; (*p1==' ') || (*p1=='\t'); p1++);
          stripspc(p1);
          if (*p1=='\0')
          { str[strlen(str)]=' ';
in1corrcharset:
            logwrite('!', "Incorrect \"charset\" param ignored in sendmail.cf: %s\n", str);
            continue;
          }
          setcharset(p, p1);
          continue;
        }
      }
      close_tpl();
    }
  }
#endif

  if (localdom[0]==0)
  { logwrite('?', "Parameter DOMAIN not specified!\n");
    return 3;
  }
  if (strchr(gatemaster, '@')==NULL)
  { strcat(gatemaster, "@");
    strcat(gatemaster, localdom);
  }
#ifndef UNIX
  if ((local==0) && uupcdir[0])
  { logwrite('?', "Can't find string \"NodeName=\" in your UUPC.RC!\n");
    return 3;
  }
#endif
  if (local[0]==0)
    strcpy(local, localdom);
  debug(6, "Config: local node is %s", local);
#ifndef UNIX
  if ((remote[0]==0) && uupcdir[0])
  { logwrite('?', "Can't find string \"MailServ=\" in your UUPC.RC!\n");
    return 3;
  }
#endif
  if (remote[0])
    debug(6, "Config: remote node is %s", remote);

  if (extsetname[0]==0)
    strcpy(extsetname, EXTSETNAME);
  if (intsetname[0]==0)
    strcpy(intsetname, INTSETNAME);
  if (charsetsdir[0])
  {
    if (charsetalias[0]=='\0')
    { strcpy(charsetalias, charsetsdir);
      strcat(charsetalias, "charsets.alias");
    }
  }
  if (charsetalias[0])
  {
    FILE *f;
    if ((f=fopen(charsetalias, "r")) != NULL)
    {
      while (fgets(str, sizeof(str), f))
      { char *p=strchr(str, '\n');
        if (p) *p='\0';
        if (*str=='#' || *str=='\0' || isspace(*str)) continue;
        for (p=str; *p && !isspace(*p); p++);
        if (!*p) continue;
        *p++='\0';
        while (isspace(*p)) p++;
        addchsalias(str, p);
      }
      fclose(f);
    }
  }
  addchsalias("x-koi8-u",     "koi8-u");
  addchsalias("cp866",        "x-cp866");
  addchsalias("x-cp866-u",    "x-cp1125");
  addchsalias("ruscii",       "x-cp1125");
  addchsalias("cp866-u",      "x-cp1125");
  addchsalias("cp1251",       "x-cp1251");
  addchsalias("windows-1251", "x-cp1251");
#if 0
  extsetname=canoncharset(extsetname);
  intsetname=canoncharset(intsetname);
#endif
  if (charsetsdir[0]=='\0')
  { short int tmptable[256];
    if (extcharset[0])
      setcharset(intsetname, extcharset);
    for (i=0; i<256; i++)
      tmptable[i]=i;
    addtable(extsetname, tmptable);
  }
  /* add builtin tables */
  addmytable("x-cp866",  cp866_table,  charsetsdir);
  addmytable("ruscii",   cp1125_table, charsetsdir);
  addmytable("x-cp1251", cp1251_table, charsetsdir);
  addmytable("koi8-r",   koi8r_table,  charsetsdir);
  addmytable("koi8-u",   koi8u_table,  charsetsdir);
  if (findtable(extsetname, charsetsdir)==NULL) 
  { logwrite('?', "Can't find charset for extsetname %s!\n", extsetname);
    return 3;
  }
  if (findtable(intsetname, charsetsdir)==NULL)
  { logwrite('?', "Can't find charset for intsetname %s!\n", intsetname);
    return 3;
  }

  { short int *t;
    t=findtable(extsetname, charsetsdir);
    addmytable("us-ascii", t, charsetsdir); /* bugly mail editor setup */
  }

  if (pktin[0]==0)
    strcpy(pktin, tmpdir); /* for tossbad */
#ifndef UNIX
  if ((uux[0]==0) && uupcdir)
  { strcpy(uux, uupcdir);
    if (uux[3]) strcat(uux, PATHSTR);
    strcat(uux, "uux.exe");
  }
#endif
  if ((rnews[0]==0) && uux[0])
    sprintf(rnews, "%s -x1 -gN -r -p %%s!rnews", uux);

#ifndef UNIX
  p=strpbrk(rnews, " \t");
  if (p) *p='\0';
  if ((rnews[0]==0) || access(rnews, 0))
  { if (uupcver!=SENDMAIL)
    { if (byuux)
        logwrite('!', "Can't find %s, by-uux changed to No.\n", rnews);
      byuux=0;
    }
    else
    { /* no spool, no rnews; only mailnews or directory */
      for (i=0; i<ngroups; i++)
        if (group[i].type==G_CNEWS)
        { logwrite('?', "Can't upload newsgroups in cnews mode: no rnews and uux found!\n");
          return 1;
        }
      byuux=1;
    }
  }
  if (p) *p=' ';
  if ((uupcver==SENDMAIL) && (byuux==0))
  { logwrite('!', "Can't upload to spool when uupcver=sendmail, by-uux changed to Yes.\n");
    byuux=1;
  }
  if (byuux)
#endif
  { debug(6, "Config: uux is '%s'", uux);
    debug(6, "Config: rnews is '%s'", rnews);
  }

  if (compress[0]==0)
#ifdef UNIX
    strcpy(compress, "gzip -9");
#else
    strcpy(compress, "gzip.exe -9");
#endif
  else if (strcmp(compress, "nul")==0)
    compress[0]=0;
  debug(6, "Config: compress is '%s'", compress);
#ifndef UNIX
  if ((uupcver==KENDRA) && (getenv("UUPCUSRRC")==NULL))
  { if (postmast[0]=='\0')
    { logwrite('?', "Didn't find \"postmaster=\" keyword in your %s!\n",
             getenv("UUPCSYSRC"));
      return 1;
    }
    strcpy(str, "UUPCUSRRC=");
    p=str+strlen(str);
    strcpy(p, conf_dir);
    strcat(p, postmast);
    strcat(p, ".rc");
    if (access(p, 0))
    { logwrite('?', "Can't find %s!\n", p);
      return 1;
    }
    putenv(strdup(str));
    debug(6, "Config: putenv %s", str);
  }
#endif
#ifdef __MSDOS__
  if (use_swap==-1)
    use_swap=USE_ALL;
#endif
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
  if (echolog)
    strcpy(loglevel, "-$!?");
  else
    strcpy(loglevel, "$!?");
  inconfig=0;
  srand(getpid()+(int)time(NULL));
  return 0;
}
