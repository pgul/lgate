/*
 * $Id$
 *
 * $Log$
 * Revision 2.2  2001/01/26 14:43:50  gul
 * init holdsize=0, not -1
 *
 * Revision 2.1  2001/01/21 10:20:02  gul
 * new cfg param 'fromtop'
 *
 * Revision 2.0  2001/01/10 20:42:24  gul
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <time.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#if defined(__OS2__)
#include <os2.h>
#elif defined(__MSDOS__)
#include "exec.h"
#endif
#ifndef UNIX
#include "lib.h"
#include "import.h"
#endif
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

extern char charset[];
extern int  validlen;

int  tz;
int  rcv2via,savehdr;
char checksb,echolog,forgolded,domainmsgid;
char dirnews[FNAME_MAX],nconf[FNAME_MAX];
char localdom[MAXDOM];
int  curaka;
#ifdef __MSDOS__
int  use_swap;
#endif
errtotype errorsto;

char extsetname[128], intsetname[128]; 
static int  hout,noxc,checksubj;
static char extcharset[FNAME_MAX];
static uword z,nt,nd,pt;
static char s[MAXDOM],gateuser[MAXDOM];
static char user[32],mailext[32],boxdir[FNAME_MAX],charsetalias[FNAME_MAX];
static char * echonames;
static long lechonames;
#ifndef UNIX
static char conf_dir[FNAME_MAX];
static char uupcdir[FNAME_MAX];
int  uupcver;
#endif
#ifdef DO_PERL
char perlfile[FNAME_MAX] = "";
#endif

static char *ignore[]={
"reject-tpl=",
"max-received=",
"by-uux=",
"pktin=",
"newsserv=",
"send-to=",
"free=",
"no-send=",
"route-to",
"to-ifmail",
"no-route",
"privel=",
"twit=",
"uucode=",
"route-files",
"route-uue",
"filebox=",
"maxsize=",
"maxline=",
"cnewssize=",
"netdomain=",
"maxuue=",
"no-twit=",
"message-id=",
"to-uucp=",
"alias",
"moderator",
"norm-only=",
"compress=",
"fido2rel-chk",
"fido2rel-flt",
"rel2fido-flt",
"route-split",
"unsecure=",
"hide-tearline=",
"hide-origin=",
"uudecode=",
"uuencode=",
"precedence=",
"semdir=",
"8bit-header=",
"x-comment-to=",
"attach-from=",
"del-transit-files=",
"log=",
"rnews=",
"write-reason=",
"local=",
"pgp-",
"sentdir=",
"incomplete=",
"fsp-1004=",
"bangfrom=",
"env-chaddr=",
"sysop=",
"fido2rel-chk-pl=",
"inb-dir=",
"fromtop="
};

static void * galloc(long bytes)
{
  if (bytes==0) return (void *)1;
#ifdef __MSDOS__
  if (bytes>=0x8000) return NULL;
  return farmalloc(bytes);
#else
  return malloc((unsigned)bytes);
#endif
}

static void canondir(char * dir)
{
#if defined(__MSDOS__) || defined(__OS2__)
  char * p;

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
      DosQueryCurrentDir(tolower(str[0])-'a'+1,str+3,(unsigned long *)&i);
    }
#else
    getcurdir(tolower(str[0])-'a'+1,str+3);
#endif
    if (str[3]) strcat(str,"\\");
  }
  strcat(str,p);
  if (str[strlen(str)-1]!='\\')
    strcat(str,"\\");
  strcpy(dir,str);
#else
  if (*dir!='/')
  { getcwd(str, sizeof(str));
    strcat(str, "/");
    strcat(str, dir);
    strcpy(dir, str);
  }
  if (dir[strlen(dir)-1]!='/')
    strcat(dir,"/");
#endif
}

#ifndef UNIX
static void canonuucpdir(char * dir)
{ char * p;

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
    strcpy(str+2,uupcdir+2);
  strcat(str,p);
  addslash(str);
  strcpy(dir,str);
  debug(10,"CanonUucpDir: canonical name for %s is %s",dir,str);
  return;
}
#endif

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

#ifdef __MSDOS__
static void setswap(char *p)
{
  use_swap = USE_FILE;
  for (;*p;p++)
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
      default:   logwrite('!',"Unknown swap method %c ignored\n",tolower(*p));
                 continue;
    }
}
#endif

int config(void)
{ int i, j;
  char _Huge * pitwit;
  long npitwit;
  time_t curtime;
  struct tm *curtm;
  char *p, *p1;

  if (nconf[0]==0)
  {
#ifdef UNIX
    strcpy(nconf, GATECFG);
    setpath(nconf);
    debug(5, "full config name is %s\n", nconf);
#else
    strcpy(nconf, myname);
    p=strrchr(nconf,PATHSEP);
    if (p==NULL) p=nconf;
    else p++;
    strcpy(p, GATECFG);
#endif
  }
#ifndef UNIX
  uupcver=5;
  uupcdir[0]=spool_dir[0]=0;
#endif
  rmail[0]=netmaildir[0]=logname[0]=pktout[0]=dirnews[0]=0;
  organization[0]=pktpwd[0]=user[0]=rescan[0]=binkout[0]=0;
#ifndef __MSDOS__
  lbso[0]=tlboxes[0]=longboxes[0]='\0';
#endif
  tboxes[0]='\0';
  boxdir[0]='\0';
  local[0]=extcharset[0]=localdom[0]=0;
  extsetname[0]=intsetname[0]=0;
  gateuser[0]=0;
  strcpy(postmast,"postmaster");
  held_tpl[0]=badaddr_tpl[0]=0;
  ncaddr=0;
  nuplinks=0;
  ncdomain=0;
  nchecker=0;
  checksb=1;
  echolog=0;
  tabsize=0;
  maxpart=16;
  uppername=1;
  myorigin=0;
  pktsize=64;
  tmpdir[0]=0;
  badmail[0]=0;
#ifdef __MSDOS__
  use_swap=-1;
#endif
  rcv2via=1;
  savehdr=1;
  maxhops=0;
  netmail2pst=1;
  attr=msgPRIVATE|msgKILLSENT|msgLOCAL;
  newechoflag[0]=0;
  naka=0;
  nitwit=nitwitto=nitwitfrom=nitwitvia=0;
  npitwit=0;
  nechoes=0;
  forgolded=1;
  domainmsgid=1;
  packmail=0;
  gatevia=2;
  keepatt=ATT_KEEP;
  routeattach=0;
  shortvia=1;
  holdsize=0;
  curaka=-1;
  lechonames=0;
  replyform=REPLY_EMPTY;
  nosplit=0;
  kill_vcard=do_alternate=0;
  holdhuge=1;
  split_report=0;
  putchrs=0;
  charsetsdir[0]='\0';
  p=getenv("TEMP");
  if (p==NULL)
    p=getenv("TMP");
  if (p)
    strcpy(tmpdir,p);
  if (tmpdir[0]==0)
#ifdef UNIX
    strcpy(tmpdir, "/tmp");
#else
    getcwd(tmpdir,sizeof(tmpdir));
#endif
  canondir(tmpdir);
  uncompress[0]=holdpath[0]=0;
  tz=0;
  p1=getenv("TZ");
  if (p1)
  { getmytz(p1,&tz);
    debug(6, "Config: GetTZ('%s') is %d", p1, tz);
  }
  /* first pass */
  tplout=0;
  if (init_tpl(nconf))
    return 2;
  setglobal("Module","Rel2Fido");
  while (configline(str,sizeof(str)))
  {
    if (strnicmp(str,"chdomain",8)==0)
    { ncdomain++;
      continue;
    }
    if (strnicmp(str,"group",5)==0)
    { naka++;
      continue;
    }
    if ((strnicmp(str,"address=",8)==0) ||
        (strnicmp(str,"aka=",4)==0))
    { naka++;
      continue;
    }
    if (strnicmp(str,"conference",10)==0)
    { if (noecho) continue;
      for (p=str+10;(*p==' ') || (*p=='\t');p++);
      p1=strpbrk(p," \t");
      if (p1==NULL) continue;
      *p1=0;
      lechonames+=strlen(p)+1;
      *p1=' ';
      for (p=p1+1;(*p==' ') || (*p=='\t');p++);
      p1=strpbrk(p," \t");
      if (p1) continue;
      lechonames+=strlen(p)+1;
      nechoes++;
      continue;
    }
    if (strnicmp(str,"uplink=",7)==0)
    { nuplinks++;
      continue;
    }
    if (strnicmp(str,"chaddr=",7)==0)
    { ncaddr++;
      continue;
    }
    if (strnicmp(str,"itwit=",6)==0)
    { nitwit++;
      npitwit+=strlen(str+6)+1;
      continue;
    }
    if (strnicmp(str,"itwit-to=",9)==0)
    { nitwitto++;
      npitwit+=strlen(str+9)+1;
      continue;
    }
    if (strnicmp(str,"itwit-from=",11)==0)
    { nitwitfrom++;
      npitwit+=strlen(str+11)+1;
      continue;
    }
    if (strnicmp(str,"itwit-via=",10)==0)
    { nitwitvia++;
      npitwit+=strlen(str+10)+1;
      continue;
    }
    if (strnicmp(str,"charsets-dir=",13)==0)
    { strcpy(charsetsdir, "nul");
      continue;
    }
    if (strnicmp(str,"rel2fido-chk",12)==0)
    { nchecker++;
      continue;
    }
    if (strnicmp(str,"log=",4)==0)
    {
      if (strpbrk(str+4,"/\\:"))
        strcpy(logname,str+4);
      else
      { /* если путь не указан - в каталог запуска */
#ifdef UNIX
        strcpy(logname, "/var/log/");
#else
        strcpy(logname, myname);
#endif
        p=strrchr(logname, PATHSEP);
        if (p==NULL) p=logname;
        else p++;
        strcpy(p,str+4);
      }
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

  if (logname[0]=='\0')
  {
#ifdef UNIX
    strcpy(logname, "/var/log/");
#else
    strcpy(logname, myname);
#endif
    p=strrchr(logname, PATHSEP);
    if (p==NULL) p=logname;
    else p++;
    strcpy(p,"lgate.log");
  }
  if (access(logname,0))
  { hout=myopen(logname,O_CREAT|O_RDWR);
    if (hout==-1)
    { puts("Can't create log-file!");
      return 3;
    }
    close(hout);
  }
  /* выделяем память */
  cdomain=galloc(ncdomain*(long)sizeof(cdomain[0]));
  if (cdomain==NULL)
  {
nomemory:
    logwrite('?',"Not enough memory!\n");
    return 7;
  }
  myaka=galloc(naka*(long)sizeof(myaka[0]));
  if (myaka==NULL) goto nomemory;
  uplink=galloc(nuplinks*(long)sizeof(uplink[0]));
  if (uplink==NULL) goto nomemory;
  caddr=galloc(ncaddr*(long)sizeof(caddr[0]));
  if (caddr==NULL) goto nomemory;
  itwit=galloc(nitwit*(long)sizeof(itwit[0]));
  if (itwit==NULL) goto nomemory;
  itwitto=galloc(nitwitto*(long)sizeof(itwitto[0]));
  if (itwitto==NULL) goto nomemory;
  itwitfrom=galloc(nitwitfrom*(long)sizeof(itwitfrom[0]));
  if (itwitfrom==NULL) goto nomemory;
  itwitvia=galloc(nitwitvia*(long)sizeof(itwitvia[0]));
  if (itwitvia==NULL) goto nomemory;
  if (npitwit==0) pitwit=(void *)1;
  else
#ifdef __MSDOS__
    pitwit=farmalloc(npitwit);
#else
    pitwit=malloc((int)npitwit);
#endif
  if (pitwit==NULL) goto nomemory;
  checker=galloc(nchecker*(long)sizeof(checker[0]));
  if (checker==NULL) goto nomemory;
  if (nechoes && (!noecho))
  { 
#ifdef __MSDOS__
    echoes=farmalloc(nechoes*(long)sizeof(echoes[0]));
    echonames=farmalloc(lechonames);
#else
    echoes=malloc(nechoes*sizeof(echoes[0]));
    echonames=malloc((int)lechonames);
#endif
    if (echoes==NULL || echonames==NULL) goto nomemory;
  }

  /* второй проход */
  if (naka)
    myaka[0].zone=2;
  else
  {
    logwrite('?',"Address not specified!\n");
    return 3;
  }
  ncdomain=naka=nuplinks=ncaddr=nechoes=nchecker=0;
  nitwit=nitwitto=nitwitfrom=nitwitvia=0;
  lechonames=0;
  tplout=1;
  init_tpl(nconf);
  while (configline(str,sizeof(str)))
  {
    if (strnicmp(str,"display ",8)==0)
    { logwrite('$',"%s\n",str+8);
      continue;
    }
#ifndef UNIX
    if (strnicmp(str,"uupc=",5)==0)
    { if (!fullpath(str+5))
        goto notfull;
      strcpy(uupcdir,str+5);
      addslash(uupcdir);
      continue;
    }
    if (strnicmp(str,"uupcver=",8)==0)
    { if (strncmp(str+8,"5",1)==0)
      { strcpy(charset,DOSCHARS5);
        validlen=VALIDLEN_ACHE;
      }
      else if (strncmp(str+8,"6.14h",5)==0)
      { uupcver=614;
        strcpy(charset,DOSCHARS614H);
        validlen=VALIDLEN_ACHE;
      }
      else if (strncmp(str+8,"6.15",4)==0)
      { uupcver=615;
        strcpy(charset,DOSCHARS614H);
        validlen=VALIDLEN_ACHE;
      }
      else if (strncmp(str+8,"6",1)==0)
      { uupcver=6;
        strcpy(charset,DOSCHARS6);
        validlen=VALIDLEN_ACHE;
      }
      else if (strncmp(str+8,"7",1)==0)
      { uupcver=615;
        strcpy(charset,DOSCHARS614H);
        validlen=VALIDLEN_ACHE;
      }
      else if (strnicmp(str+8,"kendra",6)==0)
      { uupcver=KENDRA;
        strcpy(charset,DOSCHARSEXT);
        validlen=VALIDLEN_EXT;
      }
      else if (strnicmp(str+8,"sendmail",8)==0)
        uupcver=SENDMAIL;
      else
        goto invparam;
      continue;
    }
#endif
    if (strnicmp(str,"rmail=",6)==0)
    { strcpy(rmail,str+6);
      continue;
    }
    if (strnicmp(str,"postmaster=",11)==0)
    { if (str[11])
        strcpy(postmast,str+11);
      continue;
    }
    if (strnicmp(str,"user=",5)==0)
    { strncpy(user,str+5,8);
      user[8]=0;
      continue;
    }
    if (strnicmp(str,"netmail=",8)==0)
    { if (!fullpath(str+8))
      {
notfull:
        *strchr(str,'=')='\0';
        logwrite('?', "You must specify FULL path to your %s directory!\n", str);
        closeall();
        return 3;
      }
      strcpy(netmaildir, str+8);
      addslash(netmaildir);
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
      strcpy(tlboxes,str+8);
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
    { if (!fullpath(str+8))
        goto notfull;
      strcpy(badmail, str+8);
      addslash(badmail);
      strcat(badmail, BADPSTNAME);
      continue;
    }
    if (strnicmp(str, "temp=", 5)==0)
    {
      strcpy(tmpdir, str+5);
      canondir(tmpdir);
      continue;
    }
    if (strnicmp(str, "pack=", 5)==0)
    { if (tolower(str[5])=='y')
        packmail=1;
      else if (tolower(str[5])=='n')
        packmail=0;
      else
      { 
invparam:
        logwrite('!', "Invalid parameter %s ignored!\n", str);
        continue;
      }
      continue;
    }
    if (strnicmp(str, "golded=", 7)==0)
    { if (tolower(str[7])=='y')
        forgolded=1;
      else if (tolower(str[7])=='n')
        forgolded=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "seen-by=", 8)==0)
    { if (tolower(str[8])=='y')
        checksb=1;
      else if (tolower(str[8])=='n')
        checksb=0;
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
    if (strnicmp(str, "upper=", 6)==0)
    { if (tolower(str[6])=='y')
        uppername=1;
      else if (tolower(str[6])=='n')
        uppername=0;
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
    if (strnicmp(str, "gatevia=", 8)==0)
    { if (tolower(str[8])=='y')
        gatevia=1;
      else if (tolower(str[8])=='n')
        gatevia=0;
      else if (tolower(str[8])=='a')
        gatevia=2;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "domain-id=", 10)==0)
    { if (tolower(str[10])=='y')
        domainmsgid=1;
      else if (tolower(str[10])=='n')
        domainmsgid=0;
      else if (tolower(str[10])=='f')
        domainmsgid=2;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "echolog=", 8)==0)
    { if (tolower(str[8])=='y')
        echolog=1;
      else if (tolower(str[8])=='n')
        echolog=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "errors-to=", 10)==0)
    { if (strnicmp(str+10, "mast", 4)==0)
        errorsto=TO_MASTER;
      else if (strnicmp(str+10, "send", 4)==0)
        errorsto=TO_SENDER;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "pktout=", 7)==0)
    { if (!fullpath(str+7))
        goto notfull;
      strcpy(pktout, str+7);
      addslash(pktout);
      continue;
    }
    if (strnicmp(str, "organization=", 13)==0)
    { strcpy(organization, str+13);
      continue;
    }
    if (strnicmp(str, "swap=", 5)==0)
    { 
#ifdef __MSDOS__
      setswap(str+5);
#endif
      continue;
    }
    if (strnicmp(str, "fidosystem=", 11)==0)
    { strcpy(remote, str+11);
      /* remote[8]=0; */
      continue;
    }
    if (strnicmp(str, "chdomain", 8)==0)
    { p=strpbrk(str, " \t");
      if (p==NULL)
        goto invparam;
      if (p!=str+8)
        goto notfull;
      while ((*p==' ') || (*p=='\t')) p++;
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      if (p1-p>=sizeof(cdomain[0].relcom))
      { strncpy(cdomain[ncdomain].relcom, p, sizeof(cdomain[0].relcom)-1);
        cdomain[ncdomain].relcom[sizeof(cdomain[0].relcom)-1]=0;
      }
      else
      { strncpy(cdomain[ncdomain].relcom, p, (unsigned)p1-(unsigned)p);
        cdomain[ncdomain].relcom[(unsigned)p1-(unsigned)p]=0;
      }
      for (p=p1;(*p==' ')||(*p=='\t');p++);
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
    if (strnicmp(str, "group", 5)==0)
    { /* формат:  "group <distribution> <remote> [<switches>]" */
      /* switches: /feed, /cnews, /noseenby, /noxc, /nosubj,
                   /net=fidonet.org,
                   /aka=2:463/68.128@fidonet.carrier.kiev.ua
      */
      curaka=0;
      noxc=0;
      checksubj=1;
      j=0;
      for(p=p1=str+5; p1;)
      { for (p=p1; (*p==' ') || (*p=='\t'); p++);
        if (*p=='\"')
          p1=strchr(++p, '\"');
        else
          p1=strpbrk(p, " \t");
        if (p1) *p1=0;
        if (*p!='/' || j<2)
        { if (j==0)
          { /* distribution */
            if (p1) *p1=' ';
            j++;
            continue;
          }
          if (j!=1)
          { if (p1) *p1=' ';
            logwrite('?', "Incorrect GROUP string %s\n", str);
            return 9;
          }
          /* remote */
          j++;
          if (p1) *p1=' ';
          continue;
        }
        p++;
        if (stricmp(p, "noseenby")==0)
        {
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "feed")==0)
        {
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "extmsgid")==0)
        {
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "dir")==0)
        {
          if (p1) *p1=' ';
          continue;
        }
        if (stricmp(p, "cnews")==0)
        {
          if (p1) *p1=' ';
          continue;
        }
        if (strnicmp(p, "net=", 4)==0)
        {
          if (p1) *p1=' ';
          continue;
        }
        if (strnicmp(p, "noxc", 4)==0)
        { noxc=1;
          if (p1) *p1=' ';
          continue;
        }
        if (strnicmp(p, "nosubj", 6)==0)
        { checksubj=0;
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
        { logwrite('!', "Incorrect fido address in switch %s ignored!\n", p-1);
          if (p1) *p1=' ';
          continue;
        }
        p+=4;
        if (strpbrk(p, "%@"))
          strcpy(s, strpbrk(p, "%@")+1);
        else
          s[0]=0;
        if (p1) *p1=' ';
        /* ищем это aka */
        for (i=0;i<naka;i++)
        { if ((z!=myaka[i].zone) || (nt!=myaka[i].net) ||
             (nd!=myaka[i].node) || (pt!=myaka[i].point))
            continue;
          if (s[0]==0)
            break;
          if (stricmp(s, myaka[i].domain)==0)
            break;
        }
        if (i<naka)
        { curaka=i;
          continue;
        }
        if (s[0]==0)
        { logwrite('!', "%u:%u/%u.%u is not my aka,  domain is requied!\n", z, nt, nd, pt);
          continue;
        }
        logwrite('!', "%u:%u/%u.%u%c%s is not my aka!\n", z, nt, nd, pt,
                 strchr(s, '@') ? '%' : '@', s);
        myaka[naka].zone=z;
        myaka[naka].net=nt;
        myaka[naka].node=nd;
        myaka[naka].point=pt;
        strncpy(myaka[naka].domain, s, sizeof(myaka[0].domain)-1);
        curaka=naka;
        naka++;
        continue;
      }
      if (j<2)
      { logwrite('?', "Incorrect GROUP string %s\n", str);
        return 9;
      }
      if (naka==0)
      { logwrite('?', "No address specified before GROUP string!");
        return 9;
      }
      continue;
    }
    if ((strnicmp(str, "address=", 8)==0) ||
        (strnicmp(str, "aka=", 4)==0))
    { p=strchr(str, '=');
      if (getfidoaddr(&myaka[naka].zone, &myaka[naka].net,
                      &myaka[naka].node, &myaka[naka].point, p+1))
      { logwrite('?', "%s is incorrect fido address!\n", p+1);
        return 9;
      }
      p1=strchr(p, '@');
      if (p==NULL)
      { logwrite('?', "You must specify domain at ADDR/AKA string!");
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
    if (strnicmp(str, "conference", 10)==0)
    { if (curaka==-1)
      { logwrite('?', "Conference group not specified before conference declaration!");
        return 9;
      }
      if (noecho)
        continue;
      for (p=str+10; (*p==' ') || (*p=='\t'); p++);
      p1=strpbrk(p, " \t");
      if (p1==NULL)
        goto invparam;
      *p1=0;
      strupr(p);
      echoes[nechoes].fido=(char *)((char _Huge *)echonames+lechonames);
      lechonames+=strlen(p)+1;
      strcpy(echoes[nechoes].fido, p);
      *p1=' ';
      for (p=p1+1;(*p==' ') || (*p=='\t');p++);
      p1=strpbrk(p, " \t");
      if (p1)
        goto invparam;
      echoes[nechoes].usenet=(char *)((char _Huge *)echonames+lechonames);
      lechonames+=strlen(p)+1;
      strcpy(echoes[nechoes].usenet, p);
      echoes[nechoes].aka=curaka;
      echoes[nechoes].noxc=noxc;
      echoes[nechoes].checksubj=checksubj;
      nechoes++;
      continue;
    }
    if (strnicmp(str, "uplink=", 7)==0)
    { if (getfidoaddr(&uplink[nuplinks].zone, &uplink[nuplinks].net,
                      &uplink[nuplinks].node, &uplink[nuplinks].point, str+7))
      { logwrite('?', "%s is incorrect fido address!\n", str+7);
        return 9;
      }
      nuplinks++;
      continue;
    }
    if (strnicmp(str, "itwit=", 6)==0)
    { 
      itwit[nitwit].str=(char *)pitwit;
#ifndef __MSDOS__
      itwit[nitwit].regbuf=NULL;
#endif
      strcpy(itwit[nitwit].str, str+6);
      pitwit+=strlen(itwit[nitwit++].str)+1;
      continue;
    }
    if (strnicmp(str, "itwit-to=", 9)==0)
    { itwitto[nitwitto].str=(char *)pitwit;
#ifndef __MSDOS__
      itwitto[nitwitto].regbuf=NULL;
#endif
      strcpy(itwitto[nitwitto].str, str+9);
      pitwit+=strlen(itwitto[nitwitto++].str)+1;
      continue;
    }
    if (strnicmp(str, "itwit-from=", 11)==0)
    { itwitfrom[nitwitfrom].str=(char *)pitwit;
#ifndef __MSDOS__
      itwitfrom[nitwitfrom].regbuf=NULL;
#endif
      strcpy(itwitfrom[nitwitfrom].str, str+11);
      pitwit+=strlen(itwitfrom[nitwitfrom++].str)+1;
      continue;
    }
    if (strnicmp(str, "itwit-via=", 10)==0)
    { itwitvia[nitwitvia].str=(char *)pitwit;
#ifndef __MSDOS__
      itwitvia[nitwitvia].regbuf=NULL;
#endif
      strcpy(itwitvia[nitwitvia].str, str+10);
      pitwit+=strlen(itwitvia[nitwitvia++].str)+1;
      continue;
    }
    if (strnicmp(str, "rescan=", 7)==0)
    { strcpy(rescan, str+7);
      continue;
    }
    if (strnicmp(str, "newecho=", 8)==0)
    { strcpy(newechoflag, str+8);
      continue;
    }
    if (strnicmp(str, "chaddr=", 7)==0)
    { p=str+7;
      while ((*p==' ') || (*p=='\t')) p++;
      if (*p==0)
        goto invparam;
      caddr[ncaddr].fido[sizeof(caddr[0].fido)-1]=0;
      caddr[ncaddr].relcom[sizeof(caddr[0].relcom)-1]=0;
/* chaddr="Pavel Gulchouck" 2:463/68 gul@mercury.kiev.ua (Pavel Gulchouck) */
/* chaddr=SysOp 2:463/68 postmaster@mercury.kiev.ua (System Administrator) */
      if (*p=='\"')
      { p1=strchr(p+1, '\"');
        if (p1==NULL) goto invparam;
        *p1=0;
        strncpy(caddr[ncaddr].fido, p+1, sizeof(caddr[0].fido)-1);
        *p1='\"';
        p=p1+1;
      }
      else
      { p1=strpbrk(p, " \t");
        if (p1==NULL) goto invparam;
        *p1=0;
        strncpy(caddr[ncaddr].fido, p, sizeof(caddr[0].fido)-1);
        *p1=' ';
        p=p1+1;
      }
      while((*p==' ') || (*p=='\t')) p++;
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
      /* из строки p выделяем только relcom-address */
      for (p1=caddr[ncaddr].relcom; *p; p++, p1++)
      { if (*p=='(')
        { while ((*p!=')') && *p) p++;
          if (*p==')')
            p++;
          if (*p==0) break;
        }
        if (*p=='<')
          break;
        if (p1-caddr[ncaddr].relcom<sizeof(caddr[0].relcom)-1)
          *p1=*p;
      }
      if (*p=='<')
      { strncpy(caddr[ncaddr].relcom, p+1, sizeof(caddr[0].relcom));
        p=strchr(caddr[ncaddr].relcom, '>');
        if (p) *p=0;
      }
      p=caddr[ncaddr].relcom+strlen(caddr[ncaddr].relcom)-1;
      while ((*p=='\n') || (*p==' ') || (*p=='\t'))
        p--;
      *(p+1)=0;
      ncaddr++;
      continue;
    }
    if (strnicmp(str, "timezone=", 9)==0)
    { if (getmytz(str+9, &tz))
        goto invparam;
      debug(6, "Config: GetTZ('%s') is %d", str+9, tz);
      continue;
    }
    if (strnicmp(str, "pktpwd=", 7)==0)
    { strncpy(pktpwd, str+7, 8);
      pktpwd[8]=0;
      strupr(pktpwd);
      continue;
    }
    if (strnicmp(str, "size=", 5)==0)
    { maxpart=atol(str+5);
      continue;
    }
    if (strnicmp(str, "pktsize=", 8)==0)
    { i=atoi(str+8);
      if ((i<10) || (i>1024))
        goto invparam;
      pktsize=i;
      continue;
    }
    if (strnicmp(str, "attrib=", 7)==0)
    { attr=0;
      for (p=str+7;*p;p++)
        switch(toupper(*p))
        { case 'P': attr|=msgPRIVATE;
                    break;
          case 'C': attr|=msgCRASH;
                    break;
          case 'R': attr|=msgREAD;
                    break;
          case 'S': attr|=msgSENT;
                    break;
          case 'A': attr|=msgFILEATT;
                    break;
          case 'W': attr|=msgFORWD;
                    break;
          case 'O': attr|=msgORPHAN;
                    break;
          case 'K': attr|=msgKILLSENT;
                    break;
          case 'L': attr|=msgLOCAL;
                    break;
          case 'H': attr|=msgHOLD;
                    break;
          case 'F': attr|=msgFREQ;
                    break;
          case 'Q': attr|=msgRETRECREQ;
                    break;
          case 'T': attr|=msgRETREC;
                    break;
          case 'D': attr|=msgDIRECT;
                    break;
          default:  logwrite('!', "Unknown flag \'%c\' ignored!\n", toupper(*p));
                    break;
        }
      continue;
    }
    if (strnicmp(str, "holdpath=", 9)==0)
    {
      if (!fullpath(str+9))
        goto notfull;
      strcpy(holdpath, str+9);
      addslash(holdpath);
      continue;
    }
    if (strnicmp(str, "holdsize=", 9)==0)
    { i=atoi(str+9);
      if (((i<4) || (i>2048)) && (i!=0))
        goto invparam;
      holdsize=i;
      continue;
    }
    if (strnicmp(str, "tabsize=", 8)==0)
    { i=atoi(str+8);
      if ((i<0) || (i>16))
        goto invparam;
      tabsize=i;
      continue;
    }
    if (strnicmp(str, "maxhops=", 8)==0)
    { i=atoi(str+8);
      if (i<0)
        goto invparam;
      maxhops=i;
      continue;
    }
    if (strnicmp(str, "resend-bad=", 11)==0)
    { if (tolower(str[11])=='y')
        netmail2pst=0;
      else if (tolower(str[11])=='n')
        netmail2pst=1;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "myorigin=", 9)==0)
    { if (tolower(str[9])=='y')
        myorigin=1;
      else if (tolower(str[9])=='n')
        myorigin=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "via=", 4)==0)
    { if (tolower(str[4])=='s')
        shortvia=1;
      else if (tolower(str[4])=='l')
        shortvia=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "rel2fido-chk-pl=", 16)==0)
    {
#ifdef DO_PERL
      if (!fullpath(str+16))
        goto notfull;
      strcpy(perlfile, str+16);
#endif
      continue;
    }
    if (strnicmp(str, "rel2fido-chk", 12)==0)
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
      while ((*p1==' ')||(*p1=='\t'))
        p1++;
      if (*p1=='\0')
        checker[nchecker].cmdline[0]='\0';
      else
        strncpy(checker[nchecker].cmdline, p1, sizeof(checker[0].cmdline));
      nchecker++;
      continue;
    }
    if (strnicmp(str, "badaddr-tpl=", 12)==0)
    { setpath(str+12);
      strcpy(badaddr_tpl, str+12);
      continue;
    }
    if (strnicmp(str, "held-tpl=", 9)==0)
    { setpath(str+9);
      strcpy(held_tpl, str+9);
      continue;
    }
    if (strnicmp(str, "uncompress=", 11)==0)
    { strcpy(uncompress, str+11);
      continue;
    }
    if (strnicmp(str, "softCR=", 7)==0)
    { softCR=str[7];
      continue;
    }
    if (strnicmp(str, "replyto=", 8)==0)
    { if (tolower(str[8])=='e')
        replyform=REPLY_EMPTY;
      else if (tolower(str[8])=='u')
        replyform=REPLY_UUCP;
      else if (tolower(str[8])=='a')
        replyform=REPLY_ADDR;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "decode-attach=", 14)==0)
    { if (tolower(str[14])=='y' || tolower(str[14])=='h')
      { keepatt=ATT_DECODE;
        routeattach=0;
      }
      else if (tolower(str[14])=='n')
      { keepatt=ATT_KEEP;
        routeattach=0;
      }
      else if (tolower(str[14])=='d')
      { keepatt=ATT_REJECT;
        routeattach=0;
      }
      else if (tolower(str[14])=='r')
      { keepatt=ATT_DECODE;
        routeattach=1;
      }
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "domain=", 7)==0)
    { strcpy(localdom, str+7);
      continue;
    }
    if (strnicmp(str, "maildir=", 8)==0)
    { strcpy(boxdir, str+8);
      addslash(boxdir);
      continue;
    }
    if (strnicmp(str, "newsdir=", 8)==0)
    { strcpy(dirnews, str+8);
      addslash(dirnews);
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
      for (;(*p==' ')||(*p=='\t');p++);
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
      for (;(*p==' ')||(*p=='\t');p++);
      if (*p=='\0')
      { str[strlen(str)]=' ';
        logwrite('!', "Incorrect \"charset-alias\" param ignored in " GATECFG ": %s\n", str);
        continue;
      }
      addchsalias(str+14, p);
      continue;
    }
    if (strnicmp(str, "split-multipart=", 16)==0)
    { if (tolower(str[16])=='y')
        nosplit=0;
      else if (tolower(str[16])=='n')
        nosplit=1;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "logstyle=", 9) == 0)
    { if (stricmp(str+9, "fd") && stricmp(str+9, "bink"))
        goto invparam;
      continue;
    }
    if (strnicmp(str, "kill-vcard=", 11)==0)
    { if (tolower(str[11])=='y')
        kill_vcard=1;
      else if (tolower(str[11])=='n')
        kill_vcard=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "honour-alternate=", 17)==0)
    { if (tolower(str[17])=='y')
        do_alternate=1;
      else if (tolower(str[17])=='n')
        do_alternate=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "hold-huge=", 10)==0)
    { if (tolower(str[10])=='y')
        holdhuge=1;
      else if (tolower(str[10])=='n')
        holdhuge=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "split-reports=", 14)==0)
    { if (tolower(str[14])=='y')
        split_report=1;
      else if (tolower(str[14])=='n')
        split_report=0;
      else
        goto invparam;
      continue;
    }
    if (strnicmp(str, "put-chrs=", 9)==0)
    { if (tolower(str[9])=='y')
        putchrs=1;
      else if (tolower(str[9])=='n')
        putchrs=0;
      else
        goto invparam;
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
    for (i=0; i<sizeof(ignore)/sizeof(ignore[0]); i++)
      if (strnicmp(str, ignore[i], strlen(ignore[i]))==0)
        break;
    if (i<sizeof(ignore)/sizeof(ignore[0]))
      continue;
   logwrite('!', "Unknown line in %s ignored: %s\n", curtplname, str);
  }
  close_tpl();
  /* разбираемся, чего не хватает */
  if (netmaildir[0]==0)
  { logwrite('?', "Parameter NETMAIL not specified!\n");
    return 3;
  }
  if (nuplinks==0)
  { logwrite('?', "Parameter UPLINK not specified!\n");
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
  if ((uupcdir[0]==0) && (localdom[0]==0))
  { logwrite('?', "Parameter DOMAIN not specified!\n");
    return 3;
  }
#endif
  if (organization[0]==0)
  { logwrite('?', "Parameter ORGANIZATION not specified!\n");
    return 3;
  }
  if (myaka[0].zone==0)
  { logwrite('?', "Parameter ADDRESS not specified!\n");
    return 3;
  }
  if (remote[0]==0 && !bypipe)
  { logwrite('?', "Parameter FIDOSYSTEM not specified!\n");
    return 3;
  }
  if (logname[0]==0)
  { logwrite('?', "Parameter LOG not specified!\n");
    return 3;
  }
  if (holdpath[0]=='\0')
    strcpy(holdpath, tmpdir);
  if (rmail[0]==0)
#ifdef UNIX
     strcpy(rmail, "sendmail -i");
#else
  { if (uupcver==SENDMAIL)
      strcpy(rmail, "sendmail.exe -i");
    else
      strcpy(rmail, "rmail.exe");
  }
  if ((rmail[1]!=':') || (rmail[2]!='\\'))
    if (uupcver!=SENDMAIL)
    { p=strrchr(rmail, '\\');
      if (p==NULL)
      { p=strrchr(rmail, ':');
        if (p==NULL)
          p=rmail;
        else p++;
      }
      else p++;
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
#endif /* 0 */
#endif
  debug(6, "Config: rmail is %s", rmail);

  if (boxdir[0] && !fullpath(boxdir))
  {
#ifndef UNIX
    if (uupcdir)
      canonuucpdir(boxdir);
    else
#endif
    { logwrite('?', "You must specify FULL path to maildir!\n");
      return 1;
    }
  }
  if (dirnews[0] && !fullpath(dirnews))
  {
#ifndef UNIX
    if (uupcdir)
      canonuucpdir(dirnews);
    else
#endif
    { logwrite('?', "You must specify FULL path to newsdir!\n");
      return 1;
    }
  }

#ifndef UNIX
  if (uupcdir[0])
  {
    if (dirnews[0]==0)
    { strcpy(dirnews, uupcdir);
      strcat(dirnews, "news\\");
    }
    if (boxdir[0]==0)
    { strcpy(boxdir, uupcdir);
      strcat(boxdir, "mail\\");
      if (uupcver!=KENDRA)
        strcat(boxdir, "boxes\\");
    }
    if ((spool_dir[0]==0) && (uupcver!=SENDMAIL))
    { strcpy(spool_dir, uupcdir);
      strcat(spool_dir, "spool\\");
    }
    p=getenv("UUPCSYSRC");
    if (p==NULL)
    { if (uupcver==KENDRA)
      { logwrite('?', "Environment variable UUPCSYSRC must be specified!\n");
        return 1;
      }
      else
      { strcpy(str, uupcdir);
        strcat(str, "conf\\uupc.rc");
      }
    }
    else
      strcpy(str, p);
    strcpy(conf_dir, str);
    p=strrchr(conf_dir, '\\');
    if (p)
      p[1]='\0';
    else
      conf_dir[0]='\0';
    inconfig=2;
    debug(6, "Config: UUPC sys rc is %s", str);

    if ((p=getenv("extcharset"))!=NULL && (extcharset[0]==0) && charsetsdir[0]=='\0')
      strcpy(extcharset, p);
    if ((p=getenv("extsetname"))!=NULL && (extsetname[0]==0))
      strcpy(extsetname, p);
    if ((p=getenv("intsetname"))!=NULL && (intsetname[0]==0))
      strcpy(intsetname, p);
    if ((p=getenv("domain"))!=NULL && (localdom[0]==0))
      strcpy(localdom, p);
    if ((p=getenv("uncompress"))!=NULL && (uncompress[0]==0))
      strcpy(uncompress, p);
#ifdef __MSDOS__
    if ((p=getenv("swap"))!=NULL && (use_swap==-1))
      setswap(p);
#endif

    if (init_tpl(str))
      return 3;
    /* ищем строки "NodeName=", "maildir=", "newsdir=" */
    funix=2;
    while (configline(str, sizeof(str)))
    { if (strnicmp(str, "nodename=", 9)==0)
      { for (p=str+9;(*p==' ') || (*p=='\t');p++);
        strcpy(local, p);
        p=strchr(local, '\n');
        if (p) *p=0;
        stripspc(local);
        continue;
      }
      if (strnicmp(str, "maildir=", 8)==0)
      { for (p=str+8;(*p==' ') || (*p=='\t');p++);
        strcpy(boxdir, p);
        p=strchr(boxdir, '\n');
        if (p) *p=0;
        stripspc(boxdir);
        canonuucpdir(boxdir);
        if ((uupcver==5) || (uupcver==6))
          strcat(boxdir, "boxes\\");
        continue;
      }
      if (strnicmp(str, "newsdir=", 8)==0)
      { for (p=str+8;(*p==' ') || (*p=='\t');p++);
        strcpy(dirnews, p);
        p=strchr(dirnews, '\n');
        if (p) *p=0;
        stripspc(dirnews);
        canonuucpdir(dirnews);
        continue;
      }
      if (strnicmp(str, "spooldir=", 9)==0)
      { for (p=str+9;(*p==' ') || (*p=='\t');p++);
        strcpy(spool_dir, p);
        p=strchr(spool_dir, '\n');
        if (p) *p=0;
        stripspc(spool_dir);
        canonuucpdir(spool_dir);
        continue;
      }
      if ((strnicmp(str, "extcharset=", 11)==0) && (extcharset[0]==0) && charsetsdir[0]=='\0')
      { for (p=str+11;(*p==' ') || (*p=='\t');p++);
        strcpy(extcharset, p);
        p=strchr(extcharset, '\n');
        if (p) *p=0;
        stripspc(extcharset);
        canonuucpdir(extcharset);
        extcharset[strlen(extcharset)-1]='\0'; /* last '\\' */
        continue;
      }
      if ((strnicmp(str, "extsetname=", 11)==0) && (extsetname[0]==0))
      { for (p=str+11;(*p==' ') || (*p=='\t');p++);
        strcpy(extsetname, p);
        p=strchr(extsetname, '\n');
        if (p) *p=0;
        stripspc(extsetname);
        continue;
      }
      if ((strnicmp(str, "intsetname=", 11)==0) && (intsetname[0]==0))
      { for (p=str+11;(*p==' ') || (*p=='\t');p++);
        strcpy(intsetname, p);
        p=strchr(intsetname, '\n');
        if (p) *p=0;
        stripspc(intsetname);
        continue;
      }
      if (strnicmp(str, "charset=", 8)==0 && charsetsdir[0]=='\0')
      { for (p=str+8;(*p==' ') || (*p=='\t');p++);
        p1=strpbrk(p, " \t");
        if (p1==NULL) goto incorrcharset;
        *p1++='\0';
        for (;(*p1==' ')||(*p1=='\t');p1++);
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
      if ((strnicmp(str, "domain=", 7)==0) && (localdom[0]==0))
      { for (p=str+7;(*p==' ') || (*p=='\t');p++);
        strcpy(localdom, p);
        p=strchr(localdom, '\n');
        if (p) *p=0;
        stripspc(localdom);
        continue;
      }
      if ((strnicmp(str, "uncompress=", 11)==0) && (uncompress[0]==0))
      { for (p=str+11;(*p==' ') || (*p=='\t');p++);
        strcpy(uncompress, p);
        p=strchr(uncompress, '\n');
        if (p) *p=0;
        stripspc(uncompress);
        continue;
      }
      if ((strnicmp(str, "tz=", 3)==0) && (tz==0))
      { if (getmytz(str+3, &tz))
          goto invparam;
        debug(6, "Config: GetTZ('%s') is %d", str+9, tz);
        continue;
      }
      if (uupcver==KENDRA)
      { if (strnicmp(str, "postmaster=", 11)==0)
        { for (p=str+11;(*p==' ') || (*p=='\t');p++);
          strcpy(gateuser, p);
          p=strchr(gateuser, '\n');
          if (p) *p=0;
          stripspc(gateuser);
        }
        if (strnicmp(str, "confdir=", 8)==0)
        { for (p=str+8;(*p==' ') || (*p=='\t');p++);
          strcpy(conf_dir, p);
          p=strchr(conf_dir, '\n');
          if (p) *p=0;
          stripspc(conf_dir);
          if (conf_dir[strlen(conf_dir)-1]!='\\')
            strcat(conf_dir, "\\");
        }
        if (strnicmp(str, "mailext=", 8)==0)
        { for (p=str+8;(*p==' ') || (*p=='\t');p++);
          strcpy(mailext, p);
        }
      }
#ifdef __MSDOS__
      if (use_swap==-1 && strnicmp(str, "swap=", 5)==0)
        setswap(str+5);
#endif
    }
    close_tpl();
    if ((p=getenv("nodename"))!=NULL)
      strcpy(local, p);
    if ((p=getenv("maildir"))!=NULL)
    { strcpy(boxdir, p);
      canonuucpdir(boxdir);
      if ((uupcver==5) || (uupcver==6))
        strcat(boxdir, "boxes\\");
    }
    if ((p=getenv("newsdir"))!=NULL)
    { strcpy(dirnews, p);
      canonuucpdir(dirnews);
    }
    if ((p=getenv("spooldir"))!=NULL)
    { strcpy(spool_dir, p);
      canonuucpdir(spool_dir);
    }
    if (uupcver==KENDRA)
    {
      if ((p=getenv("postmaster"))!=NULL)
        strcpy(gateuser, p);
      if ((p=getenv("confdir"))!=NULL)
      { strcpy(conf_dir, p);
        if (conf_dir[strlen(conf_dir)-1]!='\\')
          strcat(conf_dir, "\\");
      }
      if ((p=getenv("mailext"))!=NULL)
        strcpy(mailext, p);
    }

    if (uupcver!=KENDRA)
    {
      strcpy(str, conf_dir);
      strcat(str, "sendmail.cf");
      inconfig=2;
      if (init_tpl(str))
        return 3;
      /* ищем строки "charset?=" */
      funix=2;
      while (configline(str, sizeof(str)))
      { if (strlen(str)<9) continue;
        if ((strnicmp(str, "charset", 7)==0) && (str[8]=='=' || str[9]=='=') && charsetsdir[0]=='\0')
        { for (p=strchr(str, '=')+1;(*p==' ') || (*p=='\t');p++);
          p1=strpbrk(p, " \t");
          if (p1==NULL) goto in1corrcharset;
          *p1++='\0';
          for (;(*p1==' ')||(*p1=='\t');p1++);
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
  addchsalias("x-koi8-u", "koi8-u");
  addchsalias("cp866", "x-cp866");
  addchsalias("x-cp866-u", "ruscii");
  addchsalias("x-cp1125", "ruscii");
  addchsalias("cp866-u", "ruscii");
  addchsalias("cp1251", "x-cp1251");
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
  addmytable("x-cp866",  cp866_table, charsetsdir);
  addmytable("ruscii",   cp1125_table,charsetsdir);
  addmytable("x-cp1251", cp1251_table,charsetsdir);
  addmytable("koi8-r",   koi8r_table, charsetsdir);
  addmytable("koi8-u",   koi8u_table, charsetsdir);
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

#ifndef UNIX
  if ((local[0]==0) && uupcdir[0])
  { logwrite('?', "Can't find string \"NodeName=\"!");
    return 3;
  }
#endif
  if (local[0])
    debug(6, "Config: local node is %s", local);
  if (localdom[0]==0)
  { strcpy(localdom, local);
    strcat(localdom, ".");
    strcat(localdom, "uucp");
  }
  debug(6, "Config: local domain is %s", localdom);
  if (boxdir[0]==0)
    strcpy(boxdir, tmpdir);
  if (badmail[0]==0)
  { strcpy(badmail, boxdir);
    strcat(badmail, BADPSTNAME);
  }
  debug(6, "Config: badmail is %s", badmail);
  strcpy(userbox, boxdir);
  if (user[0])
  { strcat(userbox, user);
    if (mailext[0])
    { strcat(userbox, ".");
      strcat(userbox, mailext);
    }
  }
  else
    strcat(userbox, TMPBOXNAME);
  debug(6, "Config: userbox is %s", userbox);
  if (uncompress[0]==0)
    strcpy(uncompress, "gzip" EXEEXT " -d %s");
  debug(6, "Config: uncompress is %s", uncompress);
  /* заполняем myaka[i].uplink */
  for (i=0;i<naka;i++)
  { for (j=0;j<nuplinks;j++)
      if (myaka[i].zone==uplink[j].zone)
        break;
    if ((j==nuplinks) && (myaka[i].zone>0) && (myaka[i].zone<7))
    { for (j=0;j<nuplinks;j++)
        if ((uplink[j].zone>0) && (uplink[j].zone<7))
          break;
      if (j==nuplinks) j=0;
    }
    myaka[i].uplink=j;
  }
#ifndef UNIX
  if (uupcver==KENDRA)
  { if ((p=getenv("UUPCUSRRC"))==NULL)
    { if (gateuser[0]=='\0')
      { logwrite('?', "Parameter 'postmaster' must be set at %s!\n", getenv("UUPCSYSRC"));
        return 1;
      }
      strcpy(str, "UUPCUSRRC=");
      p=str+strlen(str);
      strcpy(p, conf_dir);
      strcat(p, gateuser);
      strcat(p, ".rc");
      if (access(p, 0))
      { logwrite('?', "File %s does not exists!\n", p);
        return 1;
      }
      putenv(strdup(str));
      debug(6, "Config: set UUPC usr RC to %s", p);
    }
    else
      debug(6, "Config: UUPC usr rc is %s", p);
  }
#endif
#ifdef __MSDOS__
  if (use_swap==-1)
    use_swap=USE_ALL;
#endif

  curtime = time(NULL);
  curtm = localtime(&curtime);
  pkthdr.OrigNode=myaka[0].node;
  pkthdr.DestNode=uplink[0].node;
  pkthdr.year=curtm->tm_year+1900;
  pkthdr.month=curtm->tm_mon;
  pkthdr.day=curtm->tm_mday;
  pkthdr.hour=curtm->tm_hour;
  pkthdr.min=curtm->tm_min;
  pkthdr.sec=curtm->tm_sec;
  pkthdr.baud=0;
  pkthdr.two=2;
  pkthdr.OrigNet=myaka[0].net;
  pkthdr.DestNet=uplink[0].net;
#if defined (FIDOUNKNWN)
  pkthdr.RevisionMaj=MAJVER;
  pkthdr.RevisionMin=MINVER;
  pkthdr.ProdCodeL=pkthdr.ProdCodeH=0;
#elif defined (FSC90)
  pkthdr.RevisionMaj=MAJVER;
  pkthdr.RevisionMin=MINVER;
  pkthdr.ProdCodeH=(char)(PRODCODE>>8);
  pkthdr.ProdCodeL=(char)(PRODCODE & 0xff);
#else
  pkthdr.RevisionMaj=pkthdr.RevisionMin=0;
  pkthdr.ProdCodeH=MAJVER;
  pkthdr.ProdCodeL=MINVER;
#endif
  strncpy(pkthdr.password, pktpwd, 8);
  pkthdr.OrigZone=myaka[0].zone;
  pkthdr.DestZone=uplink[0].zone;
  pkthdr.AuxNet=0;
  pkthdr.CWvalidationCopy=0x100;
  pkthdr.CapabilWord=1;
  pkthdr.OrigZone_=myaka[0].zone;
  pkthdr.DestZone_=uplink[0].zone;
  pkthdr.OrigPoint=myaka[0].point;
  pkthdr.DestPoint=uplink[0].point;
  pkthdr.ProductData[0]=0x7567;
  pkthdr.ProductData[1]=0x6C;
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
