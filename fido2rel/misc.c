/*
 * $Id$
 *
 * $Log$
 * Revision 2.12  2003/03/25 19:46:39  gul
 * Bugfix in retoss first message in badmail
 *
 * Revision 2.11  2002/03/21 13:43:26  gul
 * Remove dest addr list length limitation
 *
 * Revision 2.10  2002/01/15 18:48:37  gul
 * Remove nkillattfiles=32 limitation
 *
 * Revision 2.9  2001/07/09 11:14:59  gul
 * "File attached to nobody" warning fixed
 *
 * Revision 2.8  2001/01/25 18:41:38  gul
 * myname moved to debug.c
 *
 * Revision 2.7  2001/01/25 13:14:09  gul
 * quiet var moved to logwrite.c
 *
 * Revision 2.6  2001/01/25 12:40:07  gul
 * Minor changes for fix compile warnings
 *
 * Revision 2.5  2001/01/21 10:20:00  gul
 * new cfg param 'fromtop'
 *
 * Revision 2.4  2001/01/20 01:33:40  gul
 * Added some debug messages
 *
 * Revision 2.3  2001/01/19 17:43:06  gul
 * Cosmetic changes
 *
 * Revision 2.2  2001/01/16 19:10:14  gul
 * cosmetic changes (translate comments etc.)
 *
 * Revision 2.1  2001/01/15 09:37:53  gul
 * rename pkt to *.bad changed to rmove()
 *
 * Revision 2.0  2001/01/10 20:42:18  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if defined(__OS2__)
#define INCL_DOSPROCESS
#define INCL_DOSQUEUES
#define INCL_DOSFILEMGR
#include <os2.h>
#ifdef __WATCOMC__
#include <rexxsaa.h>
#endif
#endif
#ifndef W_OK
#define R_OK    4       /*  Test for read permission    */
#define W_OK    2       /*  Test for write permission   */
#define X_OK    1       /*  Test for execute permission */
#define F_OK    0       /*  Test for existence of file  */
#endif
#include "gate.h"

#define TMPOUT     "tempgate.???"

addrstr *send_to;
addrstr *rej;
addrstr *sfree;
char pktin[FNAME_MAX], pktout[FNAME_MAX];
struct echotype _Huge *echoes;
struct grouptype *group;
unsigned nechoes, ngroups;
char rescan[FNAME_MAX];
char master[80], newsserv[80], organization[80];
char binkout[FNAME_MAX];
char tboxes[FNAME_MAX];
#ifndef __MSDOS__
char lbso[FNAME_MAX], tlboxes[FNAME_MAX], longboxes[FNAME_MAX];
#endif
uword mastzone, mastnet, mastnode, mastpoint;
ftnaddress *uplink;
aliastype *alias;
unsigned nuplink;
unsigned nsend, nrej, nfree, ncdomain, nalias, nmoder, nchecker, nattfrom;
gatetype *gates;
cdomaintype *cdomain;
modertype *moderator;
checktype *checker;
int ngates, curgate;
int maxrcv, gatevia;
char rmail[FNAME_MAX];
char netmaildir[FNAME_MAX];
char tmpdir[FNAME_MAX];
char gatemaster[128]="postmaster";
struct t_addr *myaka;
int  naka, curaka, upaka;
unsigned ncaddr, npaddr, ntwit, nnotwit;
uword zone, net, node, point;
unsigned maxsize=8;
unsigned maxline=70;
int  xcomment;
struct caddrtype *caddr;
struct addrtype *paddr, *twit, *notwit, *attfrom;
struct message msghdr;
char *to, *gw_to, from[128];
int  sizeto, sizegw_to;
char pktpwd[9];
char packed;
char str[2048];
char *buffer;
unsigned ibuf;
unsigned long offs_beg;
int  h;
char msgname[FNAME_MAX]="";
struct packet pkthdr;
struct lrd_type lastread, new_lrd;
int  lrd;
char *pheader[MAXFIELDS];
int  cheader;
ftnaddress pktdest;
int  ourpkt;
int  hidetear, hideorigin;
int  fsp1004, bangfrom, env_chaddr, fromtop;
int  writereason=0;
char inb_dir[FNAME_MAX], charsetsdir[FNAME_MAX], charsetalias[FNAME_MAX];
#ifdef __MSDOS__
int  share;
#endif

static DIR *d=NULL;
static struct dirent *df;
static unsigned potolok;
static int killed=0;
struct ftnchrs_type *ftnchrs=NULL;

static void findpkt(void);
static int  nextpktaka(int *curaka);
static void one_pkt(char *msgname);

#if defined(DO_PERL) && defined(OS2)
/* Perl for OS2 has own malloc/free but does not have strdup :( */
char *strdup(const char *str)
{
  char *p = malloc(strlen(str)+1);
  if (p) strcpy(p, str);
  return p;
}
#endif

int params(int argc, char *argv[])
{ int help, i;
  char *p, *p1;

  nconf[0]=0;
  inconfig=1;
  tossbad=nonet=noecho=help=nglobal=fake=0;
  lrd=LRD_CREATE;
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
  for (i=1; i<argc; i++)
  {
    if ((argv[i][0]!='-') && (argv[i][0]!='/'))
    { fprintf(stderr, "Incorrect parameter \"%s\" ignored!\n", argv[i]);
      continue;
    }
    if (stricmp(argv[i]+1, "nonet")==0)
    { nonet=1;
      continue;
    }
    if (stricmp(argv[i]+1, "noecho")==0)
    { noecho=1;
      continue;
    }
    if (stricmp(argv[i]+1, "tossbad")==0)
    { tossbad=1;
      continue;
    }
    if (stricmp(argv[i]+1, "fake")==0)
    { fake=1;
      continue;
    }
    if (stricmp(argv[i]+1, "l")==0)
    { lrd=LRD_CHECK;
      continue;
    }
    if (stricmp(argv[i]+1, "q")==0)
    { quiet=1;
      continue;
    }
    if (stricmp(argv[i]+1, "l-")==0)
    { lrd=0;
      continue;
    }
    if ((stricmp(argv[i]+1, "help")==0) || (stricmp(argv[i]+1, "-help")==0) ||
        (stricmp(argv[i]+1, "h")==0)    || (stricmp(argv[i]+1, "?")==0))
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
        continue;
      }
    }
    if (tolower(argv[i][1])=='c')
    { strcpy(nconf, argv[i]+2);
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
          continue;
        }
      }
      p=strchr(p1, '=');
      if (p)
      { *p++=0;
        setglobal(p1, p);
      }
      else
        fprintf(stderr, "Incorrect %s swicth ignored!\n", argv[i]);
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
  }
  if (help)
  {
    puts(COPYRIGHT);
    puts("FTN -> Internet Gate");
    puts("Copyright (C) Pavel Gulchouck 2:463/68 aka gul@gul.kiev.ua");
    puts("   Usage:");
    puts("fido2rel" COMEXT " [<switches>]");
    puts("   Switches:");
    puts("-noecho         - don't gate *.pkt and *.?ut, only *.msg");
    puts("-nonet          - don't gate *.msg");
    puts("-tossbad        - retoss bad messages");
    puts("-c<filename>    - config file (default is gate.cfg)");
    puts("-l              - use lastreads");
    puts("-l-             - don't create lastreads");
    puts("-q              - be quiet");
    puts("-d<var>=<value> - set variable for config and template");
    puts("-[x|X]<level>   - debug level");
    puts("-fake           - do nothing, only save params");
    puts("-?, -h          - this help");
  }
  if (help && (!tossbad) && (!nonet) && (!noecho) && (nconf[0]==0) &&
     (lrd==LRD_CREATE))
  { /* "/?" only */
    return 1;
  }
#if defined(HAVE_GETUID) && defined(HAVE_GETEUID) && defined(HAVE_GETGID) && defined(HAVE_GETEGID)
  if (nconf[0] && (getuid()!=geteuid() || getgid()!=getegid()))
  { puts("You do not allow to use -c switch");
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
  lastread.time=new_lrd.time=0;
  lastread.num=new_lrd.num=0;
  if (lrd==LRD_CHECK)
  { strcpy(str, netmaildir);
    strcat(str, PATHSTR LRDNAME);
    i=open(str, O_RDONLY|O_BINARY);
    if (i!=-1)
    { read(i, &lastread, sizeof(lastread));
      close(i);
    }
  }
  return 0;
}

void term(int signo)
{
  killed=1;
#ifdef SIGINT
  signal(SIGINT,   SIG_IGN);
#endif
#ifdef SIGBREAK
  signal(SIGBREAK, SIG_IGN);
#endif
#ifdef SIGTERM
  signal(SIGTERM,  SIG_IGN);
#endif
}

void set_table(char *charset)
{
  short int *exttable, *xtable;
  int i, j;

  debug(8, "Set_Table charset=%s", charset);
  for (i=0; i<128; i++) int2ext_tab[i]=(char)(i+128);
  if ((exttable = findtable(myextsetname, charsetsdir)) == NULL)
    return;
  if ((xtable=findtable(charset, charsetsdir)) == NULL)
    return;
  memset(int2ext_tab, '?', 128);
  for (i=128; i<256; i++)
  { for (j=0; j<256; j++)
      if (xtable[i]==exttable[j])
      { int2ext_tab[i & 0x7f]=j;
        break;
      }
    if (j==256 && charsetsdir[0])
    { int newc=0;
      if (xtable[i]==1168) /* ukrainian capital "GHE" with upturn */
        newc=1043;         /* cyrillic capital "GHE" */
      else if (xtable[i]==1169) /* ukrainian small "GHE" with upturn */
        newc=1075;              /* cyrillic small "GHE" */
      else if (xtable[i]==1030) /* ukrainian capital "I" */
        newc='I';
      else if (xtable[i]==1110) /* ukrainian small "I" */
        newc='i';
      if (newc)
        for (j=0; j<256; j++)
          if (exttable[j]==newc)
            int2ext_tab[i & 0x7f]=j;
    }
  }
}

void retoss(void)
{ int  i, h, firstbuf, lastch;
  long l, curoffs;
  FILE *fbad;
  time_t curtime;
  struct tm *curtm;

  /* pack all *.msg from badmail to pkt-file in pktin */
  if (badmail[0]==0)
    return;
  d=opendir(badmail);
  if (d==NULL)
    return;
  while ((df=readdir(d))!=NULL)
  { if (strlen(df->d_name)<5) continue;
    if (stricmp(df->d_name+strlen(df->d_name)-4, ".msg")==0)
      break;
  }
  if (df==NULL)
  { closedir(d);
    return;
  }
  l=time((time_t *)&l);
  do
  { sprintf(msgname, "%s%08lx.pkt", pktin, l);
    l++;
  } while (access(msgname, 0)==0);
  debug(6, "retoss: pktname is %s", msgname);
  fbad=fopen(msgname, "wb");
  if (fbad==NULL)
  { logwrite('?', "Can't create %s: %s!\n", msgname, strerror(errno));
    closedir(d);
    return;
  }
  if (flock(fileno(fbad), LOCK_EX|LOCK_NB))
  { logwrite('?', "Can't lock %s: %s!\n", msgname, strerror(errno));
    fclose(fbad);
    unlink(msgname);
    closedir(d);
    return;
  }
  /* put pkt header */
  curtime=time(NULL);
  curtm=localtime(&curtime);

  pkthdr.OrigNode=uplink[0].node;
  pkthdr.DestNode=myaka[0].node;
  pkthdr.year =curtm->tm_year+1900;
  pkthdr.month=curtm->tm_mon;
  pkthdr.day  =curtm->tm_mday;
  pkthdr.hour =curtm->tm_hour;
  pkthdr.min  =curtm->tm_min;
  pkthdr.sec  =curtm->tm_sec;
  pkthdr.baud=0;
  pkthdr.two=2;
  pkthdr.OrigNet=uplink[0].net;
  pkthdr.DestNet=myaka[0].net;
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
  pkthdr.OrigZone=uplink[0].zone;
  pkthdr.DestZone=myaka[0].zone;
  pkthdr.AuxNet=0;
  pkthdr.CWvalidationCopy=0x100;
  pkthdr.CapabilWord=1;
  pkthdr.OrigZone_=uplink[0].zone;
  pkthdr.DestZone_=myaka[0].zone;
  pkthdr.OrigPoint=uplink[0].point;
  pkthdr.DestPoint=myaka[0].point;
  pkthdr.ProductData[0]=0x7567;
  pkthdr.ProductData[1]=0x6C;
  pkthdr_byteorder(&pkthdr);
  if (fwrite(&pkthdr, sizeof(pkthdr), 1, fbad)!=1)
  { logwrite('?', "Can't write to %s: %s!\n", msgname, strerror(errno));
    flock(fileno(fbad), LOCK_UN);
    fclose(fbad);
    unlink(msgname);
    closedir(d);
    return;
  }
  for (; df; df=readdir(d))
  { if (strlen(df->d_name)<5) continue;
    if (stricmp(df->d_name+strlen(df->d_name)-4, ".msg"))
      continue;
    curoffs=ftell(fbad);
    strcpy(str, badmail);
    addslash(str);
    strcat(str, df->d_name);
    debug(12, "ReToss: copy %s to %s", str, msgname);
    h=myopen(str, O_BINARY|O_RDONLY|O_EXCL);
    if (h==-1)
    { logwrite('?', "Can't open %s: %s!\n", str, strerror(errno));
      continue;
    }
    if (flock(h, LOCK_EX|LOCK_NB))
    { logwrite('?', "Can't lock %s: %s!\n", str, strerror(errno));
      close(h);
      continue;
    }
    if (read(h, &msghdr, sizeof(msghdr))!=sizeof(msghdr))
    { logwrite('?', "Error in %s!\n", str);
      flock(h, LOCK_UN);
      close(h);
      continue;
    }
    /* put msg to pkt */
    writemsghdr(&msghdr, fbad);
    firstbuf=1;
    lastch='\r';
    for (i=read(h, buffer, BUFSIZE); i>0; i=read(h, buffer, BUFSIZE))
    {
      if (firstbuf)
      { if (strncmp(buffer, "Reason:", 7)==0)
        { char *p;
          for (p=buffer; *p!='\r' && p-buffer<i; p++);
          if (*p=='\r')
          { p++;
            i-=(unsigned)(p-buffer);
            memcpy(buffer, p, i);
            if (i==0) continue;
          }
        }
        firstbuf=0;
      }
      lastch=buffer[i-1];
      if (fwrite(buffer, i, 1, fbad)!=1)
      {
retosserr:
        logwrite('?', "Can't write to %s: %s!\n", msgname, strerror(errno));
        flock(h, LOCK_UN);
        close(h);
        fseek(fbad, curoffs, SEEK_SET);
        h=0;
        fwrite(&h, 2, 1, fbad);
        fflush(fbad);
        chsize(fileno(fbad), curoffs+2);
        flock(fileno(fbad), LOCK_UN);
        fclose(fbad);
        closedir(d);
        return;
      }
    }
    if (lastch!=0)
      /* msg not ended by \0 */
      if (fwrite("", 1, 1, fbad)!=1)
        goto retosserr;
    if (fflush(fbad))
      goto retosserr;
    flock(h, LOCK_UN);
    close(h);
    unlink(str);
  }
  closedir(d);
  i=0;
  fwrite(&i, 2, 1, fbad);
  fflush(fbad);
  flock(fileno(fbad), LOCK_UN);
  fclose(fbad);
}

void findlet(void)
{ struct stat statbuf;

  debug(3, "FindLet");
  if (tossbad && msgname[0] && access(msgname, 1)==0)
  { packed=1;
    one_pkt(msgname);
  }
  if (killed)
  { logwrite('!', "Terminated by Ctrl/Break or SIGTERM!\n");
    return;
  }
  packed=0;
  if (!nonet)
  { ourpkt=1;
    pktdest.zone=pktdest.net=pktdest.node=pktdest.point=0;
    upaka=0;
    if (h!=-1)
    { flock(h, LOCK_UN);
      close(h);
    }
    h=-1;
    d=opendir(netmaildir);
    if (d)
    { while ((df=readdir(d))!=NULL)
      { if (cmpaddr(df->d_name, "*.msg"))
          continue;
        debug(11, "FindLet: found %s", df->d_name);
        strcpy(msgname, netmaildir);
        addslash(msgname);
        strcat(msgname, df->d_name);
        if (access(msgname, 2)) /* W_OK */
        { debug(11, "FindLet: file R/O, skipped");
          continue;
        }
        stat(msgname, &statbuf);
        if (lrd==LRD_CHECK)
        { /* check lastreads */
          if ((lastread.num>=atoi(df->d_name)) &&
              (lastread.time>=statbuf.st_mtime))
          { debug(11, "FindLet: LastRead check, message skipped");
            continue;
          }
        }
        if (lrd)
        { if (new_lrd.num<atoi(df->d_name))
            new_lrd.num=atoi(df->d_name);
          /* check if the date is correct */
          if (statbuf.st_mtime<=time(NULL))
            new_lrd.time=statbuf.st_mtime;
          else
            logwrite('!', "Message %s has future time!\n", df->d_name);
        }
        h=myopen(msgname, O_RDWR|O_BINARY|O_EXCL);
        if (h==-1)
        { debug(11, "FindLet: Can't open: %s, message skipped", strerror(errno));
          continue;
        }
        if (flock(h, LOCK_EX|LOCK_NB))
        { debug(11, "FindLet: Can't flock: %s, message skipped", strerror(errno));
          close(h);
          continue;
        }
        ibuf=BUFSIZE;
        if (hread(h, &msghdr, sizeof(msghdr))!=sizeof(msghdr))
        { debug(11, "FindLet: can't read msg header, skipped");
          flock(h, LOCK_UN);
          close(h);
          continue;
        }
        debug(4, "FindLet: message %s size %lu bytes for us", msgname, filelength(h));
        msghdr_byteorder(&msghdr);
        if (one_message(msgname))
        { closedir(d);
          return;
        }
        if (h!=-1)
        { flock(h, LOCK_UN);
          close(h);
          h=-1;
        }
        if (killed) break;
      }
      closedir(d);
      /* write lastreads */
      if (lrd)
      { debug(12, "FindLet: update LastRead");
        strcpy(msgname, netmaildir);
        strcat(msgname, PATHSTR LRDNAME);
        if (access(msgname, W_OK))
          h=myopen(msgname, O_BINARY|O_RDWR|O_CREAT|O_EXCL);
        else
          h=myopen(msgname, O_BINARY|O_RDWR|O_EXCL);
        if (h!=-1)
        { if (flock(h, LOCK_EX|LOCK_NB)==0)
          { write(h, &new_lrd, sizeof(new_lrd));
            flock(h, LOCK_UN);
          }
          close(h);
          h=-1;
        }
      }
    }
  }
  if (noecho)
  { debug(11, "FindLet: no more netmail messages");
    return;
  }
  packed=1;
  if (!killed)
    findpkt();
  if (killed)
    logwrite('!', "Terminated by Ctrl/Break or SIGTERM!\n");
  else
    debug(11, "FindLet: no more messages");
}

static void one_pkt(char *msgname)
{ int i, r=0;

  debug(11, "One_Pkt: found %s", msgname);
  h=myopen(msgname, O_RDWR|O_BINARY|O_EXCL);
  if (h==-1)
  { debug(11, "One_Pkt: can't open %s: %s, skipped", msgname, strerror(errno));
    return;
  }
  if (flock(h, LOCK_EX|LOCK_NB))
  { debug(11, "One_Pkt: can't flock %s: %s, skipped", msgname, strerror(errno));
    close(h);
  }
  if (read(h, &pkthdr, sizeof(pkthdr))!=sizeof(pkthdr))
  { flock(h, LOCK_UN);
    close(h);
    h=-1;
    debug(11, "One_Pkt: can't read pkt header, skipped");
    return;
  }
  pkthdr_byteorder(&pkthdr);
  debug(15, "One_Pkt: packet from %d:%d/%d.%d to %d:%d/%d.%d",
        pkthdr.OrigZone, pkthdr.OrigNet, pkthdr.OrigNode, pkthdr.OrigPoint,
        pkthdr.DestZone, pkthdr.DestNet, pkthdr.DestNode, pkthdr.DestPoint);
  strncpy(str, pkthdr.password, 8);
  str[8]=0;
  debug(15, "One_Pkt: pkt passwd='%s'", str);
  debug(17, "One_Pkt: AuxNet=%d, OrigZone_=%d, DestZone_=%d",
        pkthdr.AuxNet, pkthdr.OrigZone_, pkthdr.DestZone_);
  for (i=0; i<naka; i++)
    if ((pkthdr.DestNode==myaka[i].node) &&
        (pkthdr.DestNet==myaka[i].net) &&
        (pkthdr.DestZone==myaka[i].zone) &&
        (pkthdr.DestPoint==myaka[i].point))
      break;
  if (i==naka)
  {
    for (i=0; i<ngates; i++)
      if ((pkthdr.DestNode==gates[i].pktfor.node) &&
          (pkthdr.DestNet==gates[i].pktfor.net) &&
          (pkthdr.DestZone==gates[i].pktfor.zone) &&
          (pkthdr.DestPoint==gates[i].pktfor.point))
      break;
    if (i==ngates)
    { flock(h, LOCK_UN);
      close(h);
      h=-1;
      debug(11, "FindLet: packet not for us, skipped");
      return;
    }
    ourpkt=0;
  }
  else
    ourpkt=1;
  if ((pkthdr.DestZone_!=pkthdr.DestZone) ||
      (pkthdr.OrigZone_!=pkthdr.OrigZone))
  { flock(h, LOCK_UN);
    close(h);
    h=-1;
    debug(11, "One_Pkt: strange zone in pkthdr, skipped");
    return;
  }
  for (upaka=0; upaka<nuplink; upaka++)
  {
    if ((pkthdr.OrigZone!=uplink[upaka].zone) ||
        (pkthdr.OrigNet!=uplink[upaka].net) ||
        ((pkthdr.AuxNet!=0) && (pkthdr.AuxNet!=uplink[upaka].net)) ||
        (pkthdr.OrigNode!=uplink[upaka].node) ||
        (pkthdr.OrigPoint!=uplink[upaka].point))
    { if (uplink[upaka].point==0)
        continue;
      if ((pkthdr.OrigZone!=uplink[upaka].zone) ||
          (pkthdr.OrigNet!=-1) ||
          (pkthdr.AuxNet!=uplink[upaka].net) ||
          (pkthdr.OrigNode!=uplink[upaka].node) ||
          (pkthdr.OrigPoint!=uplink[upaka].point))
        continue;
    }
    break;
  }
  if (upaka==nuplink)
  { flock(h, LOCK_UN);
    close(h);
    h=-1;
    logwrite('!', "Packet %s not from uplink, ignored\n", msgname);
    return;
  }
  strncpy(str, pkthdr.password, 8);
  str[8]=0;
  if (stricmp(str, pktpwd) && pktpwd[0])
  { logwrite('!', "Incorrect password \"%s\" in %s: expected \"%s\"\n",
             str, msgname, pktpwd);
    badpkt();
    return;
  }
  ibuf=BUFSIZE;
  pktdest.zone=pkthdr.DestZone;
  pktdest.net=pkthdr.DestNet;
  pktdest.node=pkthdr.DestNode;
  pktdest.point=pkthdr.DestPoint;
#ifdef __OS2__
  DosSetFHState(h, OPEN_FLAGS_NOINHERIT); /* else we cannot delete because of uux running */
#endif
  debug(4, "%s size %lu bytes for us", msgname, filelength(h));

  for (; h!=-1;)
  { /* is there another messages? */
    /* and read header */
    i=0;
    if (hread(h, &i, 2)!=2)
    { logwrite('?', "Incorrect packet structure, %s renamed to *.bad!\n",
               msgname);
      badpkt();
      return;
    }
    if (i==0)
    { while ((i=hgetc(h))==0);
      if (i!=EOF)
      { logwrite('!', "Warning: data exists after logical EOF in %s!\n",
                 msgname);
        flock(h, LOCK_UN);
        close(h);
        h=-1;
        badpkt();
        return;
      }
      flock(h, LOCK_UN);
      close(h);
      h=-1;
      if (rclose())
      { logwrite('?', "Can't send cnews-packet, %s renamed to bad!\n", msgname);
        badpkt();
        return;
      }
      if (unlink(msgname))
        logwrite('!', "Can't unlink %s: %s!\n", msgname, strerror(errno));
      else
        debug(8, "One_Pkt: %s deleted", msgname);
      return;
    }
    if (hread(h, &msghdr.orig_node, 2)!=2)
    {
gobadpkt:
      logwrite('?', "Can't read %s: %s!\n", msgname, strerror(errno));
      badpkt();
      return;
    }
    if (hread(h, &msghdr.dest_node, 2)!=2)
      goto gobadpkt;
    if (hread(h, &msghdr.orig_net, 2)!=2)
      goto gobadpkt;
    if (hread(h, &msghdr.dest_net, 2)!=2)
      goto gobadpkt;
    if (hread(h, &msghdr.attr, 2)!=2)
      goto gobadpkt;
    if (hread(h, &msghdr.cost, 2)!=2)
      goto gobadpkt;
    /* read date */
    for (i=0; i<sizeof(msghdr.date); i++)
    { r=hgetc(h);
      if (r==EOF)
        goto gobadpkt;
      msghdr.date[i]=(char)r;
      if (r==0) break;
    }
    if (r)
    { logwrite('?', "Bad packed message structure in %s ('Date' field)\n", msgname);
      badpkt();
      return;
    }
    /* read to */
    for (i=0; i<sizeof(msghdr.to); i++)
    { r=hgetc(h);
      if (r==EOF)
        goto gobadpkt;
      msghdr.to[i]=(char)r;
      if (r==0) break;
    }
    if (r)
    { logwrite('?', "Bad packed message structure in %s ('To' field)\n", msgname);
      badpkt();
      return;
    }
    /* read from */
    for (i=0; i<sizeof(msghdr.from); i++)
    { r=hgetc(h);
      if (r==EOF)
        goto gobadpkt;
      msghdr.from[i]=(char)r;
      if (r==0) break;
    }
    if (r)
    { logwrite('?', "Bad packed message structure in %s ('From' field)\n", msgname);
      badpkt();
      return;
    }
    /* read subj */
    for (i=0; i<sizeof(msghdr.subj); i++)
    { r=hgetc(h);
      if (r==EOF)
        goto gobadpkt;
      msghdr.subj[i]=(char)r;
      if (r==0) break;
    }
    if (r)
    { logwrite('?', "Bad packed message structure in %s ('Subj' field)\n", msgname);
      badpkt();
      return;
    }
    if (!(msghdr.attr & msgLOCAL))
      msghdr.attr|=msgFORWD;
    offs_beg=lseek(h, 0, SEEK_CUR)-potolok+ibuf;
    debug(11, "FindLet: found message");
    msghdr_byteorder(&msghdr);
    one_message(msgname);
  }
}

void badpkt(void)
{ char *p;

  if (h!=-1)
  { flock(h, LOCK_UN);
    close(h);
    h=-1;
  }
  debug(5, "BadPkt: %s", msgname);
  strcpy(str, msgname);
  p=strrchr(str, PATHSEP);
  if (p==NULL) p=str;
  p=strchr(p, '.');
  if (p==NULL) p=str+strlen(str);
  strcpy(p, ".bad");
  if (rmove(msgname, str))
    logwrite('!', "Can't rename %s to %s: %s!\n", msgname, str, strerror(errno));
}

void badmsg(char *reason)
{ DIR *d;
  struct dirent *df;
  unsigned maxmsg;
  int fbad, i;
  char *p;
  char name[256];

  debug(5, "BadMsg");
  if (area==-1)
    logwrite('!', "From %s %u:%u/%u.%u to %s failed (%s)\n",
             msghdr.from, zone, net, node, point, to[0] ? to : msghdr.to,
             reason);
  if (!packed)
  { /* copy to badmail */
    if (badmail[0]==0)
    { badpkt(); /* rename to *.bad */
      return;
    }
  }
  maxmsg=0;
  d=opendir(badmail[0] ? badmail : netmaildir);
  if (d==NULL)
  { logwrite('?', "Can't opendir %s: %s!\n",
             badmail[0] ? badmail : netmaildir, strerror(errno));
    if (packed)
      badpkt();
    return;
  }
  while ((df=readdir(d))!=NULL)
  { if (cmpaddr(df->d_name, badmail[0] ? "*.msg" : "*.bad"))
      continue;
    if (atoi(df->d_name)>maxmsg)
      maxmsg=atoi(df->d_name);
  }
  closedir(d);

  strcpy(name, badmail[0] ? badmail : netmaildir);
  addslash(name);
  if (badmail[0])
    sprintf(name+strlen(name), "%u.msg", maxmsg+1);
  else
    sprintf(name+strlen(name), "%u.bad", maxmsg+1);

#if 0
  if ((!packed) && (toupper(msgname[0])==toupper(name[0])))
  { if (h!=-1)
    { flock(h, LOCK_UN);
      close(h);
      h=-1;
    }
    if (rename(msgname, name)==0)
    { debug(5, "BadMsg: renamed %s to %s", msgname, name);
      return;
    }
    debug(1, "BadMsg: can't rename %s to %s: %s", msgname, name, strerror(errno));
  }
#endif
  fbad=myopen(name, O_BINARY|O_RDWR|O_EXCL|O_CREAT);
  if (fbad==-1 || flock(fbad, LOCK_EX|LOCK_NB))
  { if (fbad!=-1)
    { close(fbad);
      unlink(name);
      fbad=-1;
    }
    logwrite('?', "Can't create %s: %s!\n", name, strerror(errno));
    if (packed)
      badpkt();
    return;
  }
  if (h==-1)
  { h=myopen(msgname, O_BINARY|O_RDONLY|O_EXCL);
    if (h==-1 || flock(h, LOCK_EX|LOCK_NB))
    { if (h!=-1)
      { close(h);
        unlink(msgname);
        h=-1;
      }
      flock(fbad, LOCK_UN);
      close(fbad);
      unlink(name);
      logwrite('?', "Can't open %s: %s!\n", msgname, strerror(errno));
      if (packed)
        badpkt();
      return;
    }
  }
  if (packed)
    lseek(h, offs_beg, SEEK_SET);
  else
    lseek(h, sizeof(msghdr), SEEK_SET);
  debug(5, "BadMsg: copy %s to %s", msgname, name);
  ibuf=BUFSIZE;
  write(fbad, &msghdr, sizeof(msghdr));
  if (writereason)
  { write(fbad, "Reason: ", 8);
    write(fbad, reason, strlen(reason));
    write(fbad, "\r", 1);
  }
  while (hgets(str, sizeof(str), h))
  { p=strchr(str, '\n');
    if (p) *p='\r';
    write(fbad, str, strlen(str));
  }
  i=0;
  write(fbad, &i, 1);
  flock(fbad, LOCK_UN);
  close(fbad);
  if (!packed)
  { flock(h, LOCK_UN);
    close(h);
    h=-1;
    unlink(msgname);
    debug(5, "BadMsg: %s deleted", msgname);
  }
  debug(11, "BadMsg: done");
}

int isfield(char *line)
{ int i;

  for (i=0; i<cheader; i++)
    if (strnicmp(pheader[i], line, strlen(line))==0)
      return 1;
  return 0;
}

int hgetc(int h)
{
  if ((ibuf==BUFSIZE) || (ibuf==potolok))
  { potolok=read(h, buffer, BUFSIZE);
    ibuf=0;
  }
  if (ibuf==potolok)
    return EOF;
  return buffer[ibuf++];
}

int hread(int h, void *buf, unsigned n)
{ unsigned u;
  int i;
  for (u=0; u<n; u++)
  { i=hgetc(h);
    if (i==EOF) return u;
    ((char *)buf)[u]=(char)i;
  }
  return n;
}

int hgets(char *s, unsigned ssize, int h)
{ int i, j;

  for (i=0; i<ssize-1; i++)
  { j=hgetc(h);
    if (j==EOF)
    { s[i]=0;
      return i;
    }
    s[i]=(char)j;
    if (j==0)
    { if (i) ibuf--; /* handle last line without '\r' -- BiP */
      return i;
    }
    if (j=='\n')
    { s[++i]=0;
      return i;
    }
    if (j=='\r')
    { j=hgetc(h);
      if ((j!='\n') && (j!=EOF))
        ibuf--;
      s[i++]='\n';
      s[i]=0;
      return i;
    }
  }
  s[ssize-1]=0;
  return ssize;
}

void parsekludge(char *str, char *klname, char *klopt)
{ char *p, *pklname, *pklopt;

  p=str+strlen(str)-1;
  if (strlen(str)==0 || *p!='\n') p=NULL;
  else *p='\0';
  debug(11, "ParseKludge: '%s'", str);
  if (p) *p='\n';
  pklname=klname, pklopt=klopt;
  for (p=str+1; *p && (*p!=':') && !isspace(*p);)
    *pklname++=*p++;
  *pklname='\0';
  *pklopt='\0';
  if (*p=='\0')
  { debug(11, "ParseKludge: klname='%s', klopt='%s'", klname, klopt);
    return;
  }
  for (p++; isspace(*p); p++);
  if (*p=='\0')
  { debug(11, "ParseKludge: klname='%s', klopt='%s'", klname, klopt);
    return;
  }
  while (*p && (*p!='\n'))
    *pklopt++=*p++;
  *pklopt='\0';
  debug(11, "ParseKludge: klname='%s', klopt='%s'", klname, klopt);
}

int moveatt(char *fname, unsigned long attr)
{ char *p, *p1;
  int i, h;
  char tmpfname[FNAME_MAX];

  if (strpbrk(fname, "/\\")==NULL)
  {
    strcpy(tmpfname, inb_dir);
    strncat(tmpfname, fname, sizeof(tmpfname)-1);
    tmpfname[sizeof(tmpfname)-1]='\0';
    fname=tmpfname;
  }
  if (access(fname, 0))
  { logwrite('!', "Can't find attached file %s!\n", fname);
    return 1;
  }
  p1=fname;
  p=strrchr(p1, '/');
  if (p) p1=p+1;
#ifndef UNIX
  p=strrchr(p1, '\\');
  if (p) p1=p+1;
  p=strrchr(p1, ':');
  if (p) p1=p+1;
#endif
  strcpy(str, tmpdir);
  strcat(str, p1);
  if (stricmp(str, fname)==0)
  {
#if 1
    static int maxkillattfiles=0;
    void *newptr;
    if (nkillattfiles==maxkillattfiles)
    { if (maxkillattfiles)
      { newptr=realloc(killattfiles,sizeof(*killattfiles)*(maxkillattfiles*=2));
        if (newptr==NULL) free(killattfiles);
        killattfiles=newptr;
      }
      else
        killattfiles=malloc(sizeof(*killattfiles)*(maxkillattfiles=32));
      if (killattfiles == NULL)
      { logwrite('!', "Not enough memory (%ld bytes needed)\n", sizeof(*killattfiles)*maxkillattfiles);
        return 0;
      }
    }
#else
    if (nkillattfiles<sizeof(killattfiles)/sizeof(killattfiles[0]))
#endif
    { killattfiles[nkillattfiles].name=strdup(p1);
      killattfiles[nkillattfiles++].attr=attr;
    }
    return 0;
  }
  /* make unique filename */
  if (access(str, 0)==0)
  { if (strchr(fname, '.')==NULL)
      strcat(str, ".");
    p=strrchr(str, '.');
    while (strlen(p)<4)
      strcat(str, "0");
    p=str+strlen(str)-3;
    for (i=0; i<999; i++)
    { if (access(str, 0))
        break;
      if (i<10)
        sprintf(p+2, "%d", i);
      else if (i<100)
        sprintf(p+1, "%d", i);
      else
        sprintf(p, "%d", i);
    }
  }
  p=strrchr(str, PATHSEP);
  if (p==NULL) p=str;
  else p++;
  if (attr & msgKFS)
    if (rename(fname, str)==0)
    { debug(5, "moveatt: %s renamed to %s", fname, str);
      if (nkillattfiles<sizeof(killattfiles)/sizeof(killattfiles[0]))
      { killattfiles[nkillattfiles].name=strdup(p);
        killattfiles[nkillattfiles++].attr=msgKFS;
      }
      return 0;
    }
  if (copyfile(fname, str))
  { logwrite('?', "Can't copy %s to %s: %s!\n", fname, str, strerror(errno));
    return 1;
  }
  if (nkillattfiles<sizeof(killattfiles)/sizeof(killattfiles[0]))
  { killattfiles[nkillattfiles].name=strdup(p);
    killattfiles[nkillattfiles++].attr=msgKFS;
  }
  debug(5, "moveatt: %s copied to %s", fname, str);
  if (attr & msgKFS)
  { if (unlink(fname))
      logwrite('!', "Can't unlink %s: %s\n", fname, strerror(errno));
    else
      debug(5, "moveatt: %s unlinked", fname);
  }
  else if (attr & msgTFS)
  { h=open(fname, O_BINARY|O_RDWR|O_EXCL);
    if (h==-1)
    { logwrite('!', "Can't trancate %s: %s", fname, strerror(errno));
      return 0;
    }
    chsize(h, 0);
    close(h);
    debug(5, "moveatt: %s trancated", fname);
  }
  return 0;
}

static void checkbox(char *path)
{
  DIR *d;
  struct dirent *df;
  struct stat st;

  d=opendir(path);
  if (d==NULL)
    return;
  while ((df=readdir(d))!=NULL)
  { if (df->d_name[0]=='.') continue;
    strcpy(msgname, path);
    strcat(msgname, df->d_name);
    if (stat(msgname, &st))
      continue;
    if (!(st.st_mode & S_IFREG))
      continue;
    if (cmpaddr(df->d_name, "*.pkt"))
    { moveatt(msgname, msgKFS);
      continue;
    }
    debug(4, "checkbox: found %s", msgname);
    one_pkt(msgname);
    if (killed) break;
  }
  closedir(d);
}

static char dhex(int i)
{ return (i>9) ? 'a'+i-10 : '0'+i;
}

static void findpkt(void)
{ int i, fpktaka, hbsy;
  static char loname[256], *bsyname;
  FILE *hlo;
  char flavours[]="icdfnh";
  char flavoursut[]="icdoh";
#ifndef __MSDOS__
  char *lbsoflavours[]={"Immediate", "Crash", "Direct", "Normal", "Hold" };
#define lbsoflavoursut lbsoflavours
#endif
  ftnaddress5d fpktaddr;

  if (binkout[0] ||
#ifndef __MSDOS__
      lbso[0] || tlboxes[0] || longboxes[0] ||
#endif
      tboxes[0])
  {
    fpktaka=-1;
    while (nextpktaka(&fpktaka)==0)
    { 
      if (fpktaka<naka)
      { debug(20, "FindPkt: check for aka number %d (total %d akas)", fpktaka, naka);
        memcpy(&fpktaddr, &myaka[fpktaka], sizeof(fpktaddr));
      }
      else
      { debug(20, "FindPkt: check for gate number %d (total %d gates)", fpktaka-naka, ngates);
        memcpy(&fpktaddr, &gates[fpktaka-naka].pktfor, sizeof(fpktaddr));
      }
      debug(4, "FindPkt: check mail for %u:%u/%u.%u",
            fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point);
      if (binkout[0])
      { bsyname=GetBinkBsyName((ftnaddr *)&fpktaddr, binkout, myaka[0].zone);
        strcpy(loname, bsyname);
        strcpy(loname+strlen(loname)-3, "clo");
        hbsy=-1;
        for (i=0; i<strlen(flavours); i++)
        { loname[strlen(loname)-3]=flavours[i];
          debug(20, "FindPkt: checking %s", loname);
          if (access(loname, 2)) continue;
          debug(4, "FindPkt: found %s", loname);
          if (hbsy==-1)
          { hbsy=open(bsyname, O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
            if (hbsy==-1)
            { logwrite('!', "Can't create %s, mail for %u:%u/%u.%u skipped\n",
                       bsyname, fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point);
              break;
            }
#ifdef __OS2__
            DosSetFHState(hbsy, OPEN_FLAGS_NOINHERIT);
#endif
            debug(8, "FindPkt: %s created", bsyname);
          }
          hlo=fopen(loname, "r");
          if (hlo==NULL)
          { logwrite('!', "Can't open %s: %s!\n", loname, strerror(errno));
            continue;
          }
#ifdef __OS2__
          DosSetFHState(fileno(hlo), OPEN_FLAGS_NOINHERIT);
#endif
          while (fgets(msgname, sizeof(msgname), hlo))
          {
            if (strchr(msgname, '\n'))
              *strchr(msgname, '\n')='\0';
            if (cmpaddr(msgname, "*.pkt"))
            { /* file attach - move to tempdir */
              debug(4, "findpkt: found attach %s", msgname);
              if (*msgname=='^')
                moveatt(msgname+1, msgKFS);
              else if (*msgname=='#')
                moveatt(msgname+1, msgTFS);
              else
                moveatt(msgname, 0);
              continue;
            }
            if ((msgname[0]=='#') || (msgname[0]=='^'))
              strcpy(msgname, msgname+1);
            if (msgname[0]==0)
              continue;
            if (access(msgname, 0))
            { logwrite('!', "Can't find file %s!\n", msgname);
              continue;
            }
            debug(4, "FindPkt: found %s", msgname);
            one_pkt(msgname);
          }
          fclose(hlo);
          if (unlink(loname))
            logwrite('!', "Can't unlink %s: %s!\n", loname, strerror(errno));
        }
        if (i<strlen(flavours))
          goto boxes; /* busy */
        strcpy(msgname, loname);
        strcpy(msgname+strlen(msgname)-2, "ut");
        for (i=0; i<strlen(flavoursut); i++)
        { if (killed) break;
          msgname[strlen(msgname)-3]=flavoursut[i];
          debug(20, "FindPkt: checking %s", msgname);
          if (access(msgname, 2)) continue;
          if (hbsy==-1)
          { hbsy=open(bsyname, O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
            if (hbsy==-1)
            { logwrite('!', "Can't create %s, mail for %u:%u/%u.%u skipped\n",
                       bsyname, fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point);
              break;
            }
#ifdef __OS2__
            DosSetFHState(hbsy, OPEN_FLAGS_NOINHERIT);
#endif
            debug(8, "FindPkt: %s created", bsyname);
          }
          debug(4, "FindPkt: found %s", msgname);
          one_pkt(msgname);
        }
        if (hbsy!=-1)
        { close(hbsy);
          if (DelBinkSem((ftnaddr *)&fpktaddr, binkout, myaka[0].zone))
            logwrite('!', "Can't unlink %s: %s!\n", bsyname, strerror(errno));
          else
            debug(8, "FindPkt: %s deleted", bsyname);
        }
        if (killed) break;
      }
boxes:

#ifndef __MSDOS__
      if (lbso[0])
      {
        bsyname=GetLBSOBsyName((ftnaddr *)&fpktaddr, fpktaddr.ftndomain, lbso);
        hbsy=-1;
        for (i=0; i<sizeof(lbsoflavours)/sizeof(lbsoflavours[0]); i++)
        { char *p;
          strcpy(loname, bsyname);
          p=strrchr(loname, '.');
          if (p==NULL) continue;
          strcpy(p+1, lbsoflavours[i]);
          strcat(loname, ".List");
          debug(20, "FindPkt: checking %s", loname);
          if (access(loname, 2)) continue;
          debug(4, "FindPkt: found %s", loname);
          if (hbsy==-1)
          { hbsy=open(bsyname, O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
            if (hbsy==-1)
            { logwrite('!', "Can't create %s, mail for %u:%u/%u.%u skipped\n",
                       bsyname, fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point);
              break;
            }
#ifdef __OS2__
            DosSetFHState(hbsy, OPEN_FLAGS_NOINHERIT);
#endif
            debug(8, "FindPkt: %s created", bsyname);
          }
          hlo=fopen(loname, "r");
          if (hlo==NULL)
          { logwrite('!', "Can't open %s: %s!\n", loname, strerror(errno));
            continue;
          }
#ifdef __OS2__
          DosSetFHState(fileno(hlo), OPEN_FLAGS_NOINHERIT);
#endif
          while (fgets(msgname, sizeof(msgname), hlo))
          {
            if (*msgname=='~') continue;
            if (strchr(msgname, '\n'))
              *strchr(msgname, '\n')='\0';
            if (cmpaddr(msgname, "*.pkt"))
            { /* file attach - move to tempdir */
              debug(4, "findpkt: found attach %s", msgname);
              if (*msgname=='^')
                moveatt(msgname+1, msgKFS);
              else if (*msgname=='#')
                moveatt(msgname+1, msgTFS);
              else
                moveatt(msgname, 0);
              continue;
            }
            if ((msgname[0]=='#') || (msgname[0]=='^'))
              strcpy(msgname, msgname+1);
            if (msgname[0]==0)
              continue;
            if (access(msgname, 0))
            { logwrite('!', "Can't find file %s!\n", msgname);
              continue;
            }
            debug(4, "FindPkt: found %s", msgname);
            one_pkt(msgname);
          }
          fclose(hlo);
          if (unlink(loname))
            logwrite('!', "Can't unlink %s: %s!\n", loname, strerror(errno));
        }
        if (i<sizeof(lbsoflavours)/sizeof(lbsoflavours[0]))
          goto lboxes; /* busy */
        for (i=0; i<sizeof(lbsoflavoursut)/sizeof(lbsoflavoursut[0]); i++)
        { char *p;
          if (killed) break;
          strcpy(msgname, bsyname);
          p=strrchr(msgname, '.');
          if (p==NULL) continue;
          strcpy(p+1, lbsoflavoursut[i]);
          strcat(msgname, ".Mail");
          debug(20, "FindPkt: checking %s", msgname);
          if (access(msgname, 2)) continue;
          if (hbsy==-1)
          { hbsy=open(bsyname, O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
            if (hbsy==-1)
            { logwrite('!', "Can't create %s, mail for %u:%u/%u.%u skipped\n",
                       bsyname, fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point);
              break;
            }
#ifdef __OS2__
            DosSetFHState(hbsy, OPEN_FLAGS_NOINHERIT);
#endif
            debug(8, "FindPkt: %s created", bsyname);
          }
          debug(4, "FindPkt: found %s", msgname);
          one_pkt(msgname);
        }
        if (hbsy!=-1)
        { close(hbsy);
          if (DelLBSOSem((ftnaddr *)&fpktaddr, fpktaddr.ftndomain, lbso))
            logwrite('!', "Can't unlink %s: %s!\n", bsyname, strerror(errno));
          else
            debug(8, "FindPkt: %s deleted", bsyname);
        }
        if (killed) break;
      }
lboxes:
      if (tlboxes[0])
      { sprintf(loname, "%s%hu.%hu.%hu.%hu", tlboxes,
                fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point);
        checkbox(loname);
        if (killed) break;
        strcat(loname, ".h");
        checkbox(loname);
        if (killed) break;
      }
      if (longboxes[0])
      { char *flavours[]={ "immediate", "crash", "direct", "normal", "hold" };
        int j;
        for (j=0; j<sizeof(flavours)/sizeof(flavours[0]); j++)
        { sprintf(loname, "%s%s.%hu.%hu.%hu.%hu.%s", longboxes, fpktaddr.ftndomain,
                  fpktaddr.zone, fpktaddr.net, fpktaddr.node, fpktaddr.point,
                  flavours[j]);
          checkbox(loname);
          if (killed) break;
        }
        if (killed) break;
      }
#endif
      if (tboxes[0])
      { sprintf(loname, "%s%c%c%c%c%c%c%c%c.%c%c", tboxes,
                dhex(fpktaddr.zone/32),  dhex(fpktaddr.zone%32),
                dhex(fpktaddr.net/1024), dhex((fpktaddr.net/32)%32), dhex(fpktaddr.net%32),
                dhex(fpktaddr.node/1024), dhex((fpktaddr.node/32)%32), dhex(fpktaddr.node%32),
                dhex(fpktaddr.point/32), dhex(fpktaddr.point%32));
        checkbox(loname);
        if (killed) break;
        strcat(loname, "h");
        checkbox(loname);
        if (killed) break;
      }
    }
  }
  if (pktin[0])
  { strcpy(loname, pktin);
    removeslash(loname);
    d=opendir(loname);
    if (d==NULL)
    { logwrite('!', "Can't open directory %s: %s!\n", loname, strerror(errno));
      return;
    }
    while ((df=readdir(d))!=NULL)
    { if (cmpaddr(df->d_name, "*.pkt"))
        continue;
      strcpy(msgname, pktin);
      strcat(msgname, df->d_name);
      debug(4, "FindPkt: found %s", msgname);
      one_pkt(msgname);
      if (killed) break;
    }
    closedir(d);
  }
  debug(1, "FindPkt: found nothing");
}


static int nextpktaka(int *curaka)
{ /* get next gate aka or next /for= */
  /* 0 in success */
  int i;
  uword zone, net, node, point;
  char *ftndomain;

  for (;;)
  { curaka[0]++;
    if (curaka[0]==naka+ngates)
      return 1;
    if (curaka[0]>=naka)
    { if (gates[curaka[0]-naka].pktfor.zone==0)
        continue;
      zone=gates[curaka[0]-naka].pktfor.zone;
      net=gates[curaka[0]-naka].pktfor.net;
      node=gates[curaka[0]-naka].pktfor.node;
      point=gates[curaka[0]-naka].pktfor.point;
      ftndomain=gates[curaka[0]-naka].pktfor.ftndomain;
      if (ftndomain[0]=='\0')
      { for (i=0; i<naka; i++)
          if (myaka[i].zone==zone)
            break;
        if (i==naka && zone>0 && zone<7)
          for (i=0; i<naka; i++)
            if (myaka[i].zone>0 && myaka[i].zone<7)
              break;
        if (i==naka) i=0;
        strcpy(gates[curaka[0]-naka].pktfor.ftndomain, myaka[i].ftndomain);
      }
    }
    else
    { zone=myaka[curaka[0]].zone;
      net=myaka[curaka[0]].net;
      node=myaka[curaka[0]].node;
      point=myaka[curaka[0]].point;
      ftndomain=myaka[curaka[0]].ftndomain;
    }
    for (i=0; (i<curaka[0]) && (i<naka); i++)
      if ((zone==myaka[i].zone) &&
          (net==myaka[i].net) &&
          (node==myaka[i].node) &&
          (point==myaka[i].point) &&
          (stricmp(ftndomain, myaka[i].ftndomain)==0))
        break;
    if ((i<naka) && (i<curaka[0]))
      continue;
    if (curaka[0]<naka)
      return 0;
    for (i=0; i<curaka[0]-naka; i++)
      if ((zone==gates[i].pktfor.zone) &&
          (net==gates[i].pktfor.net) &&
          (node==gates[i].pktfor.node) &&
          (point==gates[i].pktfor.point) &&
          (stricmp(ftndomain, gates[i].pktfor.ftndomain)==0))
        break;
    if (i==curaka[0]-naka)
      return 0;
  }
}

void putaddr(char *str, uword zone, uword net, uword node, uword point)
{
  if (point) sprintf(str, "%u:%u/%u.%u", zone, net, node, point);
  else sprintf(str, "%u:%u/%u", zone, net, node);
}

int checkaddr(char *addr)
{ /* 0 - not address,
     1 - reject,
     2 - free,
     3 - normal
  */
  int i;

  debug(11, "CheckAddr(%s)", addr);
  if (strchr(addr, '@')==0)
    return 0;
  /* should not match any rej */
  for (i=0; i<nrej; i++)
    if (cmpaddr(addr, rej[i])==0)
      break;
  if (i!=nrej)
    return 1;
  for (i=0; i<nfree; i++)
    if (cmpaddr(addr, sfree[i])==0)
      break;
  if (i!=nfree)
    return 2;
  for (i=0; i<nsend; i++)
    if (cmpaddr(addr, send_to[i])==0)
      break;
  if (i==nsend)
    return 1;
  return 3;
}

#if defined(__OS2__)
void rexx_extchk(void *param)
{ char *p;
  char *cmdline=param;
  RXSTRING arg;
  RXSTRING rexxretval;
  short rexxrc=0;
  int   rc;

  debug(8, "Rexx_ExtChk(%s)", cmdline);
  p=strpbrk(cmdline, " \t");
  if (p)
    *p++='\0';
  else
    p=cmdline+strlen(cmdline);
  rexxretval.strlength=0;
  MAKERXSTRING(arg, p, strlen(p));
  p=getenv("COMSPEC");
  if (p==NULL) p="cmd.exe";
  rc=RexxStart(1, &arg, cmdline, 0, p, RXSUBROUTINE, 0, &rexxrc, &rexxretval);
  close(fileno(stdout));
  if (rc)
  { logwrite('?', "Can't run external checker!\n");
    rexxrc=3;
  }
  debug(8, "Rexx_ExtChk: return %d", rexxrc);
  *(int *)cmdline=rexxrc;
  _endthread();
}
#endif

#ifdef DO_PERL
#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *perl;
static int do_perl=1;
extern char perlfile[];
static char *perlargs[]={"", perlfile, NULL};
extern char *memtxt;
extern long imemtxt;
void boot_DynaLoader(CV *cv);
void xs_init(void)
{
#ifndef __OS2__
  dXSUB_SYS;
#endif
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, "callperl");
}

static void exitperl(void)
{
  if (perl)
  { perl_destruct(perl);
    perl_free(perl);
    perl=NULL;
  }
}
#endif

int extcheck(char *addr, int *area)
{ /* 0 - not address,
     1 - reject,
     2 - free,
     3 - normal
  */
  int  i;
  char *p, *p1;
  static char tmpaddr[80], conflist[1024];
  int  newarea;
  static char extstr[256];
#if defined(__OS2__)
  TID tid;
  int saveout;
  int hpipe[2];
#ifdef DO_PERL
  int h;
#endif
#elif defined(UNIX)
  pid_t pid;
  int h;
#endif
#ifdef DO_PERL
  SV *svfrom, *svto, *svsize, *svarea, *svbody, *svattr, *svsubj;
  SV *svintsetname, *svextsetname;
  STRLEN n_a;
#endif
  FILE *f;
  static char cmdline[CMDLINELEN+128];

  /* external check */
  for (i=0; i<nchecker; i++)
  { if (stricmp(checker[i].mask, "any")==0) break;
    if ((*area!=-1) && (stricmp(checker[i].mask, "echo")==0)) break;
    if ((*area==-1) && (cmpaddr(addr, checker[i].mask)==0)) break;
  }
  if ((i==nchecker) || (checker[i].cmdline[0]=='\0'))
    return 3;
  debug(4, "ExtChk: addr=%s, area=%s",
        addr, (*area==-1)?"NetMail":echoes[*area].usenet);
#ifdef DO_PERL
  if (perlfile[0]=='\0')
    goto ext_noperl;
  if (!do_perl)
    return 3;
  if (perl==NULL)
  { int saveerr, perlpipe[2];
    if (access(perlfile, R_OK))
    { logwrite('!', "Can't read %s: %s, perl filtering disabled\n",
               perlfile, strerror(errno));
      do_perl=0;
      return 3;
    }
    perl = perl_alloc();
    perl_construct(perl);
#ifdef HAVE_FORK
    pipe(perlpipe);
chk_fork:
    if ((pid=fork())>0)
    {
      saveerr=dup(fileno(stderr));
      dup2(perlpipe[1], fileno(stderr));
      close(perlpipe[0]);
      close(perlpipe[1]);
      h=perl_parse(perl, xs_init, 2, perlargs, NULL);
      dup2(saveerr, fileno(stderr));
      close(saveerr);
      waitpid(pid, perlpipe, 0);
    }
    else if (pid==0)
    { FILE *f;
      close(perlpipe[1]);
      f=fdopen(perlpipe[0], "r");
      while (fgets(conflist, sizeof(conflist), f))
        logwrite('!', conflist);
      fclose(f);
      exit(0);
    }
    else
    { if (errno==EINTR)
        goto chk_fork;
      logwrite('!', "extchk: can't fork(): %s!\n", strerror(errno));
      return 3;
    }
#else /* not HAVE_FORK */
    saveerr=dup(fileno(stderr));
    perlpipe[0]=open("/dev/null", O_WRONLY);
    if (perlpipe[0]!=-1)
    { dup2(perlpipe[0], fileno(stderr));
      close(perlpipe[0]);
    }
    h=perl_parse(perl, xs_init, 2, perlargs, NULL);
    dup2(saveerr, fileno(stderr));
    close(saveerr);
#endif
    if (h)
    { logwrite('!', "Can't parse %s, perl filtering disabled\n", perlfile);
      exitperl();
      do_perl=0;
      return 3;
    }
    atexit(exitperl);
  }
  { dSP;
    svfrom=perl_get_sv("from", TRUE);
    svto  =perl_get_sv("to"  , TRUE);
    svsize=perl_get_sv("size", TRUE);
    svarea=perl_get_sv("area", TRUE);
    svbody=perl_get_sv("body", TRUE);
    svattr=perl_get_sv("attr", TRUE);
    svsubj=perl_get_sv("subject", TRUE);
    svintsetname=perl_get_sv("intsetname", TRUE);
    svextsetname=perl_get_sv("extsetname", TRUE);
    p=strchr(from, ' ');
    if (p==NULL) p=from+strlen(from);
    memcpy(tmpaddr, from, sizeof(tmpaddr));
    tmpaddr[(unsigned)p-(unsigned)from]='\0';
    sv_setpv(svfrom, tmpaddr);
    sv_setpv(svto,   addr);
    sv_setiv(svsize, txtsize);
    sv_setpv(svarea, (*area==-1) ? "NetMail" : echoes[*area].usenet);
    sv_setpvn(svbody, memtxt, (int)imemtxt);
    sv_setiv(svattr, msghdr.attr);
    memcpy(tmpaddr, msghdr.subj, sizeof(msghdr.subj));
    tmpaddr[sizeof(msghdr.subj)-1]='\0';
    sv_setpv(svsubj, tmpaddr);
    sv_setpv(svintsetname, myintsetname);
    sv_setpv(svextsetname, myextsetname);
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(checker[i].cmdline, G_EVAL|G_SCALAR);
    SPAGAIN;
    i=POPi;
    PUTBACK;
    FREETMPS;
    LEAVE;
    strncpy(extstr, SvPV(perl_get_sv("to", FALSE), n_a), sizeof(extstr));
    strncpy(tmpaddr, SvPV(perl_get_sv("from", FALSE), n_a), sizeof(tmpaddr));
    strncpy(conflist, SvPV(perl_get_sv("area", FALSE), n_a), sizeof(conflist));
    myextsetname=SvPV(perl_get_sv("extsetname", FALSE), n_a);
    if (SvTRUE(ERRSV))
    {
      logwrite('!', "Perl filter eval error: %s\n", SvPV(ERRSV, n_a));
#if 0
      exitperl();
      do_perl=0;
#endif
      return 3;
    }
  }
  goto ext_res;
ext_noperl:
#endif  /* DO_PERL */

  /* form command line */
  strcpy(cmdline, checker[i].cmdline);
  p=strchr(from, ' ');
  if (p==NULL) p=from+strlen(from);
  memcpy(tmpaddr, from, sizeof(tmpaddr));
  tmpaddr[(unsigned)p-(unsigned)from]='\0';
  chsubstr(cmdline, "%from", tmpaddr);
  chsubstr(cmdline, "%to", addr);
  sprintf(tmpaddr, "%lu", txtsize);
  chsubstr(cmdline, "%size", tmpaddr);
  if (*area==-1)
    chsubstr(cmdline, "%area", "NetMail");
  else
    chsubstr(cmdline, "%area", echoes[*area].usenet);
  debug(4, "ExtChk: cmdline '%s'", cmdline);
  conflist[0]='\0';
#if defined(__MSDOS__)
  strcat(cmdline, " >");
  p=cmdline+strlen(cmdline);
  mktempname(TMPOUT, p);
  i=swap_system(cmdline);
#elif defined(__OS2__)
  if (pipe(hpipe))
  { logwrite('?', "Can't create pipe for external checker!\n");
    return 3;
  }
  DosSetFHState(hpipe[0], OPEN_FLAGS_NOINHERIT);
  saveout=dup(fileno(stdout));
  dup2(hpipe[1], fileno(stdout));
  close(hpipe[1]);
  i=3;
  f=fdopen(hpipe[0], "r");
  if (f==NULL)
  { logwrite('?', "Can't fdopen pipe!\n");
    close(hpipe[0]);
  }
  else
  {
    tid=_beginthread(rexx_extchk, NULL, STACK_SIZE, cmdline);
    fgets(extstr, sizeof(extstr), f);
    if (fgets(tmpaddr, sizeof(tmpaddr), f)==NULL)
      tmpaddr[0]='\0';
    else
      fgets(conflist, sizeof(conflist), f);
    while (fgetc(f)!=EOF);
    fclose(f);
    DosWaitThread(&tid, DCWW_WAIT);
    i=*(int *)cmdline;
  }
  dup2(saveout, fileno(stdout));
  close(saveout);
#else
  pid=pipe_system(NULL, &h, cmdline);
  f=fdopen(h, "r");
  fgets(extstr, sizeof(extstr), f);
  if (fgets(tmpaddr, sizeof(tmpaddr), f)==NULL)
    tmpaddr[0]='\0';
  else
    fgets(conflist, sizeof(conflist), f);
  while (fgetc(f)!=EOF);
  fclose(f);
  waitpid(pid, &i, 0);
  i = ((i << 8 ) | (i >> 8)) & 0xffff;
#endif
#ifdef DO_PERL
ext_res:
#endif
  debug(4, "ExtChk: external checker returns %d", i);
  if ((i>255) || (i<0))
  { logwrite('?', "Can't execute external checker!\n");
    i=1;
  }
  else if (i>5)
  { logwrite('?', "External checker unknown retcode %d!\n", i);
    i=1;
  }
  else
    debug(1, "External checker retcode %d\n", i);
  switch (i)
  { case 3: i=2;
            break;
    case 4: i=0;
            break;
    case 0:
    case 2: 
#if defined(__MSDOS__)
            f=fopen(p, "r");
            if (f==NULL)
            { logwrite('?', "Can't read checker's stdout!\n");
              i=3;
              break;
            }
            else
            { fgets(extstr,   sizeof(extstr),   f);
              fgets(tmpaddr,  sizeof(tmpaddr),  f);
              fgets(conflist, sizeof(conflist), f);
              fclose(f);
            }
#endif
            p1=strchr(extstr, '\n');
            if (p1) *p1='\0';
            if (stricmp(addr, extstr))
              debug(4, "ExtChk: change to-addr to %s", extstr);
            strcpy(addr, extstr);
            p1=strchr(tmpaddr, '\n');
            if (p1) *p1='\0';
            if (tmpaddr[0])
            { if (stricmp(from, tmpaddr))
                debug(4, "ExtChk: change from-addr to %s", extstr);
              strcpy(from, tmpaddr);
            }
            p1=strchr(conflist, '\n');
            if (p1) *p1='\0';
            if (conflist[0])
            { if (stricmp((*area==-1) ? "NetMail" : echoes[*area].usenet, conflist))
                debug(4, "ExtChk: change area to %s", extstr);
              if (stricmp(conflist, "netmail"))
                newarea=-1;
              else
              { for (newarea=0; newarea<nechoes; newarea++)
                  if (strcmp(echoes[newarea].usenet, conflist)==0)
                    break;
                if (newarea==nechoes)
                { logwrite('?', "External checker returns unknown conference name %s\n", conflist);
                  conflist[0]='\0';
                }
                else
                  newarea=i;
              }
              if ((newarea==-1) && (*area!=-1))
              { logwrite('?', "Can't change echomail message to netmail area by external checker");
                conflist[0]='\0';
              }
              else if ((newarea!=-1) && (*area==-1))
              { logwrite('?', "Can't change netmail message to echomail area by external checker");
                conflist[0]='\0';
              }
              if (conflist[0])
                *area=newarea;
            }
            if (i!=2)
              i=3;
            break;
    case 5: 
            if (*area==-1)
            { i=1;
              break;
            }
            logwrite('?', "External checker incorrect retcode %d for echomail!\n", i);
            i=3;
            break;
    default:i=3;
            break;
  }
#ifdef __MSDOS__
  unlink(p);
#endif
  return i;
}

void chsubstr(char *str, char *from, char *to)
{
  char *p;
  int  i, j;

  p=str;
  if (strlen(str)+strlen(to)-strlen(from) >= CMDLINELEN)
    return;
  while ((p=strstr(p, from))!=NULL)
  {
    strcpy(p, p+strlen(from));
    j=strlen(to);
    for (i=strlen(p); i>=0; i--)
      p[i+j]=p[i];
    strncpy(p, to, j);
#ifdef __MSDOS__
    for(; j>0; j--, p++)
    { if (*p=='>') *p='}';
      else if (*p=='<') *p='{';
    }
#else
    p+=j;
#endif
  }
}

int mktempname(char *sample, char *dest)
{
  int  i, k, l1, l2, l3;
  long l;
  char *p;

  strcpy(dest, tmpdir);
  strcat(dest, sample);
  p=strchr(dest, '?');
  if (p==NULL)
  { debug(6, "mktempname(%s): %s", sample, dest);
    return !access(dest, 0);
  }
  for (i=0, l=10; p[++i]=='?'; l*=10)
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
    { debug(6, "mktempname(%s): %s", sample, dest);
      return 0;
    }
    l1=(l1+1)%(int)l;
    if (l1==l2)
    { debug(1, "mktempname(%s): failed", sample, dest);
      return 1;
    }
  }
}

static char *struct_fields[]=
            { "Cc:",
              "Bcc:",
              "Content-Type:",
              "Content-Transfer-Encoding:",
              "Content-Disposition:",
              "Content-Length:",
              "Mime-Version:",
              "Received:",
              "Precedence:",
              "Lines:",
              "Resent-From:",
              "Resent-To:",
              "Resent-Date:",
              "Resent-Message-Id:",
              "Apparently-To:",
              "To:",
              "From:",
              "Message-Id:",
              "Date:",
              "References:",
              "NNTP-Posting-Host:",
              "Approved:",
              "Return-Receipt-To:",
              "Sender:",
              "Errors-To:",
              "Newsgroups:"
            };

static int qpchar(char c)
{
  if (c>128) return 1;
  if (c<=32) return 1;
  if (isspace(c) || ispunct(c)) return 1;
  if (strchr("()<>@,;:\"/[]?.=\\_" /*"_=?!\"#$@[\\]^`{|}~()<>"*/ , c)) return 1;
  return 0;
}

static char *foldhdr(char *str)
{
  char *sdest, *p;
  int len=strlen(str);

  if (len<=90) return str;
  sdest=malloc(len+len/60+2);
  if (sdest==NULL) return str;
  for (p=sdest, len=0; *str; len++)
  { if (len>70 && (*str==' ' || *str=='\t'))
    { *p++='\n';
      len=8;
      *p++='\t';
      str++;
    }
    else
      *p++=*str++;
  }
  *p='\0';
  return sdest;
}

char *qphdr(char *str)
{ char *s, *p, *pl, *pldest, *sdest;
  int  llen, lword, lenword=0, i, structured;
  char c;

  if (hdr8bit) return foldhdr(str);
  debug(5, "QPhdr('%s')", str);
  lword=7; /* bit */
  for (p=str; *p; p++)
    if ((*p=='\n') & p[1])
      *p=' ';
    else if (*p>=128)
      lword=8;
  if (lword==7)
  { debug(8, "QPhdr: no 8bit");
    return foldhdr(str);
  }
  s=strdup(str);
  if (s==NULL)
  { debug(1, "QPhdr: can't strdup");
    return str;
  }
  lword=7;
  sdest=malloc(strlen(str)*3+128);
  if (sdest==NULL)
  { free(s);
    debug(1, "QPhdr: can't malloc");
    return str;
  }
  structured=0;
  for (i=0; i<sizeof(struct_fields)/sizeof(struct_fields[0]); i++)
    if (strnicmp(str, struct_fields[i], strlen(struct_fields[i]))==0)
      structured=1;
  pl=s, pldest=sdest;
  llen=0;
  for (;;)
  { int wasrbr=0;

    if (structured)
    { if (*pl=='(')
      { if (lword==8)
        { strcpy(pldest, "?= ");
          pldest+=2;
          lword=7;
        }
        *pldest++=*pl++;
      }
      else if (*pl==')')
      { if (lword==8)
        { strcpy(pldest, "?=");
          lword=7;
        }
        *pldest++=*pl++;
        wasrbr=1;
      }
    }
    for (p=pl; isspace(*p); p++);
    for (;*p && !isspace(*p) && ((!structured) || ((*p!='(') && (*p!=')'))); p++)
      if (*p>=128) break;
    if (*p<128)
    { /* 7 bit */
      if (lword==8)
      { strcpy(pldest, "?=");
        pldest+=2;
        llen+=2;
      }
      c=*p;
      *p='\0';
      strcpy(pldest, pl);
      pldest+=strlen(pl);
      pl+=strlen(pl);
      llen+=strlen(pl);
      *p=c;
      if (*p=='\0')
      { free(s);
        return sdest;
      }
      lword=7;
      if (llen>MAXUNFOLD)
      { strcpy(pldest, "\n\t");
        pldest+=2;
        pl++; /* skip space */
        llen=1;
      }
      continue;
    }
    /* 8bit */
    if (lword==7)
    { if (structured && wasrbr && (!isspace(*pl)))
        *pldest++=' ';
      else
        while(isspace(*pl))
          *pldest++=*pl++;
      sprintf(pldest, "=?%s?Q?", myextsetname);
      lenword=strlen(pldest);
      pldest+=lenword;
    }
    else
    { while (isspace(*pl))
      { if (lenword+3+2>=75)
        { strcpy(pldest, "?=");
          llen+=2;
          pldest+=2;
          if (llen>=MAXUNFOLD)
          { strcpy(pldest, "\n\t");
            pldest+=2;
            llen=1;
          }
          else
          { *pldest++=' ';
            llen++;
          }
          sprintf(pldest, "=?%s?Q?", myextsetname);
          lenword=strlen(pldest);
          pldest+=lenword;
        }
        sprintf(pldest, "=%02X", *pl++);
        pldest+=3;
        llen+=3;
        lenword+=3;
      }
    }
    for (; *pl && !isspace(*pl); pl++)
    { 
      if (lenword+3+2>=75)
      { strcpy(pldest, "?=");
        llen+=2;
        pldest+=2;
        if (llen>=MAXUNFOLD)
        { strcpy(pldest, "\n\t");
          pldest+=2;
          llen=1;
        }
        else
        { *pldest++=' ';
          llen++;
        }
        sprintf(pldest, "=?%s?Q?", myextsetname);
        lenword=strlen(pldest);
        pldest+=lenword;
      }
      if (!qpchar(*pl))
      { *pldest++=*pl;
        llen++;
        lenword++;
        continue;
      }
      sprintf(pldest, "=%02X", *pl);
      pldest+=3;
      llen+=3;
      lenword+=3;
    }
    lword=8;
    if ((*pl=='\0') || (*pl=='\n'))
    { free(s);
      strcpy(pldest, "?=");
      if (*pl=='\n')
        strcat(pldest, "\n");
      debug(7, "QPhdr: result '%s'", sdest);
      return sdest;
    }
    if (llen>MAXUNFOLD)
    { if (*pl=='\0')
      { free(s);
        strcpy(pldest, "?=");
        debug(7, "QPhdr: result '%s'", sdest);
        return sdest;
      }
      strcpy(pldest, "?=\n\t");
      pldest+=4;
      llen=1;
      lword=7;
    }
  }
}

void mkusername(char *str)
{ int i;

  if (str[0]=='\0') strcpy(str, " ");
  for (i=0; str[i]; i++)
  {
    if ((str[i]==' ') || (str[i]=='\t'))
    { str[i]='_';
      if (curgate!=ngates)
      if (gates[curgate].yes==2)
        str[i]='.';
    }
    if ((str[i]=='(') || (str[i]=='<'))
      str[i]='{';
    if ((str[i]==')') || (str[i]=='>'))
      str[i]='}';
    if ((str[i]==':') || (str[i]==',') ||
        (str[i]==';'))
      str[i]='.';
    if (str[i]=='@')
      str[i]='%';
    if (str[i]>=250)
      str[i]='_';
  }
  int2ext(str);
}

void dateftn2rfc(char *ftndate, char *rfcdate, int tz)
{ int year, mon, day, hour, min, sec;
  int i;
  long l;
  char smon[20], sday[20];
  time_t curtime;
  struct tm *curtm;
/*
    01234567890123456789
    01 Jan 86  02:34:56\  FTSC-1  Fido Standard
    Mon  1 Jan 86 02:34\  FTSC-1  Seadog
    Mon  9 Jan 95  8:19\          SeaDog?
    01 Jan 86 02:34:56\           Buggy Qmail
    01 JAN 86  02:34:56\          WildUUCP
    1 Jan 86  02:34:56\           Unknown
    hh:mm:ss\                     D'bridge for some unkown
    01 Jan 80 02:34\
    12/31/80 02:34:11\
    12/31/1980 02:34:11\  - gate cannot parse this, but it will be good if yes.. ;)
    01234567890123456789
*/
  curtime=time(NULL);
  curtm=localtime(&curtime);
  i=sscanf(ftndate, "%u %s %u %u:%u:%u",
      &day, smon, &year, &hour, &min, &sec);
  if (i<6)
  { i=sscanf(ftndate, "%s %u %s %u %u:%u",
             sday, &day, smon, &year, &hour, &min);
    sec=0;
  }
  if (i<6)
    i=sscanf(ftndate, "%u %s %u %u:%u", &day, smon, &year, &hour, &min)+1;
  if (i<6)
  { i=sscanf(ftndate, "%u/%u/%u %u:%u:%u", &mon, &day, &year, &hour, &min, &sec);
    if (i<6)
      mon=12;
  }
  else
  { for (mon=0; mon<12; mon++)
      if (stricmp(montable[mon], smon)==0)
        break;
  }
  if (year<50)
    year+=2000;
  else if (year<150)
    year+=1900;
  if (mon==12)
  {
resetdate:
    year=curtm->tm_year+1900;
    mon=curtm->tm_mon;
    day=curtm->tm_mday;
    hour=curtm->tm_hour;
    min=curtm->tm_min;
    sec=curtm->tm_sec;
  }
  if (area!=-1)
  { /* future date ? */
    if (year>curtm->tm_year+1900) goto resetdate;
    if (year==curtm->tm_year+1900)
    { if (mon>curtm->tm_mon) goto resetdate;
      if (mon==curtm->tm_mon)
      { if (day>curtm->tm_mday) goto resetdate;
        if (day==curtm->tm_mday)
        { if (hour>curtm->tm_hour) goto resetdate;
          if (hour==curtm->tm_hour)
          { if (min>curtm->tm_min) goto resetdate;
            if (min==curtm->tm_min)
              if (sec>curtm->tm_sec) goto resetdate;
          }
        }
      }
    }
    /* too old date? */
    l=(curtm->tm_year+1900-year)*365;
    if (mon>curtm->tm_mon) l-=365;
    for(i=mon; i!=curtm->tm_mon; i=(i+1)%12)
      l+=daymon[i];
    l+=(curtm->tm_mday-day);
    if ((curtm->tm_hour<hour) ||
        ((curtm->tm_hour==hour) && (curtm->tm_min<min)) ||
        ((curtm->tm_hour==hour) && (curtm->tm_min==min) && (curtm->tm_sec<sec)))
      l--;
    if (l>MAXAGE)
      goto resetdate;
  }

  sprintf(rfcdate, "%s, %2u %s %04u %02u:%02u:%02u %c%02u00",
          weekday[dayweek(year-1900, mon, day)], day, montable[mon], year,
          hour, min, sec,
          (tz<=0) ? '+' : '-', (tz>0) ? tz : -tz);
  debug(8, "DateFTN2RFC: '%s', result='%s'", ftndate, rfcdate);
}

static char *hfields_arr[]=
            { "Cc:",
              "Bcc:",
              "Content-Type:",
              "Content-Transfer-Encoding:",
              "Content-Disposition:",
              "Content-Description:",
              "Content-Length:",
              "Mime-Version:",
              "Received:",
              "Precedence:",
              "Lines:",
              "Resent-From:",
              "Resent-To:",
              "Resent-Date:",
              "Resent-Organization:",
              "Resent-Message-Id:",
              "Resent-X-Mailer:",
              "Apparently-To:",
              "To:",
              "From:",
              "Reply-To:",
              "Organization:",
              "Message-Id:",
              "Date:",
              "References:",
              "Subject:",
              "X-Realname:",
              "NNTP-Posting-Host:",
              "X-Phone:",
              "X-Flames-To:",
              "Approved:",
              "Return-Receipt-To:",
              "Comment-To:",
              "Comment:",
              "Sender:",
              "Errors-To:",
              "Summary:",
              "Keywords:",
              "Newsgroups:",
              "X-Class:",
              "X-Comment-To:",
              "X-To:",
              "X-Mailer:",
              "X-Mailreader:",
              "X-Newsreader:"
            };

int adduserline(char *str)
{ int i, j;

  debug(7, "AddUserLine: %s", str);
  for (i=0; i<sizeof(hfields_arr)/sizeof(hfields_arr[0]); i++)
    if (strnicmp(str, hfields_arr[i], strlen(hfields_arr[i]))==0)
    {
      if ((area!=-1) && (strnicmp(str, "Newsgroups:", 11)==0))
        return 2;
      if (strnicmp(str, "Cc:", 3)==0 &&
          (strchr(str, '@')==NULL || strchr(str, ':')))
        return 0;
      if (area!=-1)
        if (group[echoes[area].group].type==G_FEED)
          if (strnicmp(str, "Organization:", 13)==0)
            return 2;
      for(j=0; j<cheader; j++)
        if (strnicmp(pheader[j], hfields_arr[i], strlen(hfields_arr[i]))==0)
          pheader[j][0]=0;
      chkkludges;
      if (strnicmp(str, "Content-", 8)==0)
        if (!isfield("Mime-Version:"))
        { sprintf(pheader[cheader], "Mime-Version: 1.0\n");
          nextline;
        }
      sprintf(pheader[cheader], "%s", str);
      nextline;
      return 1;
    }
  return 0;
lbadmsg: /* used from chkkludges */
  return 3;
}

void getaddr(char *str)
{
  char *p, *p1;
  int  i;

  /* remove spaces */
  debug(6, "GetAddr('%s')", str);
  for(p=str; *p && isspace(*p); p++);
  if (p!=str) strcpy(str, p);
  if (*p=='\0') return;
  for(p=str+strlen(str)-1; isspace(*p); *p--='\0');

  /* skip comments */
  for(p=str; *p; p++)
  { if (*p=='(')
    { p1=p;
      for (i=0;;)
      { p1=strpbrk(p1+1, "()");
        if (p1==NULL)
          break;
        if (*p1=='(')
        { i++;
          continue;
        }
        if (i==0)
          break;
        i--;
      }
      if (p1)
        strcpy(p, p1+1);
      if (*p==0)
        break;
    }
  }
  debug(20, "GetAddr: after skip comments result is '%s'", str);

  if ((p=strchr(str, '<'))!=NULL)
    if ((p1=strchr(p, '>'))!=NULL)
    { strncpy(str, p+1, (int)(p1-p)-1);
      str[(int)(p1-p)-1]='\0';
    }
  while (isspace(*str)) strcpy(str, str+1);
  if (*str)
    for (p=str+strlen(str)-1; isspace(*p); *(p--)='\0');
  debug(6, "GetAddr: address '%s'", str);
}
