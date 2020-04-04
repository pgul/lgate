/*
 * $Id$
 *
 * $Log$
 * Revision 2.19  2011/08/28 21:04:22  gul
 * Minor bugs fixed
 *
 * Revision 2.18  2006/01/29 11:53:45  gul
 * *** empty log message ***
 *
 * Revision 2.17  2004/07/20 18:38:06  gul
 * \r\n -> \n
 *
 * Revision 2.16  2004/07/07 08:24:32  gul
 * Improved logging
 *
 * Revision 2.15  2004/03/27 12:21:47  gul
 * Get only realname from X-Comment-To:
 *
 * Revision 2.14  2002/11/17 21:00:26  gul
 * Do not put TID to generated .msg
 *
 * Revision 2.13  2002/11/17 20:55:26  gul
 * New option "tid" in gate.cfg
 *
 * Revision 2.12  2002/11/17 20:23:18  gul
 * Remove obsolete code
 *
 * Revision 2.11  2002/03/21 11:19:16  gul
 * Added support of msgid style <newsgroup|123@domain>
 *
 * Revision 2.10  2002/01/07 09:57:24  gul
 * Added init_textline() for hrewind()
 *
 * Revision 2.9  2001/08/16 14:20:39  gul
 * coredumped if malformed X-FTN-MSGID
 *
 * Revision 2.8  2001/04/20 16:23:21  gul
 * minor bugfix
 *
 * Revision 2.7  2001/04/20 06:07:25  gul
 * minor bugfix
 *
 * Revision 2.6  2001/04/19 10:10:44  gul
 * sometimes coredump on large messages with long lines
 *
 * Revision 2.5  2001/01/28 03:56:41  gul
 * fixed compilation error
 *
 * Revision 2.4  2001/01/28 03:51:10  gul
 * convert msgid to FTN-form for reply-linking even if there is another address
 * (correct return address always is in the origin).
 *
 * Revision 2.3  2001/01/27 21:58:48  gul
 * translate comments
 *
 * Revision 2.2  2001/01/26 17:49:04  gul
 * bugfix: truncate message if size=0
 *
 * Revision 2.1  2001/01/24 01:59:18  gul
 * Bugfix: sometimes put msg into pktin dir with 'pkt' extension
 *
 * Revision 2.0  2001/01/10 20:42:25  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include "gate.h"

#ifdef __OS2__
#define INCL_DOSFILEMGR
#include <os2.h>
#endif

#define chkheader(str) if (chkhdrsize(str)) goto errlet;
#define nline pheader[cheader+1]=(char *)((char _Huge *)pheader[cheader]+hstrlen(pheader[cheader])+1); cheader++;

char namec[FNAME_MAX], named[FNAME_MAX], namex[FNAME_MAX];
char newechoflag[FNAME_MAX];
char str[MAXSTR];
char addr[MAXADDR];
char msgname[FNAME_MAX];
char domainid[MAXADDR];
uword zone, net, node, point;
FILE *fout;
int  f;
unsigned ibuf;
char *buffer;
int  naka;
unsigned long attr;
unsigned long msgid;
char *header;
char fromaddr[MAXADDR];
char **pheader;
int  cheader;
int  wasfrom, wasmsgid;
unsigned long attrib;
uword lastzone;
int  npath, nseenby;
nodetype path[MAX_PATH];
struct strseenby seenby[MAXSEENBY];
int null, nonews;
char origin[MAXORIGIN+3], xorigin[120], tearline[120];
char fmsgid[SSIZE];
int  retcode;
char xftnfrom[120];
ftnaddr xftnaddr;
#ifdef DO_PERL
extern char *newintsetname;
#endif

static char orig_from[MAXADDR];
static int extchg;
static externtype extret;
static int  r;
static char *p, *p1, isftnaddr;
static uword hiszone, hisnet, hisnode, hispoint;
static char s[MAXSTR];
static char realname[SSIZE];
static int  waslet;
static uword i, j, k, n, pp;
static unsigned parts, part;
static long l;
static long partsize, spart;
static int  errl;
static int  cont;
static int  area, polynews;
static int  nxc;
static int  xc[MAXXC];
static char *bufpart;
static unsigned long ibufpart;
static int  clmn;
static char fromstr[MAXADDR], replyaddr[MAXADDR];
static char lastorigin[120];
static char s1[MAXADDR], s2[SSIZE];

static void freebufpart(void)
{ if (bufpart)
    freebuf(bufpart);
  bufpart=NULL;
}

int main(int argc, char *argv[])
{
  retcode=0;
  /* allocate buffers */
  buffer=farmalloc(BUFSIZE);
  if (buffer==NULL)
  { puts("Not enough memory!");
    return RET_ERR;
  }
  bufsrc=farmalloc(BUFSIZE);
  if (bufsrc==NULL)
  { puts("Not enough memory!");
    return RET_ERR;
  }
  curhdrsize=MAXHEADER;
  header=farmalloc(curhdrsize);
  if (header==NULL)
  { puts("Not enough memory!");
    return RET_ERR;
  }
  curnpheader=MAXNHEADER;
  pheader=(char **)farmalloc(curnpheader*sizeof(pheader[0]));
  if (pheader==NULL)
  { puts("Not enough memory!");
    return RET_ERR;
  }
  strcpy(copyright, NAZVA);
  strcat(copyright, " (Rel2Fido)");
  if (params(argc, argv))
    return RET_ERR;
  if (fake)
    return saveargs(argc, argv);
  debug(0, "Rel2Fido Started");
#ifdef __OS2__
  for (i=0; i<FOPEN_MAX; i++)
    close(i+3);
#endif
  if ((r=config())!=0)
    return retcode|RET_ERR;
  if (tossbad)
  { /* append badmail (if exists) to mailbox */
    copybad();
  }
#ifndef UNIX
  if ((uupcver==615) && bypipe && (!cnews))
    retcode=48;
#endif
  waslet=0;
  conf=0;
  funix=1;
  f=-1;
  fout=NULL;
  bufpart=NULL;
  debug(1, "Main: call GetLetter");
  getletter();
  freebufpart();
  closeout();
#ifndef __MSDOS__
  if (bypipe)
    while (fgets(str, sizeof(str), stdin)); /* to avoid SIGPIPE */
#endif
  if (waslet && rescan[0])
    touch(rescan);
  debug(0, "Exiting, retcode %d", retcode);
  return retcode;
} /* main */

int one_message(void)
{ char *newsgr;
  char badaddr;
  time_t curtime;
  struct tm *curtm;
  /* fsize ready, message is in file f or in msgbuf */

/* convert to msg */
  /* fill default msg header */
  debug(6, "One_Message started, Conf=%d, Addr=%s", conf, addr[0] ? addr : "NULL");
  fix=errl=nonews=curhops=0;
  origin[0]=tearline[0]=xorigin[0]=0;
  strcpy(msghdr.from, "uucp");
  msghdr.subj[0]=0;
  curtime=time(NULL);
  curtm=localtime(&curtime);
  sprintf(msghdr.date, "%02u %s %02u  %02u:%02u:%02u",
          curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year%100,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
  attrib=attr;
  if (conf)
  { strcpy(msghdr.to, "All");
    zone=uplink[0].zone;
    node=uplink[0].node;
    net=uplink[0].net;
    point=uplink[0].point;
  }
  hiszone=myaka[curaka].zone;
  hisnet=myaka[curaka].net;
  hisnode=myaka[curaka].node;
  hispoint=myaka[curaka].point;
  fmsgid[0]=0;
  pheader[0]=header;
  pheader[1]=NULL;
  cheader=0;
  npath=nseenby=0;
  notfile=0;
  null=wasfrom=wasmsgid=waschaddr=0;
  area=-1;
  lastzone=0;
  isftnaddr=0;
  xftnfrom[0]=0;
  xftnaddr.zone=-1;
  msgtz=0;

  /* read header */
  if (readhdr())
    goto errlet;
  if (xftnfrom[0]==0)
    xftnaddr.zone=-1;
  /*
  else if (xftnaddr.zone==-1)
    xftnfrom[0]=0;
  */
  if (strcmp(str, "\r"))
  { logwrite('?', "Bad message header");
    goto errlet;
  }

  freebufpart();
  if ((fsize>maxpart*1024l) && (maxpart>0))
    l=maxpart*1024l+RESPART;
  else
    l=fsize+RESPART;
#ifdef __MSDOS__
  { long freemem=getfreemem();
    debug(6, "One_Message: farcoreleft()=%ld", freemem);
    if (l>freemem-1024)
      if (freemem-RESPART-1024>MINPARTSIZE)
      { maxpart=(unsigned)((freemem-RESPART-0x400)/1024);
        l=maxpart*1024l+RESPART;
        logwrite('!', "Not enough memory for specified size, set size=%d\n",
                 maxpart);
      }
  }
#endif
  debug(10, "One_Message: allocating %ld bytes for buffer", l);
  bufpart=createbuf(l);
  if (bufpart==NULL)
  { logwrite('?', "Not enough memory!\n");
    retcode|=RET_ERR;
    return RET_ERR;
  }
  /* external check */
  for (k=0; k<cheader; k++)
    if (strnicmp(pheader[k], "\x01RFC-From:", 10)==0)
      break;
  if (k<cheader)
  {
    p=strchr(pheader[k], '\r');
    if (p) *p='\0';
    strncpy(fromstr, pheader[k]+10, sizeof(fromstr));
    fromstr[sizeof(fromstr)-1]=0;
    parseaddr(pheader[k]+10, fromaddr, realname, -1);
    if (p) *p='\r';
    strcpy(orig_from, fromaddr);
  }
  else
    fromaddr[0]=fromstr[0]=orig_from[0]='\0';

  replyaddr[0]='\0';
  for (k=0; k<cheader; k++)
    if (strnicmp(pheader[k], "\x01RFC-Reply-To:", 14)==0)
      break;
  if (k<cheader)
  { p=strchr(pheader[k], '\r');
    if (p) *p='\0';
    parseaddr(pheader[k]+14, replyaddr, str, -1);
    if (p) *p='\r';
  }

  if (orig_from[0])
    if ((strnicmp(orig_from, "uucp", 4)==0) ||
        (strnicmp(orig_from, "MAILER-DAEMON", 13)==0) ||
        (strstr(orig_from, "MAILER-DAEMON")))
    { debug(5, "One_Message: message from robot ('%s'), set RRC", orig_from);
      attrib|=msgRETREC; /* from robot - set RRC */
    }

#ifdef DO_PERL
  for (i=0; i<cheader; i++)
    if (strnicmp(pheader[i], "Subject:", 8)==0)
      break;
  newintsetname=intsetname;
#endif
  newsgr=newsgroups;
  p1=NULL;
  if (newsgr==NULL)
    newsgr="NetMail";
  debug(9, "One_Message: NewsGr='%s'", newsgr);
  extret=extcheck(addr, fromaddr, &newsgr
#ifdef DO_PERL
                  , (i<cheader) ? pheader[i]+8 : NULL
#endif
                  );
  if (stricmp(newsgr, "netmail")==0)
    newsgr=NULL;
  extchg=0;
  if (extret==EXT_DEFOUT)
  { extchg=1;
    extret=EXT_DEFAULT;
  }
  if (extret==EXT_FREEOUT)
  { extchg=1;
    extret=EXT_FREE;
  }
  if (extret==EXT_HOLDOUT)
  { extchg=1;
    extret=EXT_HOLD;
  }
  if (extchg && (fromaddr[0]))
    strcpy(fromstr, fromaddr);
  parseaddr(fromstr, fromaddr, realname, -1);
  if (extchg || (replyaddr[0]=='\0'))
    strcpy(replyaddr, fromaddr);
  strcpy(orig_from, fromaddr);
  if (extret==EXT_DEVNULL)
  {
    if (attname[0]) 
    { unlink(attname);
      attname[0]='\0';
    }
    logwrite('!', "Message from %s to %s killed by external checker!\n",
             fromaddr, conf ? newsgroups : addr);
    if (!bypipe)
      goto todevnull;
    freebufpart();
    return 0;
  }
  if (extret==EXT_REJECT)
  { strcpy(fromaddr, orig_from);
    logwrite('!', "Message from %s to %s rejected by external checker!\n", fromaddr, addr);
    reject(EXTERNAL);
    if (attname[0]) 
    { unlink(attname);
      attname[0]='\0';
    }
    goto wasreject;
  }
  badaddr=0;
  if (!conf)
    if (transaddr(msghdr.to, &zone, &net, &node, &point, addr))
    { strcpy(fromaddr, orig_from);
      badaddr=1;
      /* reject after itwit checking */
    }

  if (wasfrom)
  { parseaddr(fromstr, fromaddr, realname, 1); /* chaddr */
    /* check if this is fido address */
    if (transaddr(realname, &hiszone, &hisnet, &hisnode, &hispoint, fromaddr)==0)
    { /* fido address */
      xftnfrom[0]=0;
      xftnaddr.zone=-1;
      isftnaddr=1;
      debug(6, "One_Message: %s is fido address %s %d:%d/%d.%d",
            fromaddr, realname, hiszone, hisnet, hisnode, hispoint);
      if (lastzone==0)
        lastzone=hiszone;
      strcpy(fromaddr, realname);
      realname[0]=0;
    }
  }
  else
  { fromaddr[0]=0;
#if 0
    if (cheader==1)
    { /* only via gate, header is empty */
      freebufpart();
      logwrite('?', "Empty message header!\n");
      retcode|=RET_ERR;
      return RET_ERR;
    }
#endif
  }
  j=zone;
  if (xftnfrom[0] && (xftnaddr.zone!=(uword)-1))
  { /* do we have aka in his zone? */
    for (i=0; i<naka; i++)
    { if (xftnaddr.zone==myaka[i].zone)
        break;
      if ((myaka[i].zone<7) && (xftnaddr.zone<7))
        break;
    }
    if (i==naka)
    { xftnfrom[0]=0;
      xftnaddr.zone=-1;
      debug(7, "One_Message: I don't have aka in zone %d", hiszone);
    }
    else
    { j=hiszone=xftnaddr.zone;
      hisnet=xftnaddr.net;
      hisnode=xftnaddr.node;
      hispoint=xftnaddr.point;
      strcpy(fromaddr, xftnfrom);
      wasfrom=isftnaddr=1;
      realname[0]=0;
    }
  }
    
  /* aka match */
  if (conf==0)
  { curaka=akamatch(j, net, node);
    debug(7, "One_Message: using aka %d:%d/%d.%d",
          myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node, myaka[curaka].point);
    if (!isftnaddr)
    { hiszone=myaka[curaka].zone;
      hisnet=myaka[curaka].net;
      hisnode=myaka[curaka].node;
      hispoint=myaka[curaka].point;
    }
  }
  if (!isftnaddr)
  {
    if (wasfrom)
    { char *p, *p1;

      if (strlen(fromaddr)<sizeof(msghdr.from))
        strcpy(msghdr.from, fromaddr);
      chkheader(replyaddr);
      p=strchr(replyaddr, ',');
      if (p) *p='\0';
      sprintf(pheader[cheader], "\x01REPLYADDR %s\r", replyaddr);
      nline;
      while (p)
      {
        *p++=',';
        while (isspace(*p))
          p++;
        p1=strchr(p, ',');
        if (p1) *p1='\0';
        sprintf(pheader[cheader], "\x01REPLYALSO %s\r", p);
        nline;
        p=p1;
      }
      chkheader(pheader[cheader-1]);
      sprintf(pheader[cheader], "\x01REPLYTO %u:%u/%u",
              myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node);
      if (myaka[curaka].point)
        sprintf(pheader[cheader]+strlen(pheader[cheader]), ".%u",
                myaka[curaka].point);
      if (replyform==REPLY_UUCP)
        strcat(pheader[cheader], " uucp\r");
      else if (replyform==REPLY_ADDR)
        sprintf(pheader[cheader]+strlen(pheader[cheader]), " %s\r", msghdr.from);
      else /* empty */
        strcat(pheader[cheader], "\r");
      nline;
      pheader[cheader]+=8; /* for future changes */
      if (!forgolded)
      {
        if (strlen(fromaddr)>=sizeof(msghdr.from))
        { chkheader(fromaddr);
          sprintf(pheader[cheader], "From: %s\r", fromaddr);
          nline;
        }
        else
          strcpy(msghdr.from, fromaddr);
        if (realname[0])
        { chkheader(realname);
          sprintf(pheader[cheader], "RealName: %s\r", realname);
          nline;
        }
        for (k=0; k<cheader; k++)
          if (strnicmp(pheader[cheader], "\x01RFC-From:", 10)==0)
            pheader[k][0]=0;
      }
    }
    if (envelope_from[0])
    { chkheader(envelope_from);
      sprintf(pheader[cheader], "\x01RFC-Sender: %s\r", envelope_from);
    }
  }
  else
  { strncpy(msghdr.from, fromaddr, sizeof(msghdr.from));
    msghdr.from[sizeof(msghdr.from)-1]='\0';
  }

  msghdr.dest_node=node;
  msghdr.dest_net=net;
  msghdr.dest_zone=zone;
  msghdr.dest_point=point;

  if ((!isftnaddr) || (gatevia==2))
  { /* Put own via */
    debug(6, "One_Message: put my via");
    putvia(s);
    chkheader(s);
    strcpy(pheader[cheader], s);
    p=pheader[cheader];
    nline;
    /* move this via to begin */
    for (i=0; i<cheader; i++)
      if (strncmp(pheader[i], "\x01Via:", 5)==0) break;
    for (r=cheader-2; r>=(int)i; r--)
      pheader[r+1]=pheader[r];
    pheader[i]=p;
  }
  if (isftnaddr && !gatevia)
  { /* remove all "Via:" - was "Received:" */
    debug(8, "OneMessage: deleting all Received");
    for (i=0; i<cheader; i++)
      if (strncmp(pheader[i], "\x01Via:", 5)==0)
        pheader[i][0]=0;
  }
  else
    for (i=0; i<cheader; i++)
    { if (strnicmp(pheader[i], "\x01Via:", 5)==0)
      { debug(15, "One_Message: convert 'Via:' to 'Received:'");
        /* leave only "by" section and date */
        /* parse domain, if fidonet and (...) - to begin */
        j=strlen(pheader[i]);
        p=rcvfrom(pheader[i]);
        rcvconv(pheader[i]);
        if (p)
        { chkheader(p);
          if (j>strlen(p)+strlen(pheader[i]))
          { strcpy(pheader[i]+strlen(pheader[i])+1, p);
            p=pheader[i]+strlen(pheader[i])+1;
            pheader[cheader+1]=pheader[cheader];
          }
          else
          { if (chkhdrsize(p)) continue;
            strcpy(pheader[cheader], p);
            p=pheader[cheader];
            pheader[cheader+1]=pheader[cheader]+strlen(pheader[cheader])+1;
          }
          for (j=cheader-1; j>i; j--)
            pheader[j+1]=pheader[j];
          pheader[i+1]=p;
          cheader++;
        }
        /* if prev "recd from" is the same as cur "via" - remove */
        { int  j, r;
          char c, c1;
          for (j=i-1; j>=0; j--)
          { if (strncmp(pheader[j], "\x01Recd:from", 10)==0)
              break;
          }
          if (j>=0)
          { p=strpbrk(pheader[j]+11, "; ");
            if (p==NULL) continue;
            c=*p;
            *p='\0';
            p=strpbrk(pheader[i]+5, "; ");
            if (p==NULL)
            { pheader[j][strlen(pheader[j])]=c;
              continue;
            }
            c1=*p;
            *p='\0';
            p=strchr(pheader[j], '@');
            if (p) p++;
            else p=pheader[j]+11;
            r=stricmp(p, pheader[i]+5);
            if (r)
              r=strncmp(p, pheader[i]+5, strlen(p));
            pheader[i][strlen(pheader[i])]=c1;
            if (r)
              pheader[j][strlen(pheader[j])]=c;
            else
              pheader[j][0]='\0';
          }
        }
        continue;
      }
    }

  debug(6, "One_Message: checking send, nosend, twit, notwit, itwitto, maxhops");
  if (extret!=EXT_FREE)
  {
    for (k=0; k<nitwit; k++)
      if (wildcmp(orig_from, itwit+k)==0)
      {
        if (!conf)
        {
          strcpy(fromaddr, orig_from);
          logwrite('!', "%s is twit, message to %u:%u/%u.%u rejected!\n",
                   fromaddr, zone, net, node, point);
          reject(ITWIT);
          goto wasreject;
        }
        else
        {
          logwrite('-', "Message to %s from %s size %lu dropped: itwit\n", newsgroups ? newsgroups : "<>", orig_from, fsize);
          null=1;
        }
      }
    if (tofield[0] && !conf)
      for (k=0; k<nitwitto; k++)
        if (wildcmp(tofield, itwitto+k)==0)
        {
          strcpy(fromaddr, orig_from);
          logwrite('!', "%s is twit-to, message from %s to %u:%u/%u.%u rejected!\n",
                   tofield, fromaddr, zone, net, node, point);
          reject(ITWITTO);
          goto wasreject;
        }
    if (envelope_from[0] && !conf)
      for (k=0; k<nitwitfrom; k++)
        if (wildcmp(envelope_from, itwitfrom+k)==0)
        {
          strcpy(fromaddr, orig_from);
          logwrite('!', "%s is twit-from, message from %s to %u:%u/%u.%u rejected!\n",
                   envelope_from, fromaddr, zone, net, node, point);
          reject(ITWITFROM);
          goto wasreject;
        }
    if (nottext && keepatt==ATT_REJECT && !conf)
    { strcpy(fromaddr, orig_from);
      logwrite('!', "Fileattach denied, message from %s to %u:%u/%u.%u rejected!\n",
               fromaddr, zone, net, node, point);
      reject(REJ_ATTACH);
      goto wasreject;
    }
    if (!conf)
      for (k=0; k<nitwitvia; k++)
      { int i;
        char *p, *p1;
        for (i=0; i<cheader; i++)
        { if (strncmp(pheader[i], "\x01Via:", 5) &&
              strncmp(pheader[i], "\x01Recd:from ", 11)) continue;
          if (pheader[i][4]==':') p=pheader[i]+5; /* via */
          else p=pheader[i]+11; /* recd */
          p1=strchr(p, shortvia ? ' ' : ';');
          if (p1==NULL) continue;
          *p1='\0';
          if (wildcmp(p, itwitvia+k)==0)
          { strcpy(fromaddr, orig_from);
            logwrite('!', "%s is twit-via, message from %s to %u:%u/%u.%u rejected!\n",
                     p, fromaddr, zone, net, node, point);
            *p1=shortvia ? ' ' : ';';
            reject(ITWITVIA);
            goto wasreject;
          }
          *p1=shortvia ? ' ' : ';';
        }
      }
    if (badaddr)
    { strcpy(fromaddr, orig_from);
      logwrite('!', "Address %s is invalid, message rejected!\n", addr);
      reject(BADADDR);
      goto wasreject;
    }
  }
  if (maxhops && (curhops>maxhops) && !conf)
  { 
    strcpy(fromaddr, orig_from);
    logwrite('!', "Too many hops: %d (%d max) from %s to %u:%u/%u.%u!\n",
             curhops, maxhops, fromaddr, zone, net, node, point);
    reject(MANYHOPS);
wasreject:
    if (attname[0]) 
    { unlink(attname);
      attname[0]='\0';
    }
    freebufpart();
    return 0; /* go to next message */
  }
  debug(6, "One_Message: checked OK");
  msghdr.orig_node=hisnode;
  msghdr.orig_net=hisnet;
  if (!wasfrom)
  { strcpy(fromaddr, "uucp");
    strcpy(msghdr.from, fromaddr);
    debug(5, "One_Message: unknown from address, set from to uucp");
  }
  /* first letters to uupercase */
  for (p=msghdr.to-1; p++; p=strpbrk(p, " \t."))
  { if ((*p>='a') && (*p<='z'))
      *p&=~0x20;
  }
  if (strcmp(msghdr.from, "uucp")==0)
  { attrib &= ~msgRETRECREQ; /* unknown from addr */
#ifndef UNIX
    if (uupcver==615)
      retcode &= ~48;
#endif
  }
  if (area!=-1 && newsgr && strchr(newsgr, ',') == NULL)
  { /* if message-id started with "newsgroup|" - remove */
    for (i=0; i<cheader; i++)
      if (strncmp(pheader[i], "\x01RFCID:", 7) == 0)
      { if (strlen(pheader[i])>strlen(newsgr)+2)
        { if (strcmp(pheader[i]+7, newsgr)==0 &&
              pheader[i][strlen(newsgr)+7]=='|')
          { strcpy(pheader[i]+7, pheader[i]+7+strlen(newsgr)+1);
            if (strlen(domainid)>strlen(newsgr)+1)
            { p=domainid+(domainmsgid==2 ? 1 : 0);
              if (strcmp(p, newsgr)==0 && p[strlen(newsgr)]=='|')
                strcpy(p, p+strlen(newsgr)+1);
            }
          }
        }
        break;
      }
  }
  debug(8, "One_Message: generate message-id");
  if ((!wasmsgid) || (msgid==0))
    msgid=(curtime<<8)+(getpid()&0xff)+seqf++;
  if ((wasmsgid & 2)==0)
  { /* no X-FTN-MSGID */
    if (fmsgid[0])
    { if (getfidoaddr(&i, &j, &k, &n, fmsgid)==0)
      { /* put original msgid, addr is at origin
        if (i!=hiszone || j!=hisnet || k!=hisnode || n!=hispoint)
          fmsgid[0]=0;
        else
        */
        { p=strchr(fmsgid, ' ');
          if (p)
          { l=strtoul(p+1, &p1, 16);
            if (l) msgid=l;
            else fmsgid[0]=0;
          }
          else fmsgid[0]=0;
        }
      }
      else fmsgid[0]=0;
    }
    if (fmsgid[0]==0)
      i=hiszone, j=hisnet, k=hisnode, n=hispoint;
    if (fmsgid[0] || (!domainmsgid) || (domainid[0]==0) || (waschaddr))
    { if (hispoint)
        sprintf(str, "%u:%u/%u.%u", i, j, k, n);
      else
        sprintf(str, "%u:%u/%u", i, j, k);
    }
    else
      /* not FTN and user ask to put domain */
      strcpy(str, quotemsgid(domainid));
    chkheader(str);
    sprintf(pheader[cheader], "\x01MSGID: %s %08lx\r", str, msgid);
    nline;
    if (conf && (!isftnaddr))
      pheader[cheader]+=8; /* reserved for addr change */
  }
  else
    fmsgid[0]=0;
  chkheader("");
  sprintf(pheader[cheader], "\x01INTL %u:%u/%u %u:%u/%u\r",
          zone, net, node, hiszone, hisnet, hisnode);
  if (point)
  { sprintf(s, "\x01TOPT %u\r", point);
    chkheader(s);
    strcat(pheader[cheader], s);
  }
  if (hispoint)
  { sprintf(s, "\x01""FMPT %u\r", hispoint);
    chkheader(s);
    strcat(pheader[cheader], s);
  }
  if (attrib>0xFFFFl)
  { strcat(pheader[cheader], "\x01""FLAGS");
    if (attrib & msgDIRECT)
      strcat(pheader[cheader], " DIR");
    if (attrib & msgCFM)
      strcat(pheader[cheader], " CFM");
    /* and others... ;-) */
    strcat(pheader[cheader], "\r");
  }
  nline;
  p=pheader[cheader-1];
  for (i=cheader-1; i>0; i--)
    pheader[i]=pheader[i-1];
  pheader[0]=p;
  if (putchrs)
  {
    struct ftnchrs_type *fp;
    char *canonintsetname;
#ifdef DO_PERL
    canonintsetname=canoncharset(newintsetname);
#else
    canonintsetname=canoncharset(intsetname);
#endif
    for (fp=ftnchrs; fp; fp=fp->next)
    { char *rfc=fp->rfcchrs;
      rfc=canoncharset(rfc);
      if (stricmp(rfc, canonintsetname)==0)
      { chkheader(fp->ftnchrs);
        sprintf(pheader[cheader], "\x01""CHRS: %s 2\r", fp->ftnchrs);
        nline;
        break;
      }
    }
  }
  if (msgtz)
  { for(i=0; i<cheader; i++)
      if (strnicmp(pheader[i], "\x01TZUTC", 6)==0)
        break;
    if (i==cheader)
    { chkheader("");
      sprintf(pheader[cheader], "\x01TZUTC: %s%02d00\r",
              msgtz<0 ? "-" : "", msgtz<0 ? -msgtz : msgtz);
      nline;
    }
  }
  if (!notid && (conf || packmail))
  { for(i=0; i<cheader; i++)
      if (strnicmp(pheader[i], "\x01TID:", 5)==0)
        break;
    if (i==cheader)
    { chkheader(NAZVA);
      sprintf(pheader[cheader], "\x01TID: %s\r", NAZVA);
      nline;
    }
  }

  if (conf==0)
    null=0;
  if (null)
  { /* skip message */
todevnull:
    freebufpart();
    debug(5, "One_Message: moving message to /dev/null");
    debug(6, "One_Message: return %d", 0);
    return 0;
  }

  /* if too large netmail - hold file with rfc-style message */
  if ((((fsize>=holdsize*1024l) && (holdsize) && (!isftnaddr) &&
       (extret!=EXT_FREE)) || (extret==EXT_HOLD)) && (!conf))
  { /* not for uplink */
    for (i=0; i<nuplinks; i++)
      if ((zone==uplink[i].zone) &&
          (net==uplink[i].net) &&
          (node==uplink[i].node) &&
          (point==uplink[i].point))
        break;
    if (i==nuplinks)
    { if (!holdhuge && extret!=EXT_HOLD)
      { logwrite('!', "Message from %s to %u:%u/%u.%u too large (%ld bytes), rejected!\n",
                 fromaddr, zone, net, node, point, fsize);
        reject(REJ_HUGE);
        goto wasreject;
      }
      /* set subj */
      for (i=0; i<cheader; i++)
        if (strnicmp(pheader[i], "Subject:", 8)==0)
          break;
      debug(3, "One_Message: message too large (%ld bytes), hold it", fsize);
      if (i<cheader)
        i=holdmsg(realname, fromaddr, pheader[i]+8);
      else
        i=holdmsg(realname, fromaddr, NULL);
      if (i)
      { retcode|=RET_ERR;
        debug(6, "One_Message: return %d", retcode);
        freebufpart();
        return retcode;
      }
      waslet=1;
      if (!bypipe)
        retcode|=RET_NETMAIL;
      debug(6, "One_Message: return %d", 0);
      freebufpart();
      return 0;
    }
  }
  if (attname[0])
  { /* hold fileattach */
    /* set subj */
    debug(3, "One_Message: file attach %s received - hold it", attname);
    for (i=0; i<cheader; i++)
      if (strnicmp(pheader[i], "Subject:", 8)==0)
        break;
    if (i<cheader)
      i=holdatt(realname, fromaddr, pheader[i]+8);
    else
      i=holdatt(realname, fromaddr, NULL);
    if (i)
    { retcode|=RET_ERR;
      debug(6, "One_Message: return %d", retcode);
      freebufpart();
      return retcode;
    }
    waslet=1;
    if (!bypipe)
      retcode|=RET_NETMAIL;
    debug(6, "One_Message: return %d", 0);
    freebufpart();
    return 0;
  }

  /* count number of parts */
  if (maxpart>0)
  { partsize=1024l*maxpart-sizeof(msghdr)-
             ((char _Huge *)(pheader[cheader])-(char _Huge *)header)-
             strlen(origin)-60/*tech info*/-75/*^aSPLIT kludge*/;
    if (partsize<1024)
      partsize=1024;
  }
  else
    partsize=fsize+1;
  parts=(int)(fsize/partsize)+1;
  debug(8, "maxpart=%ldk, sizeof(msghdr)=%d, hdrsize=%u, strlen(origin)=%d\n",
        maxpart, sizeof(msghdr),
        (char _Huge *)(pheader[cheader])-(char _Huge *)header,
        strlen(origin));
  debug(8, "partsize=%ld, fsize=%ld, parts=%d", partsize, fsize, parts);
  debug(6, "One_Message: parts=%d", parts);
  if ((parts>1) && ((!isftnaddr) || (area!=-1)))
  {
    /* make SPLIT kludge */
    chkheader("");
    sprintf(s, "%u/%u", hisnet, hisnode);
    sprintf(pheader[cheader], "\x01SPLIT %2u %s %02u %02u:%02u:%02u @%-12s %-5u %s/%02u +++++++++\r",
            curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year%100,
            curtm->tm_hour, curtm->tm_min, curtm->tm_sec, s,
            (uword)msgid, (parts>99) ? "001" : "01", parts);
    nline;
  }

  /* check/set header fields: subj, newsgroups, reply-to */
  area=-1;
  polynews=0;
  for (i=1; i<cheader; i++)
  { if (strncmp(pheader[i], "Subject: ", 9)==0)
    { 
      debug(15, "One_Message: create subject");
      if ((parts>1) && ((!isftnaddr) || (area!=-1)))
        sprintf(msghdr.subj, "(1/%u) ", parts);
      else
        msghdr.subj[0]=0;
      r=strlen(msghdr.subj);
      strncpy(msghdr.subj+r, pheader[i]+9, sizeof(msghdr.subj)-r-1);
      msghdr.subj[sizeof(msghdr.subj)-1]=0;
      if (strlen(pheader[i]+9)+r<=sizeof(msghdr.subj))
      { p=strchr(msghdr.subj, '\r');
        if (p) *p=0;
        pheader[i][0]=0;
      }
      continue;
    }
    if ((strncmp(pheader[i], "To: ", 4)==0) && cnews)
    { if (isftnaddr)
      {
        debug(15, "One_Message: make 'To:' for cnews");
        p=strchr(pheader[i], '\r');
        if (p) *p=0;
        strncpy(msghdr.to, pheader[i]+4, sizeof(msghdr.to)-1);
        msghdr.to[sizeof(msghdr.to)-1]=0;
        if (strlen(pheader[i])<sizeof(msghdr.to))
          pheader[i][0]=0;
        else
          if (p) *p='\r';
      }
      continue;
    }
    if (((strnicmp(pheader[i], "\x01RFC-Comment-To: ", 17)==0) ||
#if 0 /* this line is not FTN "To:" */
         (strnicmp(pheader[i], "\x01RFC-X-To: ", 11)==0) ||
#endif
         (strnicmp(pheader[i], "\x01RFC-X-Comment-To: ", 19)==0)) && conf)
      if (strcmp(msghdr.to, "All")==0)
      {
        debug(15, "One_Message: make 'To:' from 'Comment-To:'");
        if ((p=strchr(pheader[i], '@'))!=NULL)
        { if ((sscanf(p+1, "f%hu.n%hu.z%hu", &j, &j, &j)==3) ||
              (sscanf(p+1, "p%hu.f%hu.n%hu.z%hu", &j, &j, &j, &j)==4))
          {
            *p=0;
            p=strchr(pheader[i], '_');
            if (p)
            { for (p=pheader[i]; *p; p++)
                if (*p=='_') *p=' ';
            }
            else
              for (p=pheader[i]; *p; p++)
                if (*p=='.') *p=' ';
          }
        }
        p=strchr(pheader[i], '\r');
        if (p) *p=0;
        for (p=strchr(pheader[i], ' '); isspace(*p); p++);
        parseaddr(p, s1, s2, -1);
        p = *s2 ? s2 : s1;
        strncpy(msghdr.to, p, sizeof(msghdr.to)-1);
        msghdr.to[sizeof(msghdr.to)-1]='\0';
        pheader[i][0]=0;
      }
    if (strnicmp(pheader[i], "\x01RFC-References:", 16)==0)
    {
      
    }
    debug(15, "One_Message: check next kludge");
  }
  if (newsgr)
  { p=newsgr;
    debug(15, "One_Message: make newsgroups list");
    while (*p)
    { p1=strpbrk(p, " \t,\r\n");
      if (p1==NULL) p1=p+strlen(p);
      r=*p1;
      *p1=0;
      for (j=0; j<nechoes; j++)
        if (strcmp(echoes[j].usenet, p)==0)
          if ((area==-1) || (echoes[j].noxc==0))
            break;
      *p1=(char)r;
      for (p=p1; isspace(*p) || (*p==','); p++);
      if (j==nechoes)
        continue;
      if (area==-1)
      { area=j;
        continue;
      }
      if (area==j) continue;
      polynews=1;
      break;
    }
    if ((!polynews) && (!errl) && (strchr(newsgr, ',')==NULL) &&
        (area!=-1) && (savehdr!=2))
    { for (i=0; i<cheader; i++)
        if (strnicmp(pheader[i], "\x01RFC-Newsgroups:", 16)==0)
          pheader[i][0]=0;
    }
    debug(15, "One_Message: area=%d, polynews=%d", area, polynews);
  }
  if ((area==-1) && conf)
  { if (newsgr)
      badpst("Unknown area");
    else
      badmess("No newsgroup specified");
    debug(6, "One_Message: return %d", 0);
    freebufpart();
    return 0;
  }
  if (area!=-1)
    if (nonews && echoes[area].checksubj)
    { badmess("No \"[News]\" at subject");
      debug(6, "One_Message: return %d", 0);
      freebufpart();
      return 0;
    }
  if (area!=-1)
    curaka=echoes[area].aka;
  else
    if (isftnaddr)
    { /* double gating, remove "To:" and "RFCID:" */
      debug(15, "One_Message: double gating, remove rfcid and to");
      for (i=0; i<cheader; i++)
      { if ((strnicmp(pheader[i], "To:", 3)==0) && (!waschaddr))
        { /* if "To:" contains '@', and hdr contains "uucp" - move */
          if (strchr(pheader[i], '@'))
          { if (stricmp(msghdr.to, "uucp")!=0)
              pheader[i][0]=0;
            /*
            else
              strcpy(pheader[i], pheader[i]+1);
            */
          }
          else
            pheader[i][0]=0;
        }
        if (strncmp(pheader[i], "\x01RFCID:", 7)==0)
          pheader[i][0]=0;
        if (strncmp(pheader[i], "RealName:", 10)==0)
          pheader[i][0]=0;
      }
    }
  if (isftnaddr)
  { /* remove REPLYADDR, REPLYTO, RFC-From and others */
    debug(7, "One_Message: double gating, remove REPLYADDR, REPLYTO, RFC-From etc.");
    for (i=0; i<cheader; i++)
      if (strncmp(pheader[i], "\x01REPLYADDR:", 11)==0)
        pheader[i][0]=0;
      else if (strncmp(pheader[i], "\x01REPLYTO:", 9)==0)
        pheader[i][0]=0;
      else if (strncmp(pheader[i], "\x01RFC-From:", 10)==0)
        pheader[i][0]=0;
      else if (strncmp(pheader[i], "RealName:", 10)==0)
        pheader[i][0]=0;
      else if (strncmp(pheader[i], "From:", 5)==0)
        pheader[i][0]=0;
  }

  if (area==-1)
  { /* if "To:" contains nothing interesting - remove it */
    for (i=0; i<cheader; i++)
      if (strnicmp(pheader[i], "To: ", 4)==0)
      { parseaddr(pheader[i]+4, s1, s2, 0);
        if (strpbrk(s1, " \t,")) continue;
        if (point)
        { sprintf(s2, "p%u.", point);
          p=s2+strlen(s2);
        }
        else p=s2;
        sprintf(p, "f%u.n%u.z%u.", node, net, zone);
        strlwr(s1);
        if (strstr(s1, s2))
        { pheader[i][0]=0;
          continue;
        }
        sprintf(s2, "%u/%u", net, node);
        if (point)
          sprintf(s2+strlen(s2), ".%u", point);
        if (strstr(s1, s2))
          pheader[i][0]=0;
      }
  }
  if (area!=-1)
  { /* add path to seen-by */
    debug(7, "One_Message: add Path to Seen-By");
    for (i=0; i<npath; i++)
      if (nseenby<MAXSEENBY)
      { for (k=0; k<nseenby; k++)
          if ((seenby[k].node==path[i].node) &&
              (seenby[k].net==path[i].net))
            break;
        if (k<nseenby)
          continue;
        seenby[k].net=path[i].net;
        seenby[k].node=path[i].node;
        nseenby++;
      }
    /* seen-by check */
    if (checksb)
    {
      debug(7, "One_Message: check seen-by");
      for (i=0; i<nseenby; i++)
      { for (j=0; j<nuplinks; j++)
          if ((seenby[i].net==uplink[j].net) &&
              (seenby[i].node==uplink[j].node) &&
              (lastzone==uplink[j].zone))
            break;
        if (j<nuplinks)
          break;
        /* don't check own aka - may be other station has the same aka
        for (j=0; j<naka; j++)
         if ((seenby[i].net==myaka[j].net) &&
             (seenby[i].node==myaka[j].node) &&
             (lastzone==myaka[j].zone) &&
             (myaka[j].point==0))
           break;
        if (j<naka)
          break;
        */
      }
      if (i<nseenby)
      { badpst("SEEN-BY check");
        debug(6, "One_Message: return %d", 0);
        freebufpart();
        return 0;
      }
    }
  }
  msghdr.attr=(uword)attrib;
  if (area!=-1)
  { /* remove intl, fmpt, topt, via */
    pheader[0][0]=0;
    msghdr.attr=0;
    for (i=0; i<cheader; i++)
    {
      if (strncmp(pheader[i], "\x01Via", 4)==0)
        pheader[i][0]=0;
      if (strncmp(pheader[i], "\x01Recd", 5)==0)
        pheader[i][0]=0;
    }
  }
  if (area==-1)
    polynews=0;
  /* remove all RFC-*, if netmail and chaddr */
  if (/*(area==-1) &&*/ (waschaddr))
    for (i=0; i<cheader; i++)
    { if (strnicmp(pheader[i], "\x01RFC-", 5)==0)
      { if (strnicmp(pheader[i], "\x01RFC-Newsgroups:", 16))
          pheader[i][0]=0;
      }
      else if (area==-1 && strnicmp(pheader[i], "\x01RFCID:", 7)==0)
        pheader[i][0]=0;
    }
  /* sort header fields */
  /* remove empty */
  /* MSGID - to start; */
  /* all unhidden to end */
  for (i=1; i<cheader; i++)
  { if (pheader[i][0]==0)
    { for (j=i; j<=cheader; j++)
        pheader[j]=pheader[j+1];
      i--;
      cheader--;
    }
  }
  /* pheader[0] is INTL & PID or empty */
  for (i=1; i<cheader; i++)
    if (strncmp(pheader[i], "\x01MSGID: ", 8)==0)
      break;
  if (i==cheader) i=1;
  p=pheader[i];
  for (; i>1; i--)
    pheader[i]=pheader[i-1];
  pheader[1]=p;
  for (i=cheader-2; i>1; i--)
  { if (pheader[i][0]==1) continue;
    /* move to the end */
    for (k=i+1; (k<cheader) && (pheader[k][0]==1); k++)
    { p=pheader[k];
      pheader[k]=pheader[k-1];
      pheader[k-1]=p;
    }
  }
  spart=fsize/parts-30 /* maxline/2 */;
  str[0]=0;
  /* seek to begin of msgbody */
  hrewind();
  while (textline(str, sizeof(str)));
  for (part=0; part<parts; part++)
  { /* put the part to buffer */
    debug(9, "One_Message: process part %d", part+1);
    if (part==1)
    { /* remove rfcid if exists */
      debug(9, "Remove RFCID");
      for (r=0; r<cheader; r++)
        if (strncmp(pheader[r], "\x01RFCID: ", 8)==0)
          pheader[r][0]='\0';
      /* remove all (?) unhide header fields */
      for (r=0; r<cheader; r++)
      { if (pheader[r][0]=='\x01')
          continue;
#if 0 /* Remove all (Resent-From, X-Real-Name etc.), not only Content-* */
        if (strnicmp(pheader[r], "\x01Content-", 9)==0)
#endif
          pheader[r][0]='\0';
      }
    }
    /* change part number */
    if ((parts>1) && ((!isftnaddr) || (area!=-1)))
    { sprintf(s, "(%u/%u)", part+1, parts);
      memcpy(msghdr.subj, s, strlen(s));
      /* change ^aSPLIT */
      for (r=1; r<cheader; r++)
        if (strncmp(pheader[r], "\x01SPLIT ", 7)==0)
          break;
      if (r<cheader)
      { sprintf(pheader[r]+46, (parts>99) ? "%03u" : "%02u", part+1);
        pheader[r][48]='/';
      }
    }
    ibufpart=0;
    cont=0;
    if (fsize || (part==0))
      empty=0;
    if (part==0)
    {
      if (!hgets())
      { if (fsize)
        { logwrite('?', "Incorrect packet renamed to *.bad!\n");
          goto errlet;
        }
      }
      else
        if (conf)
          if (strnicmp(str, "to:", 3)==0)
          { p=strchr(str, '\r');
            if (p) *p=0;
            for (p=str+3; (*p==' ') || (*p=='\t'); p++);
            strncpy(msghdr.to, p, sizeof(msghdr.to)-1);
            msghdr.to[sizeof(msghdr.to)-1]=0;
            if (strlen(p)<sizeof(msghdr.to))
            { if (!hgets())
              { if (fsize)
                { logwrite('?', "Incorrect packet, renamed to *.bad!\n");
                  goto errlet;
                }
              }
              else
                if (strcmp(str, "\r")==0)
                { if (!hgets())
                    if (fsize)
                    { logwrite('?', "Incorrect packet, renamed to *.bad!\n");
errlet:
                      errl=1;
                      break;
                    }
                }
            }
          }
    }
    lastorigin[0]=0;
    /* put body to buffer */
    for (;;)
    { if (strchr(str, '\r')==NULL)
      { if (str[0])
          cont=1;
      }
      else if (str[0]=='\r')
        empty=1;
      else
        empty=0;
      if (str[0])
        /* last empty line must be ignored for feed */
        if ((!conf) || cnews || fsize || strcmp(str, "\r"))
        { 
          if (lastorigin[0])
          { /* not last line - invalidate it */
            lastorigin[1]=''; /* '\x0f' */
            bufcopy(bufpart, ibufpart, lastorigin, strlen(lastorigin));
            ibufpart+=strlen(lastorigin);
            lastorigin[0]=0;
          }
          bufcopy(bufpart, ibufpart, str, strlen(str));
          ibufpart+=strlen(str);
        }
     skipline:
      if (fsize<0)
        break;
      if (!hgets())
      { if (fsize)
        { logwrite('?', "Incorrect packet, renamed to *.bad!\n");
          goto errlet;
        }
        break;
      }
      if (ibufpart+strlen(str)+sizeof(tearline)+sizeof(origin)+1>
          (maxpart ? 1024l*maxpart : partsize)+RESPART)
      { if (cont)
        { bufcopy(bufpart, ibufpart, "\r", 2);
          ibufpart++;
        }
        break;
      }
      if (cont) continue;
      if (area!=-1)
      {
/*
        if (strncmp(str, "---", 3)==0)
          str[0]=str[1]=str[2]='Ä';
*/
        if (strncmp(str, " * Origin:", 10)==0)
        { p=strrchr(str, '(');
          if (p)
          { while((!isdigit(*p)) && *p) p++;
            if (getfidoaddr(&j, &k, &n, &pp, p)==0)
            { strcpy(lastorigin, str);
              empty=0;
              debug(6, "One_Message: origin found");
              goto skipline;
            }
            else str[1]='';  /* '\x0f' */
          }
          else str[1]='';  /* '\x0f' */
        }
      }
      /* do we need go to next part? */
      if (part!=parts-1)
      { if ((long)ibufpart+strlen(str)+sizeof(msghdr)+
           (pheader[cheader]-header)>=1024l*maxpart)
          break;
        /* if size of the part more then apropriate - break too */
        if (ibufpart>=spart)
          break;
      }
    }
    if (errl)
      break;
    { char stmp[sizeof(tearline)+20];
      if (getbuflem(bufpart, ibufpart-1)!='\r')
        bufcopy(bufpart, ibufpart++, "\r", 1);
      if (tearline[0] && ((area==-1) || (lastorigin[0]=='\0')))
      { sprintf(stmp, "--- %s\r", tearline);
        bufcopy(bufpart, ibufpart, stmp, strlen(stmp)+1);
        ibufpart+=strlen(stmp);
      }
      if ((tearline[0]==0) && (area!=-1) && (lastorigin[0]=='\0'))
      { strcpy(stmp, "--- " NAZVA "\r");
        bufcopy(bufpart, ibufpart, stmp, strlen(stmp)+1);
        ibufpart+=strlen(stmp);
      }
    }
    if (xorigin[0] && (lastorigin[0]=='\0'))
      sprintf(lastorigin, " * Origin: %s\r", xorigin);
    if (lastorigin[0])
    { strncpy(origin, lastorigin+11, sizeof(origin));
      origin[sizeof(origin)-1]='\0';
      p=strrchr(origin, '(');
      if (p==NULL) p=origin+strlen(origin);
      if (p) for (*p--=0; isspace(*p); *p--=0);
      lastorigin[0]=0;
    }
    if (conf)
    { p=newsgr;
      p1=p;
      nxc=0;
    }
    debug(8, "One_Message: part %d in buffer, do crossposting", part+1);
    for (;;) /* by crossposting */
    { if (conf)
      { if (p1)
        { if (*p1=='\0') break;
          p=p1;
          p1=strpbrk(p1, " \t,\r\n");
          if (p1==NULL) p1=p+strlen(p);
          r=*p1;
          *p1=0;
          for (j=0; j<nechoes; j++)
            if (stricmp(echoes[j].usenet, p)==0)
              break;
          *p1=(char)r;
          while (isspace(*p1) || (*p1==','))
            p1++;
          if (j==nechoes)
            continue;
          /* compare with all previous */
          for (k=0; k<nxc; k++)
            if (xc[k]==j)
              break;
          if (k<nxc) continue;
          if ((j!=area) && echoes[j].noxc)
            continue;
          if (nxc<sizeof(xc)/sizeof(xc[0]))
            xc[nxc++]=j;
        }
        else
          j=area;
        debug(9, "One_Message: gate the part to echo %s", echoes[j].fido);
        curaka=echoes[j].aka;
        debug(9, "One_Message: using aka %d:%d/%d.%d",
              myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node, myaka[curaka].point);
      }
      /* all ok, put it */
      if (fout)
        if (fflush(fout)==EOF)
          goto errspace;
      if ((part==0) || (!isftnaddr) || (area!=-1))
      {
        r=nextmsg();
        if (r)
        { retcode|=RET_ERR;
          freebufpart();
          return retcode;
        }
        /* change REPLYTO */
        for (i=0; i<cheader; i++)
        { if (strnicmp(pheader[i], "\x01REPLYTO: ", 10)==0)
          { sprintf(pheader[i]+10, "%u:%u/%u",
                    myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node);
            if (myaka[curaka].point)
              sprintf(pheader[i]+strlen(pheader[i]), ".%u",
                      myaka[curaka].point);
            if (replyform==REPLY_UUCP)
              strcat(pheader[cheader], " uucp\r");
            else if (replyform==REPLY_ADDR)
              sprintf(pheader[cheader], " %s\r", msghdr.from);
            else /* empty */
              strcat(pheader[cheader], "\r");
          }
        }
        if (area!=-1)
        { zone=uplink[myaka[curaka].uplink].zone;
          net=uplink[myaka[curaka].uplink].net;
          node=uplink[myaka[curaka].uplink].node;
          point=uplink[myaka[curaka].uplink].point;
          msghdr.orig_zone=myaka[curaka].zone;
          msghdr.orig_net=myaka[curaka].net;
          msghdr.orig_node=myaka[curaka].node;
          msghdr.orig_point=myaka[curaka].point;
          msghdr.dest_zone=zone;
          msghdr.dest_net=net;
          msghdr.dest_node=node;
          msghdr.dest_point=point;
        }
        /* aka match by chaddr */
        if (conf && waschaddr)
        { parseaddr(fromstr, fromaddr, realname, 1); /* chaddr */
          transaddr(msghdr.from, &hiszone, &hisnet, &hisnode, &hispoint, fromaddr);
          strcpy(fromaddr, msghdr.from);
        }
        /* change msgid */
        if ((fmsgid[0]==0) && (conf) && (!isftnaddr || waschaddr))
        { if (!isftnaddr)
          { hiszone=myaka[curaka].zone;
            hisnet=myaka[curaka].net;
            hisnode=myaka[curaka].node;
            hispoint=myaka[curaka].point;
          }
          debug(9, "One_Message: changing MSGID");
          if ((wasmsgid & 2)==0 && domainmsgid==2 && domainid[0])
          { strncpy(s, domainid, sizeof(s));
            s[sizeof(s)-1]='\0';
            strncat(s, echoes[j].fido, sizeof(s)-strlen(s)-1);
            msgid=(crc32(s)^0xfffffffflu)+part;
            for (i=0; i<cheader; i++)
              if (strnicmp(pheader[i], "\x01MSGID: ", 8)==0)
              { p=strrchr(pheader[i]+8, ' ');
                if (p)
                  sprintf(p, " %08lx\r", msgid);
              }
          }
          if (((wasmsgid & 2)==0) && (!domainmsgid || (domainid[0]==0)))
          {
            for (i=0; i<cheader; i++)
              if (strnicmp(pheader[i], "\x01MSGID: ", 8)==0)
              { sprintf(pheader[i]+8, "%u:%u/%u",
                hiszone, hisnet, hisnode);
                p=pheader[i]+strlen(pheader[i]);
                if (hispoint)
                { sprintf(p, ".%u", hispoint);
                  p+=strlen(p);
                }
                sprintf(p, " %08lx\r", msgid);
              }
          }
        }
        /* change @REPLY */
        if (conf && domainmsgid==2 && freply[0]=='\0' && freplydomain[0])
        { unsigned long reply;
          strncpy(s, freplydomain, sizeof(s));
          s[sizeof(s)-1]='\0';
          strncat(s, echoes[j].fido, sizeof(s)-strlen(s)-1);
          reply=crc32(s)^0xfffffffflu;
          for (i=0; i<cheader; i++)
            if (strnicmp(pheader[i], "\x01REPLY: ", 8)==0)
            { p=strrchr(pheader[i]+8, ' ');
              if (p)
                sprintf(p, " %08lx\r", reply);
            }
        }
        /* change ^aSPLIT */
        for (i=0; i<cheader; i++)
          if (strncmp(pheader[i], "\x01SPLIT ", 7)==0)
          { sprintf(s, "%u/%u", hisnet, hisnode);
            sprintf(strchr(pheader[i], '@')+1, "%-12s", s);
            pheader[i][strlen(pheader[i])]=' ';
          }
        writehdr();
        if (area!=-1)
        { fputs("AREA:", fout);
          fputs(echoes[j].fido, fout);
          fputs("\r", fout);
          if ((part==0) && (j!=area))
            logwrite('-', "XC:  %s\n", echoes[j].fido);
        }
        /* put body */
        i=0;
        for (j=0; j<cheader; j++)
          if (strncmp(pheader[j], "\x01Via", 4) &&
              strncmp(pheader[j], "\x01Recd", 5))
          { if (savehdr ||
                (strnicmp(pheader[j], "\x01RFC-", 5)!=0) ||
                (strnicmp(pheader[j], "\x01RFC-Newsgroups:", 16)==0) ||
                (strnicmp(pheader[j], "\x01RFC-From:", 10)==0))
            { fputs(pheader[j], fout);
              if ((pheader[j][0]!=1) && (pheader[j][0]!=0)) i=1;
            }
          }
        if (i)
          fputs("\r", fout);
      }
      debug(11, "One_Message: put text part");
      if (tabsize==0)
      { if (writebuf(bufpart, ibufpart, fout))
        {
errspace:
#ifdef __MSDOS__
          logwrite('?', "ERROR! Can't write to file (disk full?)!\n");
#else
          logwrite('?', "ERROR! Can't write to file: %s!\n", strerror(errno));
#endif
          if (!bypipe)
            close(f);
          f=-1;
          goto errlet;
        }
      }
      else
      { /* tabsize */
        for (l=clmn=0; l<ibufpart; l++)
        { switch (getbuflem(bufpart, l))
          { case '\t': for (j=clmn%tabsize; j<tabsize; j++)
                         if (fputc(' ', fout)==EOF)
                           goto errspace;
                       clmn=0;
                       continue;
            case '\r': clmn=-1;
            default:   clmn++;
                       if (fputc(getbuflem(bufpart, l), fout)==EOF)
                         goto errspace;
                       continue;
          }
        }
      }
      if (ibufpart && getbuflem(bufpart, ibufpart-1)!='\r')
        if (fputc('\r', fout)==EOF)
          goto errspace;
      if (area!=-1)
      { /* put origin line */
#if 0
        fprintf(fout, " * Origin: %s (%u:%u/%u",
                origin, hiszone, hisnet, hisnode);
        if (hispoint)
          fprintf(fout, ".%u", hispoint);
        fputs(")\r", fout);
#else
        sprintf(xorigin, " * Origin: %%s (%u:%u/%u",
                hiszone, hisnet, hisnode);
        if (hispoint)
          sprintf(xorigin+strlen(xorigin), ".%u", hispoint);
        strcat(xorigin, ")\r");
        origin[MAXORIGIN-strlen(xorigin)+2]='\0';
        fprintf(fout, xorigin, origin);
        xorigin[0]='\0';
#endif
      }
      if (conf)
      { /* process path and seen-by */
        debug(11, "One_Message: make PATH and SEEN-BY");
        for (i=0; i<nseenby; i++)
          if (myaka[curaka].zone==lastzone)
            seenby[i].is=1;
          else
            seenby[i].is=0;
        if (nseenby<MAXSEENBY)
        { /* add myself */
          for (i=0; i<nseenby; i++)
            if ((seenby[i].net==myaka[curaka].net) &&
                (seenby[i].node==myaka[curaka].node) && seenby[i].is)
              break;
          if ((i==nseenby) && (myaka[curaka].point==0))
          { seenby[i].net=myaka[curaka].net;
            seenby[i].node=myaka[curaka].node;
            seenby[i].is=2;
            nseenby++;
          }
          if ((nseenby<MAXSEENBY) &&
              (uplink[myaka[curaka].uplink].point==0) &&
              (uplink[myaka[curaka].uplink].zone==myaka[curaka].zone))
          { /* add uplink */
            for (i=0; i<nseenby; i++)
              if ((seenby[i].net==uplink[myaka[curaka].uplink].net) &&
                  (seenby[i].node==uplink[myaka[curaka].uplink].node) &&
                  seenby[i].is)
                break;
            if (i==nseenby)
            { seenby[i].net=uplink[myaka[curaka].uplink].net;
              seenby[i].node=uplink[myaka[curaka].uplink].node;
              seenby[i].is=2;
              nseenby++;
            }
          }
        }
        /* sort seenbyes */
        /* buble */
        if (nseenby>1)
          for (j=k=1; j; k++)
          { j=0;
            for (i=0; i<nseenby-k; i++)
            { if (seenby[i].net<seenby[i+1].net) continue;
              if ((seenby[i].net>seenby[i+1].net) ||
                  (seenby[i].node>seenby[i+1].node))
              { j=seenby[i].net;
                seenby[i].net=seenby[i+1].net;
                seenby[i+1].net=j;
                j=seenby[i].node;
                seenby[i].node=seenby[i+1].node;
                seenby[i+1].node=j;
                j=seenby[i].is;
                seenby[i].is=seenby[i+1].is;
                seenby[i+1].is=j;
                j=1;
              }
            }
          }

        /* put path and seen-by */
        k=0;
        for (j=0; j<nseenby;)
        { if (seenby[j].is==0)
          { j++;
            continue;
          }
          if (k==0)
          { fputs("SEEN-BY:", fout);
            k=8;
            pp=-1; /* network */
          }
          if (seenby[j].net!=pp)
          { pp=seenby[j].net;
            sprintf(s, " %u/%u", pp, seenby[j].node);
          }
          else
            sprintf(s, " %u", seenby[j].node);
          if (k+strlen(s)>=80)
          { fputs("\r", fout);
            k=0;
            continue;
          }
          fputs(s, fout);
          j++;
          k+=strlen(s);
        }
        if (k)
          if (fputs("\r", fout)==EOF)
            goto errspace;
        /* remove own seenbyes */
        for (j=0; j<nseenby; j++)
          if (seenby[j].is==2)
          { for (k=j; k<nseenby-1; k++)
            { seenby[k].net=seenby[k+1].net;
              seenby[k].node=seenby[k+1].node;
              seenby[k].is=seenby[k+1].is;
            }
            nseenby--;
            j--;
          }
        k=0;
        if (myaka[curaka].zone==lastzone)
          for (j=0; j<npath;)
          { if (k==0)
            { fputs("\x01PATH:", fout);
              k=6;
              pp=-1; /* network */
            }
            if (path[j].net!=pp)
            { pp=path[j].net;
              sprintf(s, " %u/%u", pp, path[j].node);
            }
            else
              sprintf(s, " %u", path[j].node);
            if (k+strlen(s)>=80)
            { fputs("\r", fout);
              k=0;
              continue;
            }
            fputs(s, fout);
            j++;
            k+=strlen(s);
          }
        /* if (myaka[curaka].point==0) */
        {
          if (k==0) /* no path */
          { fputs("\x01PATH:", fout);
            k=6;
            pp=-1; /* network */
          }
          if (myaka[curaka].net!=pp)
          { pp=myaka[curaka].net;
            sprintf(s, " %u/%u", pp, myaka[curaka].node);
          }
          else
            sprintf(s, " %u", myaka[curaka].node);
          if (k+strlen(s)>=80)
          { fputs("\r\x01PATH:", fout);
            k=6;
            sprintf(s, " %u/%u", pp, myaka[curaka].node);
          }
          fputs(s, fout);
        }
        if (k)
          if (fputs("\r", fout)==EOF)
            goto errspace;
      }
      if ((part==parts-1) || (area!=-1) || (!isftnaddr)) /* from fido - don't split */
      {
        for (j=1; j<cheader; j++)
          if ((strncmp(pheader[j], "\x01Via ", 5)==0) ||
              (strncmp(pheader[j], "\x01Recd ", 6)==0))
            if (fputs(pheader[j], fout)==EOF)
              goto errspace;
        for (j=cheader-1; j>0; j--)
        { if (strncmp(pheader[j], "\x01Via:", 5)==0)
            if (fprintf(fout, "\x01Via %s", pheader[j]+5)==EOF)
              goto errspace;
          if (strncmp(pheader[j], "\x01Recd:", 6)==0)
            if (fprintf(fout, "\x01Recd %s", pheader[j]+6)==EOF)
              goto errspace;
        }
      }
      if (!conf) break;
      if (p1==NULL) break;
    }
    /* change msgid */
    debug(9, "One_Message: changing MSGID");
    msgid++;
    seqf++;
    for (j=1; j<cheader; j++)
      if (strncmp(pheader[j], "\x01MSGID: ", 8)==0)
        break;
    if (j<cheader)
    { if (wasmsgid & 2)
        pheader[j][0]='\0';
      else
      { p=strrchr(pheader[j]+8, ' ');
        if (p)
          sprintf(p, " %08lx\r", msgid);
      }
    }
    if (fout)
      if (fflush(fout)==EOF)
        goto errspace;
  }
  if (errl)
  { if (bypipe)
      retcode|=RET_ERR;
    debug(6, "One_Message: error, returns %d", RET_ERR);
    freebufpart();
    return RET_ERR;
  }

  if (area==-1)
  {
    if (point)
      sprintf(str, "%u:%u/%u.%u", zone, net, node, point);
    else
      sprintf(str, "%u:%u/%u", zone, net, node);
      
    logwrite('$', "From %s\tto %s %s %lu bytes OK\n", fromaddr,
             msghdr.to, str, maxmsgbuf+hdrsize);
    if (!bypipe)
      retcode|=RET_NETMAIL;
  }
  if (area!=-1)
  {
    logwrite('-', "AREA:%s\tFrom %s %lu bytes OK\n", echoes[area].fido, fromaddr, maxmsgbuf+hdrsize);
    if (!bypipe)
      retcode|=RET_ECHOMAIL;
  }
  if ((!conf) && (!packmail))
    waslet=1;
  debug(6, "One_Message: return %d", 0);
  freebufpart();
  return 0;
}
