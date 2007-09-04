/*
 * $Id$
 *
 * $Log$
 * Revision 2.21  2007/09/04 08:28:35  gul
 * Fix in message-id=fidogate
 *
 * Revision 2.20  2007/09/04 08:10:52  gul
 * message-id=fidogate
 *
 * Revision 2.19  2007/08/02 07:00:37  gul
 * Cosmetics
 *
 * Revision 2.18  2006/12/19 13:18:52  gul
 * Fix warnings
 *
 * Revision 2.17  2004/07/20 18:47:19  gul
 * \r\n -> \n
 *
 * Revision 2.16  2004/07/20 18:45:43  gul
 * Fixed reject reasons logic
 *
 * Revision 2.15  2002/11/17 20:56:16  gul
 * gcc/glibc workaround, buggy memmove
 *
 * Revision 2.14  2002/09/30 14:30:51  gul
 * bugfix
 *
 * Revision 2.13  2002/09/30 13:44:39  gul
 * bugfix
 *
 * Revision 2.12  2002/09/22 12:55:04  gul
 * extmsgid bugfix
 *
 * Revision 2.11  2002/09/22 12:43:24  gul
 * extmsgid bugfix
 *
 * Revision 2.10  2002/09/22 11:42:23  gul
 * bugfix
 *
 * Revision 2.9  2002/09/22 10:58:36  gul
 * several bugfixes
 *
 * Revision 2.8  2002/03/21 15:27:50  gul
 * Possible buffer overflow fix, remove cmdline length limitation
 *
 * Revision 2.7  2002/03/21 14:54:14  gul
 * Gw-To, Gw-Cc, Gw-Bcc works now
 *
 * Revision 2.6  2002/03/21 13:43:25  gul
 * Remove dest addr list length limitation
 *
 * Revision 2.5  2002/03/21 11:19:14  gul
 * Added support of msgid style <newsgroup|123@domain>
 *
 * Revision 2.4  2001/01/21 10:20:01  gul
 * new cfg param 'fromtop'
 *
 * Revision 2.3  2001/01/20 01:33:40  gul
 * Added some debug messages
 *
 * Revision 2.2  2001/01/19 17:42:47  gul
 * Translate comments and cosmetic changes
 *
 * Revision 2.1  2001/01/15 03:37:09  gul
 * Stack overflow in dos-version fixed.
 * Some cosmetic changes.
 *
 * Revision 2.0  2001/01/10 20:42:18  gul
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
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <time.h>
#ifdef __OS2__
#define INCL_DOSQUEUES
#define INCL_DOSPROCESS
#include <os2.h>
#endif
#include "gate.h"

#define NAMEOUT   "tempgate.???"
#define MAXWLEN   10
#define RESERV    8192
#define MINMSGLEN 4096

#ifndef DEFINED_STRSIGNAL
char *strsignal(int sig);
#endif

#define eoline() for (;strchr(str, '\n')==NULL;) if (hgets(str, sizeof(str), h)==0) break;
static void reject(int reason, char *to);
static int  memgets(char *s, int size);

unsigned long txtsize;
int  area;
char *header;
int  retcode, frescan=0;
char *myintsetname, *myextsetname;

static char *nagate, *nafig, *curto;
static int  sizenagate, sizenafig, sizecurto;
static int  rejreason, currcv;
static char msgid[256], errstr[128];
static char bound[80];
static char tmpout[FNAME_MAX];
static char *cmdline;
static int  sizecmdline;
static char rfcid;
static char pref[MAXPREFIX+1];
static char klname[2048], klopt[2048]; /* not less then sizeof(str)! */
static char filelist[80];
static unsigned long attr;
static char *p, *p1;
static VIRT_FILE *fout;
char *memtxt=NULL;
unsigned long imemtxt;
static uword tozone, tonet, tonode, topoint;
static int  i, j, k, r;
static char begline, c;
static uword u1, u2, u3, u4;
static unsigned long wlen, cword, nwords;
static int  firstline, cont;
static int  achanged;
static long l, msgbuflen;
static nodetype path[MAX_PATH];
static int  npath;
static char wascyr;
static long tear_pos, origin_pos; 
static int  tear_len, origin_len;
static int  fromtext;
static int  msgtz;
#ifndef __MSDOS__
static void *msgidregbuf1, *msgidregbuf2;
#endif

static void xstrcpy(char **dest, int *dsize, char *src)
{ if (*dsize<=strlen(src))
  { if (*dsize && *dest) free(*dest);
    *dest=strdup(src);
    *dsize=strlen(src)+1;
  }
  else strcpy(*dest, src);
}

static int xexpand(char **dest, int *dsize, int lsrc)
{ char *new;
  int ldest, newsize;

  ldest=(*dest ? strlen(*dest) : 0);
  newsize=*dsize;
  while (newsize<=lsrc+ldest+1) newsize+=128;
  if (newsize>*dsize)
  { new=*dest ? realloc(*dest, newsize) : malloc(newsize);
    if (new==NULL)
    { logwrite('!', "Not enough memory!\n"); 
      return -1;
    }
    if (*dest==NULL) *new='\0';	/* for xstrcat() to NULL string */
    *dest=new;
    *dsize=newsize;
  }
  return 0;
}

static void xstrcat(char **dest, int *dsize, char *src)
{
  int ldest;
  if (xexpand(dest, dsize, strlen(src)+2))
    return;
  ldest=(*dest && **dest) ? strlen(*dest)+1 : 0;
  if (ldest) (*dest)[ldest-1]=' ';
  strcpy(*dest+ldest, src);
}

/* add str to *to */
/* realloc *to if needed */
static void tofield(char *str, char **to, int *sizeto)
{
  char *p;
  int lento, lenstr, newsize;

  getaddr(str);
  lenstr=strlen(str);
  lento=*to ? strlen(*to) : 0;
  if (lenstr+lento+2>*sizeto)
  { newsize=*sizeto;
    while (lenstr+lento+2>newsize)
      newsize+=128;
    if (*to)
      p=realloc(*to, newsize);
    else
      p=malloc(newsize);
    if (p==NULL)
    { logwrite('!', "Not enough memory for dest addr list, truncated\n");
      return;
    }
    *sizeto=newsize;
    *to=p;
  }
  if (**to)
  { strcat(*to, " ");
    lento++;
  }
  strcpy(to[0]+lento, str);
  p=strchr(to[0]+lento, '\n');
  if (p) *p=0;
  stripspc(to[0]+lento);
}

static void fidogaterfcid(char *p, char *msgid, int size)
{
  int i;

  strcpy(msgid, "MSGID_");
  msgid += 6;
  for (i=0; *p && i<size-6; p++)
  { if (*p == ' ') msgid[i++] = '_';
    else if (strchr("()<>@,;:\\\"[]/=_", *p) || *p>=0x7f || *p<0x20)
    { sprintf(msgid+i, "=%02X", (unsigned char)*p);
      i+=3;
    }
    else
      msgid[i++] = *p;
  }
  msgid[i] = '@';
}

int one_message(char *msgname)
{
    time_t curtime;
    struct tm *curtm;

    debug(9, "Main: found message in %s", msgname);
    curtime=time(NULL);
    curtm=localtime(&curtime);
    /* look, if we need to send this */
    topoint=0;
    tozone=myaka[0].zone;
    tonet=msghdr.dest_net;
    tonode=msghdr.dest_node;
    curgate=ngates;
    wascyr=0;
    errstr[0]=0;
    tear_pos=origin_pos=-1;
    fromtext=1;
    myintsetname = intsetname;
    myextsetname = extsetname;
    for (curaka=0; curaka<naka; curaka++)
      if ((tonode==myaka[curaka].node) &&
          (tonet==myaka[curaka].net))
        break;
    if (ngates==0)
    {
      if ((curaka==naka) && (!packed))
        return 0;
/*
      if (touucp && (strchr(msghdr.to, '@')==NULL) &&
         stricmp(msghdr.to, "uucp") && (!packed))
        return 0;
*/
    }
    net=msghdr.orig_net;
    node=msghdr.orig_node;
    if (curaka<naka)
      zone=myaka[curaka].zone;
    else
      zone=myaka[0].zone;
    point=0;
    rfcid=0;
    if (msghdr.attr & msgORPHAN)
    { if (packed)
      { logwrite('?', "Orphan message for me, moved to badmail\n");
        badmsg("Message with Orphan attribute");
      }
      return 0;
    }
    if (msghdr.attr & msgSENT)
    { if (packed)
      { logwrite('?', "Sent message for me, moved to badmail\n");
        badmsg("Message with Sent attribute");
      }
      return 0;
    }
    if (msghdr.attr & msgHOLD)
    { if (packed)
      { logwrite('!', "Hold packed message for me\n");
        msghdr.attr&=~msgHOLD;
      }
      else
        return 0;
    }
    if (msghdr.attr & msgFREQ)
    { if (packed)
      { logwrite('?', "Freq for me, moved to badmail\n");
        badmsg("Message with FREQ attribute");
      }
      return 0;
    }
    if ((msghdr.attr & msgLOCAL & msgFORWD) ||
        !(msghdr.attr & (msgLOCAL | msgFORWD)))
    { if (packed)
      { logwrite('!', "Incorrect attributes (%s) in packed message\n",
                 (msghdr.attr & msgLOCAL) ? "LOC & FWD" : "no LOC and no FWD");
        msghdr.attr&=~msgLOCAL;
        msghdr.attr|=msgFORWD;
      }
      else
        return 0;
    }
    if ((msghdr.attr & msgFILEATT) && (msghdr.attr & msgLOCAL) &&
        (strchr(msghdr.to, '@')==NULL) && (!packed))
    { /* remove if empty */
      u1=0;
      cont=0;
      attr=msghdr.attr;
      while (hgets(str, sizeof(str), h))
      { if (cont)
        { if (strchr(str, '\n'))
            cont=0;
          continue;
        }
        if (strchr(str, '\n')==NULL)
          cont=1;
        if (str[0]==1)
        { if (strncmp(str+1, "TOPT", 4)==0)
            topoint=atoi(str+6);
          else if (strncmp(str+1, "FLAGS", 5)==0)
          { if (strstr(str, "KFS"))
              attr|=msgKFS;
            else if (strstr(str, "TFS"))
              attr|=msgTFS;
          }
          else if (strnicmp(str+1, "To:", 3)==0 && strchr(str, '@'))
            u1=1;
          eoline();
          continue;
        }
        else if (str[0]!='\n')
          u1=1;
      }
      if (topoint!=myaka[curaka].point)
      { /* is this aka exists? */
        for (i=0; i<naka; i++)
          if ((myaka[i].node==myaka[curaka].node) &&
              (myaka[i].net==myaka[curaka].net) &&
              (myaka[i].point==topoint)) break;
        if (i<naka)
          curaka=i;
        else
        { if (packed)
          { logwrite('?', "Packed message not for me, moved to badmail!\n");
            badmsg("Packed message not for me");
          }
          return 0;
        }
      }
      if (u1==0)
      { /* move attaches to tempdir */
        char c;
        char *p=msghdr.subj, *p1;
        for (p=msghdr.subj;;)
        {
          while (p<msghdr.subj+sizeof(msghdr.subj) && *p && isspace(*p))
            p++;
          if (p>=msghdr.subj+sizeof(msghdr.subj) || *p=='\0')
            break;
          p1=p;
          while (p1<msghdr.subj+sizeof(msghdr.subj) && *p1 && !isspace(*p1))
            p1++;
          c=*p1;
          *p1='\0';
          if (stricmp(p+strlen(p)-4, ".pkt"))
            u1=moveatt(p, attr);
          if (c=='\0') break;
          *p1=c;
          p=p1+1;
        }
        flock(h, LOCK_UN);
        close(h);
        h=-1;
        if (u1==0)
          unlink(msgname);
        return 0;
      }
      if (filelength(h)<BUFSIZE)
        ibuf=sizeof(msghdr);
      else
      { lseek(h, sizeof(msghdr), SEEK_SET);
        ibuf=BUFSIZE;
      }
    }
    debug(6, "Main: header looks like for me");
    /* look like, we should sent this */
    /* check for restrictions */
    /* and write temp file with message text */
    if (curaka==naka)
      curaka=0;
    msgtz=0;

    /* get temp files names */
    mktempname(NAMEOUT, tmpout);
    msgbuflen=filelength(h);
#if 1
    if (packed && msgbuflen>MINMSGLEN)
      msgbuflen=MINMSGLEN;
#else
    if (packed)
    { if (msgbuflen>maxsize)
        msgbuflen=maxsize;
#ifdef __MSDOS__
      { long l=farcoreleft()-1024; /* no getfreemem(), it can be too large */
        if (msgbuflen>l)
          msgbuflen=l;
      }
#endif
    }
#endif
    debug(7, "Main: message buffer size is %ld", msgbuflen);
    if (memtxt) freebuf(memtxt);
    memtxt=createbuf(msgbuflen);
    if (memtxt==NULL)
    { logwrite('?', "Not enough memory for %s!\n", msgname);
      p="Not enough memory";
lbadmsg:
      badmsg(p);
      return 0;
    }
    imemtxt=0;
    msgid[0]=0;
    firstline=1;
    cheader=0;
    pheader[0]=header;
    gw_to[0]=0;
    if (strchr(msghdr.to, '@'))
      strcpy(to, msghdr.to);
    else
      to[0]=0;
    attr=msghdr.attr;
    wlen=cword=nwords=0;
    area=-1;
    npath=0;
    cont=0;
    while (hgets(str, sizeof(str), h))
    { for (p=str; *p; p++)
        if (*p & 0x80) wascyr=1;
      switch (cont)
      {
        case 3: /* to message body */
                if (strchr(str, '\n'))
                  cont=0;
                goto plaintext;
        case 2: /* to header */
                chkkludges;
                strcpy(pheader[cheader-1]+strlen(pheader[cheader-1]), str);
                pheader[cheader]+=strlen(str);
        case 1: /* to /dev/null */
                if (strchr(str, '\n'))
                  cont=0;
                continue;
        case 0: break;
      }
      if (strchr(str, '\n')==NULL)
        cont=1;
      if (str[0]==1)
      { /* kludge */
        debug(12, "Main: read kludge line: %s", str+1);
        chkkludges;
        firstline=0;
        parsekludge(str, klname, klopt);
        if (stricmp(klname, "TOPT")==0)
        { topoint=atoi(klopt);
          continue;
        }
        if (stricmp(klname, "FMPT")==0)
        { point=atoi(klopt);
          continue;
        }
        if (stricmp(klname, "INTL")==0)
        { p=klopt;
          if (!isdigit(*p))
          { p=strchr(p, '#');
            if (p==NULL) p=klopt;
            else p++;
          }
          if (getfidoaddr(&tozone, &u1, &u2, &u3, p))
          { logwrite('?', "Incorrect INTL kludge in %s!\n", msgname);
            p="Incorrect INTL kludge";
            goto lbadmsg;
          }
          tonet=u1;
          tonode=u2;
          if (u3) topoint=u3;
          p=strchr(klopt, ' ');
          if (p)
          { p++;
            if (!isdigit(*p))
              if (strchr(p, '#'))
                p=strchr(p, '#')+1;
            if (getfidoaddr(&zone, &u1, &u2, &u3, p)==0)
            { net=u1;
              node=u2;
              if (u3) point=u3;
            }
            else
            { logwrite('?', "Incorrect INTL kludge in %s!\n", msgname);
              p="Incorrect INTL kludge";
              goto lbadmsg;
            }
          }
          continue;
        }
        if (stricmp(klname, "FLAGS")==0)
        {
          if (strstr(str+6, " CFM"))
            attr|=msgCFM;
          if (strstr(str+6, " LOK"))
          { attr|=msgLOCK;
            if (packed)
            { logwrite('?', "Locked message in %s, moved to badmail!\n", msgname);
              p="Message with LOCK attribute";
              goto lbadmsg;
            }
            flock(h, LOCK_UN);
            close(h);
            h=-1;
            break;
          }
          if (strstr(str+6, " DIR"))
             attr|=msgDIRECT;
          if (strstr(str+6, " IMM"))
            attr|=msgIMM;
          if (strstr(str+6, " KFS"))
            attr|=msgKFS;
          if (strstr(str+6, " TFS"))
            attr|=msgTFS;
          continue;
        }
        if (stricmp(klname, "TID")==0)
        { /* remove FECHO etc. */
          continue;
        }
        if (stricmp(klname, "REPLYADDR")==0)
        {
          continue;
        }
        if (stricmp(klname, "REPLYTO")==0)
        {
          continue;
        }
        if (stricmp(klname, "CHRS")==0)
        {
          struct ftnchrs_type *fp;

          p=strchr(klopt, ' ');
          if (p) *p='\0';
          for (fp=ftnchrs; fp; fp=fp->next)
            if (stricmp(fp->ftnchrs, klopt)==0)
            { myintsetname = fp->rfcchrs;
              break;
            }
          if (fp) continue;
        }
        if (stricmp(klname, "MSGID")==0)
        {
          if (strchr(str, '\n')==NULL)
            continue;
          sprintf(pheader[cheader], "X-FTN-MsgId: %s\n", klopt);
          nextline;
          chkkludges;
          if (getfidoaddr(&u1, &u2, &u3, &u4, klopt))
          { /* fidogate? */
            if (!rfcid && chkregexp(klopt, "^<[a-z0-9\\-\\._&%$!^+=:;/~*]+\\@[a-zA-Z0-9\\-\\._&%$!^+=:;/~*]+> [a-z0-9]{8,8}\\s*$"
#ifndef __MSDOS__
                , &msgidregbuf1
#endif
               ) == 0)
            {
              strncpy(msgid, klopt+1, sizeof(msgid));
              msgid[sizeof(msgid)-1]='\0';
              p=strchr(msgid, '>');
              if (p) *p='\0';
              rfcid=1;
            } else if (!rfcid && chkregexp(klopt, "^\"<([a-z0-9\\-\\._&%$!^+=:;/~* ]|\"\")+\\@([a-zA-Z0-9\\-\\._&%$!^+=:;/~* ]|\"\")+>\" [a-z0-9]{8,8}\\s*$"
#ifndef __MSDOS__
                , &msgidregbuf2
#endif
               ) == 0)
            { /* dequote */
              for (p=msgid, p1=klopt+2; p1[0] && p1[1] && p1[2] &&
                   (p1[0]!='>' || p1[1]!='\"' || p1[2]!=' ') &&
                   p-msgid<sizeof(msgid)-1; p++)
              { if (p1[0]=='\"' && p1[1]=='\"')
                  *p++=*p1++;
                else
                  *p++=*p1;
              }
              *p='\0';
              rfcid=1;
            }
            continue;
          }
          zone=u1;
          net=u2;
          node=u3;
          point=u4;
          if (msgid[0])
            continue;
          p=klopt;
          if (fscmsgid == 2) /* fidogate */
            fidogaterfcid(p, msgid, sizeof(msgid)-20);
          else if (fscmsgid == 1)
          { strncpy(msgid, p, sizeof(msgid));
            msgid[sizeof(msgid)-2]='\0';
            p=strchr(msgid, '@');
            if (p)
              if ((strcmp(p, "@fidonet.org")==0) ||
                  (strcmp(p, "@fidonet")==0))
                *p='\0';
            for (p=msgid; *p; p++)
              if (!isalpha(*p) && !isdigit(*p))
                *p='-';
            strcat(msgid, "@");
            continue;
          }
          /* ifgate style */
          for (; *p; p++)
          { if (*p==' ') break;
            if (*p=='@') break;
          }
          if (*p==0)
            continue;
          if (*p=='@')
          { *p=0;
            p=strchr(p+1, ' ');
            if (p==NULL)
              continue;
          }
          *p=0;
          while (*(++p)==' ');
          if (*p==0)
            continue;
          if ((strlen(p)>8) || strpbrk(p, " \t\n\r,;<>()@!:\"?*"))
            continue; /* not clear FTN MSGID - ignore */
          if (point)
            sprintf(msgid, "%s@p%u.f%u.n%u.z%u.", p, point, node, net, zone);
          else
            sprintf(msgid, "%s@f%u.n%u.z%u.", p, node, net, zone);
          continue;
        }
        if ((stricmp(klname, "RFCID")==0) ||
            (stricmp(klname, "RFC-Message-Id")==0))
        { if (klopt[0]=='<')
            strncpy(msgid, klopt+1, sizeof(msgid));
          else
            strncpy(msgid, klopt, sizeof(msgid));
          msgid[sizeof(msgid)-1]='\0';
          if (klopt[0]=='<')
          { p=strrchr(msgid, '>');
            if (p) *p=0;
          }
          rfcid=1;
          continue;
        }
        if (stricmp(klname, "PID")==0)
        { if (cont) cont=2;
          sprintf(pheader[cheader], "X-FTN-PID: %s\n", klopt);
          nextline;
          pheader[cheader]+=5; /* reserved for X-Newsreader */
          continue;
        }
        if (stricmp(klname, "VIA")==0)
        { if (cont) cont=2;
          sprintf(pheader[cheader], "Received: by %s\n", klopt);
          nextline;
          continue;
        }
        if (stricmp(klname, "Forwarded")==0)
        { if (cont) cont=2;
          sprintf(pheader[cheader], "Received: %s\n", klopt);
          nextline;
          continue;
        }
        if (stricmp(klname, "REPLY")==0)
        { if (strchr(str, '\n')==NULL)
            continue;
          sprintf(pheader[cheader], "X-FTN-%s: %s\n", klname, klopt);
          nextline;
          chkkludge(strlen(str)+(area==-1 ? 0 : strlen(echoes[area].usenet)));
          strcpy(pheader[cheader], "References: <");
          if (area!=-1 && group[echoes[area].group].extmsgid)
          { strcat(pheader[cheader], echoes[area].usenet);
            strcat(pheader[cheader], "|");
          }
          if (klopt[0] == '<' || (klopt[0]=='\"' && klopt[1]=='<'))
          { /* fidogate? */
            char *p2, *p1=pheader[cheader]+strlen(pheader[cheader]);
            p2=p1;
            if (klopt[0]=='\"')
            { p=klopt+2;
              while (*p)
              { if (*p=='\"')
                { if (p[1]=='\"')
                    p++;
                  else
                    break;
                }
                *p1++=*p++;
              }
              if (*p!='\"' || p[1]!=' ' || *(p1-1)!='>')
                /* bad fidogate reply */
                continue;
            }
            else
            { p=strrchr(klopt, ' ');
              if (p==NULL || *(--p)!='>')
                continue;
              memcpy(p1, klopt+1, p-klopt);
              p1[p-klopt]='\0';
            }
            /* is newsgroup exists twice in the msgid? */
            if (area!=-1 && group[echoes[area].group].extmsgid)
            { p=strstr(p2, echoes[area].usenet);
              if (p && *(p-1)=='|' && p[strlen(echoes[area].usenet)]=='|')
                strcpy(pheader[cheader]+13, p2);
            }
            strcat(pheader[cheader], "\n");
            nextline;
            continue;
          }
          if (fscmsgid == 2)
          { chkkludge(strlen(klopt)*3);
            fidogaterfcid(klopt, pheader[cheader]+strlen(pheader[cheader]), 256);
          }
          else if (fscmsgid)
          { p=strchr(klopt, '@');
            if (p)
              if ((strcmp(p, "@fidonet.org")==0) ||
                  (strcmp(p, "@fidonet")==0))
                *p='\0';
            for (p=klopt; *p; p++)
              if (!isalpha(*p) && !isdigit(*p))
                *p='-';
            strcat(pheader[cheader], klopt);
            strcat(pheader[cheader], "@");
          }
          else
          {
            p=strchr(klopt, ' ');
            if (p==NULL) continue;
            p++;
            if (getfidoaddr(&u1, &u2, &u3, &u4, klopt))
              continue;
            if (u4)
              sprintf(pheader[cheader]+strlen(pheader[cheader]),
                      "%s@p%u.f%u.n%u.z%u.", p, u4, u3, u2, u1);
            else
              sprintf(pheader[cheader]+strlen(pheader[cheader]),
                      "%s@f%u.n%u.z%u.", p, u3, u2, u1);
          }
          /* try to get domain */
          if ((atoi(klopt)>0) && (atoi(klopt)<7))
            strcat(pheader[cheader], "fidonet.org");
          else
          { /* find corresponding zone */
            for (i=0; i<naka; i++)
              if (myaka[i].zone==atoi(str+8)) break;
            if (i==naka) i=0;
            p=pheader[cheader]+strlen(pheader[cheader]);
            strcpy(p, myaka[i].domain);
            p=strpbrk(p, "%@");
            if (p) *p=0;
          }
          strcat(pheader[cheader], ">\n");
          nextline;
          continue;
        }
        if (stricmp(klname, "PATH")==0)
        {
          p=klopt;
          i=-1; /* network */
          while (*p)
          { if (npath==MAX_PATH)
              break;
            while (*p==' ') p++;
            if (!isdigit(*p)) break;
            j=atoi(p);
            while (isdigit(*p)) p++;
            if (*p=='/')
            { i=j;
              p++;
              if (!isdigit(*p)) break;
              j=atoi(p);
              while (isdigit(*p)) p++;
            }
            if (i==-1) break;
            for (k=0; k<npath; k++)
              if ((path[k].net==i) && (path[k].node==j))
                break;
            if (k<npath)
              continue;
            for (k=npath; k>0; k--)
              memcpy(path+k, path+k-1, sizeof(path[0]));
            path[0].net=i;
            path[0].node=j;
            npath++;
          }
          continue;
        }
        if (stricmp(klname, "RFC-Path")==0)
          continue;
        if (strnicmp(klname, "RFC-", 4)==0)
        { switch (adduserline(str+5))
          { case 0: if (!isfield(klname))
                    { sprintf(pheader[cheader], "%s: %s\n", klname+4, klopt);
                      nextline;
                    }
            case 1: if (cont) cont=2;
                    continue; /* to header */
#if 1
            case 2: if (cont) cont=1;   /* to /dev/null */
                    continue;
#else
            case 2: sprintf(pheader[cheader], "X-%s: $s\n", klname+4, klopt);
                    if (cont) cont=2;
                    continue;
#endif
            case 3: p="Incorrect user headline";
                    goto lbadmsg;
          }
          continue;
        }
        if ((area==-1) && (strchr(msghdr.to, '@')==NULL) &&
            (strnicmp(str+1, "To:", 3)==0) && strchr(str, '@'))
          if ((!touucp) || stricmp(msghdr.to, "uucp")==0)
          { tofield(str+4, &to, &sizeto);
            continue;
          }
        if (stricmp(klname, "Newsgroups")==0)
          continue;
        if (stricmp(klname, "Date")==0)
          continue;
        if (stricmp(klname, "Subject")==0)
          continue;
#if 0
        if (strnicmp(str+1, "X-To:", 5)==0)
        { /* golded */
          if (isfield("X-Comment-To:"))
            continue;
          sprintf(pheader[cheader], "X-Comment-%s", str+3);
          nextline;
          continue;
        }
#endif
        if (stricmp(klname, "TZUTC")==0)
        { msgtz=-atoi(klopt)/100;
          continue;
        }
        switch (adduserline(str+1))
        { case 0: break;
          case 1: if (cont) cont=2;
                  debug(8, "Main: add to header: %s", str+1);
                  continue; /* to header */
#if 1
          case 2: if (cont) cont=1;   /* to /dev/null */
                  continue;
#else
          case 2: sprintf(pheader[cheader], "X-%s: %s", klname, klopt);
                  if (cont) cont=2;
                  continue;
#endif
          case 3: p="Incorrect user headline";
                  goto lbadmsg;
        }
        /* rest of kludges simple move to header */
        if (cont) cont=2;
        for (p=klname; *p; p++)
        { if (*p & 0x80) break;
          if ((!isalpha(*p)) && (!isdigit(*p)) && (*p!='-')) break;
        }
        if (klname[0] && klopt[0] && (*p=='\0'))
        { sprintf(pheader[cheader], "X-FTN-%s: %s\n", klname, klopt);
          nextline;
          continue;
        }
        sprintf(pheader[cheader], "X-FTN-Kludge: %s", str+1);
        nextline;
        continue;
      }
      if ((strncmp(str, "AREA:", 5)==0) && firstline)
      { if (!packed)
        { logwrite('?', "%s is echomail message!\n", msgname);
          p="Not packed echomail message";
          goto lbadmsg;
        }
        firstline=0;
        p=strchr(str+5, '\n');
        if (p) *p=0;
        else
        { logwrite('?', "Too long AREA line in %s!\n", msgname);
          p="Too long AREA line";
          goto lbadmsg;
        }
        debug(4, "Main: area is %s", str+5);
        for (area=0; area<nechoes; area++)
          if (stricmp(str+5, echoes[area].fido)==0)
            break;
        if (area==nechoes)
        { logwrite('?', "Unknown area %s, message moved to badmail!\n",
                   str+5);
          p="Unknown area";
          goto lbadmsg;
        }
        curaka=group[echoes[area].group].aka;
        if (group[echoes[area].group].type==G_FEED)
        { for (p=str,p1=group[echoes[area].group].newsserv; *p1;)
          { if (isspace(*p1) || (*p1==','))
            { strcpy(p, ", ");
              p+=2;
            }
            while (isspace(*p1) || (*p1==',')) p1++;
            while ((*p1) && (!isspace(*p1)) && (*p1!=','))
              *p++=*p1++;
          }
          *p='\0';
          chkkludges;
          sprintf(pheader[cheader], "To: %s\n", str);
          nextline;
        }
        strcpy(str, group[echoes[area].group].distrib);
        if (!isfield("Distribution: "))
        { chkkludges;
          sprintf(pheader[cheader], "Distribution: %s\n", str);
          nextline;
        }
        if (!isfield("Organization: "))
        { chkkludge(strlen(organization));
          sprintf(pheader[cheader], "Organization: %s\n", organization);
          nextline;
        }
        if (!isfield("Newsgroups: "))
        { chkkludge(strlen(echoes[area].usenet));
          sprintf(pheader[cheader], "Newsgroups: %s\n", echoes[area].usenet);
          nextline;
        }
        continue;
      }
      firstline=0;
      if (strncmp(str, "SEEN-BY: ", 9)==0)
      {
        if (cont) cont=2;
        if ((area!=-1) && (group[echoes[area].group].sb==1))
        {
          chkkludges;
          sprintf(pheader[cheader], "X-FTN-%s", str);
          nextline;
        }
        continue;
      }
      if (strncmp(str, " * Origin: ", 11)==0 && !cont)
        origin_pos=imemtxt;
      else if (strcmp(str, "\n"))
      { origin_pos=-1;
        if (strncmp(str, "---", 3)==0 && !cont)
        { tear_len=strlen(str);
          tear_pos=imemtxt;
        }
        else
          tear_pos=-1; /* it was not tearline */
      }
      if ((origin_pos!=-1) && strcmp(str, "\n"))
        origin_len=strlen(str);
      else if ((area==-1) && (strchr(msghdr.to, '@')==NULL) &&
          (fromtext || !fromtop) &&
          (strnicmp(str, "To:", 3)==0) && strchr(str, '@') && gw_to[0]=='\0' &&
          ((!touucp) || stricmp(msghdr.to, "uucp")==0))
      { tofield(str+3, &to, &sizeto);
        continue;
      }
      else if ((area==-1) && (strchr(msghdr.to, '@')==NULL) &&
          (fromtext || !fromtop) &&
          (strnicmp(str, "GW-To:", 6)==0) && strchr(str, '@'))
      { to[0]='\0'; /* replace "To:" field */
        tofield(str+6, &gw_to, &sizegw_to);
        continue;
      }
      else if ((area==-1) && (strchr(msghdr.to, '@')==NULL) &&
          (fromtext || !fromtop) &&
          (strnicmp(str, "GW-Cc:", 6)==0) && strchr(str, '@'))
      { tofield(str+6, &gw_to, &sizegw_to);
        if (cont) cont=2; /* put to header */
        chkkludges;
        strcat(pheader[cheader-1], str+3);
        pheader[cheader]+=strlen(str+3);
        continue;
      }
      else if ((area==-1) && (strchr(msghdr.to, '@')==NULL) &&
          (fromtext || !fromtop) &&
          (strnicmp(str, "GW-Bcc:", 7)==0) && strchr(str, '@'))
      { tofield(str+7, &gw_to, &sizegw_to);
        if (cont) cont=1; /* don't put to header */
        continue;
      }
      /* copy header fields from message start to rfc-header */
      else if (fromtext)
      { if ((fromtext==2) && ((str[0]==' ') || (str[0]=='\t')))
        { /* add to previous header field */
          if (cont) cont=2;
          chkkludges;
          strcat(pheader[cheader-1], str);
          pheader[cheader]+=strlen(str);
          continue;
        }
        if (strnicmp(str, "Realname:", 9)==0)
        { chkkludges;
          sprintf(pheader[cheader], "X-FTN-%s", str);
          nextline;
          continue;
        }
        if (isupper(str[0]))
          switch (adduserline(str))
          { case 0: break;
            case 1: if (cont) cont=2;
                    fromtext=2;
                    debug(8, "Main: add to header %s", str);
                    continue; /* to header */
            case 2: if (cont) cont=1;   /* to /dev/null */
                    fromtext=2;
                    continue;
            case 3: p="Incorrect user headline";
                    goto lbadmsg;
          }
        if ((fromtext==2) && (strcmp(str, "\n")==0))
        { fromtext=0;
          continue;
        }
      }
      fromtext=0;
      /* all done, the rest simple copy */
      /* and count size and appropriate word length */
plaintext:
      if (cont) cont=3;
      while (imemtxt+strlen(str)>=msgbuflen)
      {
        char *p1=bufrealloc(memtxt, msgbuflen+=MINMSGLEN);
        if (p1==NULL)
        { logwrite('?', "Too large message in %s, move to badmail!\n", msgname);
          p="Too large message";
          goto lbadmsg;
        }
        memtxt=p1;
      }
      bufcopy(memtxt, imemtxt, str, strlen(str)+1);
      imemtxt+=strlen(str);
      for (p=str; *p; p++)
      { if (isspace(*p))
        { if (cword==0) continue;
          wlen+=cword;
          nwords++;
          cword=0;
        }
        else
          cword++;
      }
    }
    if (h==-1)
    { /* shit happens */
      if (memtxt) freebuf(memtxt);
      memtxt=NULL;
      return 0;
    }
    if (nwords==0)
      wlen=nwords=1; /* prevent division by zero */
    debug(9, "Main: nwords=%d, wlen=%d, wlen/nwords=%d", nwords, wlen, wlen/nwords);
    if (origin_pos!=-1)
    { if (area!=-1)
      { frombuf(str, memtxt, origin_pos, origin_len);
        str[origin_len] = '\0';
        p=strrchr(str+11, '(');
        if (p)
        { while (*(++p))
            if (isdigit(*p))
              break;
          if (*p)
            if (getfidoaddr(&u1, &u2, &u3, &u4, p)==0)
            { zone=u1;
              net=u2;
              node=u3;
              point=u4;
            }
        }
      }
      if (((area==-1) && (hideorigin & 1)) ||
          ((area!=-1) && (hideorigin & 2)))
      { /* Put X-FTN-Origin to header and don't put it to body */
        chkkludge(origin_len);
        strcpy(pheader[cheader], "X-FTN-");
        frombuf(pheader[cheader]+6, memtxt, origin_pos+3, origin_len);
        pheader[cheader][origin_len+3] = '\0';
        nextline;
        /* move origin_pos+origin_len to origin_pos, correct imemtxt */
        for (i=0; i<(int)(imemtxt-origin_pos-origin_len-sizeof(str)); i+=sizeof(str))
        { frombuf(str, memtxt, i+origin_pos+origin_len, sizeof(str));
          bufcopy(memtxt, i+origin_pos, str, sizeof(str));
        }
        if (imemtxt-origin_pos-origin_len-i>0)
        { frombuf(str, memtxt, i+origin_pos+origin_len, (int)(imemtxt-origin_pos-origin_len-i));
          bufcopy(memtxt, i+origin_len, str, (int)(imemtxt-origin_pos-origin_len-i));
        }
        imemtxt -= origin_len;
      }
    }
    if (tear_pos!=-1)
    { /* it was real tearline tearline */
      if (((area==-1) && (hidetear & 1)) ||
          ((area!=-1) && (hidetear & 2)))
      { /* Put X-FTN-Tearline to header and remove from memtxt */
        chkkludge(tear_len);
        strcpy(pheader[cheader], "X-FTN-Tearline: ");
        frombuf(pheader[cheader]+16, memtxt, tear_pos+3, tear_len);
        pheader[cheader][tear_len+13]='\0';
        nextline;
        /* move tear_pos+tear_len to tear_pos, correct imemtxt */
        for (i=0; i<(int)(imemtxt-tear_pos-tear_len-sizeof(str)); i+=sizeof(str))
        { frombuf(str, memtxt, i+tear_pos+tear_len, sizeof(str));
          bufcopy(memtxt, i+tear_pos, str, sizeof(str));
        }
        if (imemtxt-tear_pos-tear_len-i>0)
        { frombuf(str, memtxt, i+tear_pos+tear_len, (int)(imemtxt-tear_pos-tear_len-i));
          bufcopy(memtxt, i+tear_len, str, (int)(imemtxt-tear_pos-tear_len-i));
        }
        imemtxt -= tear_len;
      }
    }
#if 0
    if (tear_pos!=-1 || origin_pos!=-1)
    { char *newbuf = bufrealloc(memtxt, imemtxt); 
      if (newbuf) memtxt = newbuf;
    }
#endif
    curgate=ngates;
    if (area==-1)
    { /* once again process dest address from start */
      /* is this aka exists? */
      /* if pktdest is not our aka, check only routing */
      curaka=0;
      if (ourpkt)
      { /* our packet */
        for (i=0; i<naka; i++)
          if ((myaka[i].node==tonode) &&
              (myaka[i].net==tonet) &&
              (myaka[i].point==topoint) &&
              (myaka[i].zone==tozone)) break;
      }
      else
        i=naka;
      curaka=i;
      if (curaka==naka)
      { /* process all routing */
        for (i=0; i<ngates; i++)
        {
          if ((ourpkt && (gates[i].pktfor.zone==0)) ||
              ((gates[i].pktfor.zone==pktdest.zone) &&
               (gates[i].pktfor.net==pktdest.net) &&
               (gates[i].pktfor.node==pktdest.node) &&
               (gates[i].pktfor.point==pktdest.point)))
            if (checkmask(tozone, tonet, tonode, topoint,
                     gates[i].zone, gates[i].net, gates[i].node, gates[i].point))
            { if (gates[i].yes)
                curgate=i;
              else
                curgate=ngates;
            }
        }
        if (curgate==ngates)
        { if (packed)
          { logwrite('?', "Packed message not for me in %s, moved to badmail!\n",
                     msgname);
            badmsg("Packed message not for me");
          }
          if (memtxt) freebuf(memtxt);
          memtxt=NULL;
          return 0;
        }
        /* do aka matching */
        for (curaka=0; curaka<naka; curaka++)
          if (myaka[curaka].zone==tozone)
            break;
        if ((curaka==naka) && (tozone>0) && (tozone<7))
        /* find fidonet aka */
          for (curaka=0; curaka<naka; curaka++)
            if ((myaka[curaka].zone>0) && (myaka[curaka].zone<7))
              break;
        if (curaka==naka) curaka=0;
      }
    }
    debug(3, "Main: msg from '%s' %d:%d/%d.%d to '%s' %d:%d/%d.%d",
          msghdr.from, zone, net, node, point, msghdr.to,
          tozone, tonet, tonode, topoint);
    debug(6, "Main: using aka %d:%d/%d.%d",
          myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node, myaka[curaka].point);
    if (curgate!=ngates)
    { if ((attr & (msgIMM | msgDIRECT | msgCRASH)) && (!packed))
      { if (memtxt) freebuf(memtxt);
        memtxt=NULL;
        return 0;
      }
      debug(4, "Main: message to another gate");
      /* put address To */
      if ((strchr(msghdr.to, '@')==NULL) && to[0])
      { /* Put removed line "To:" */
        if (sizenagate==0)
          if ((nagate=malloc(sizenagate=128))==NULL)
            logwrite('!', "Not enough memory\n");
        for (p=to,p1=nagate; p1 && *p;)
        { if (isspace(*p) || (*p==','))
          { strcpy(p1, ", ");
            p1+=2;
            while (isspace(*p) || (*p==','))
              p++;
            continue;
          }
          *p1++=*p++;
          if (p1-nagate+3>=sizenagate)
          { char *newnagate=realloc(nagate, sizenagate+=128);
            if (newnagate==NULL)
            { logwrite('!', "Not enough memory for dest addr list, truncated\n");
              sizenagate-=128;
              break;
            }
            p1+=(newnagate-nagate);
            nagate=newnagate;
          }
        }
        *p1++='\0';
        { char c[128];
          int i=strlen(nagate);
          for (l=imemtxt-sizeof(c); l>0; l-=sizeof(c))
          { frombuf(c, memtxt, l, sizeof(c));
            bufcopy(memtxt, l+i+5, c, sizeof(c));
          }
          l+=sizeof(c);
          frombuf(c, memtxt, 0, (int)l);
          bufcopy(memtxt, i+5, c, (int)l);
          imemtxt+=i+5;
          bufcopy(memtxt, 0, "To: ", 4);
          bufcopy(memtxt, 4, nagate, i);
          bufcopy(memtxt, i+4, "\n", 1);
        }
      }
      /* todo: put removed Gw-To, Gw-Cc, Gw-Bcc */
      fido2rfc(to, msghdr.to, tozone, tonet, tonode, topoint, gates[curgate].domain);
      gw_to[0]='\0';
      debug(3, "Main: address is '%s'", to);
      /* process chdomain */
      for (i=0; i<ncdomain; i++)
      { if (strlen(to)<=strlen(cdomain[i].fido))
          continue;
        p=to+strlen(to)-strlen(cdomain[i].fido);
        if (stricmp(p, cdomain[i].fido))
          continue;
        strcpy(p, cdomain[i].relcom);
        /* add/remove '@' */
        if (strchr(cdomain[i].relcom, '@'))
        { p=strrchr(to, '@');
          for(p1=to; p1!=p; p1=strchr(p1, '@'))
            *p1='%';
        }
        if (strchr(cdomain[i].fido, '@'))
          if (strchr(to, '@')==0)
          { p=strrchr(to, '%');
            if (p) *p='@';
          }
        break;
      }
      debug(3, "Main: dest address after chdomain is '%s'", to);
    }

    if (gw_to[0])
    { tofield(gw_to, &to, &sizeto);
      gw_to[0]='\0';
    }

    if (to[0])
      debug(3, "Main: message to '%s'", to);

    txtsize=imemtxt;
    debug(8, "Main: text size is %ld", txtsize);

    if ((area==-1) && (curgate<ngates) && (attr & msgFILEATT))
    { if (packed)
      { logwrite('?', "Can't send fileattach to another gate, use attuucp\n");
        badmsg("FileAttach to another gate");
      }
      if (memtxt) freebuf(memtxt);
      memtxt=NULL;
      return 0;
    }

    if ((area==-1) && (to[0]==0))
    { logwrite('?', "Incorrect To address in %s, message moved to badmail!\n", msgname);
      genlett(NOADDR, msghdr.from, zone, net, node, point, 0);
      genlett(NOADDR, master, mastzone, mastnet, mastnode, mastpoint, 1);
      badmsg("Incorrect TO address");
      if (memtxt) freebuf(memtxt);
      memtxt=NULL;
      return 0;
    }

    /* find upaka */
    if (area==-1)
    { if (tozone!=uplink[upaka].zone)
      { for (i=0; i<nuplink; i++)
          if (uplink[i].zone==tozone)
            break;
        if (i==nuplink)
        { for (i=0; i<nuplink; i++)
            if (packed && (tozone>0) && (tozone<7) &&
               (uplink[upaka].zone>0) && (uplink[upaka].zone<7))
              break;
          if (i==nuplink) i=0;
        }
        upaka=i;
      }
    }
    debug(4, "Main: uplink aka is %d:%d/%d.%d",
          uplink[upaka].zone, uplink[upaka].net, uplink[upaka].node, uplink[upaka].point);

    /* change address by chaddr= */
    achanged=0;
    if (curgate==ngates)
      for (i=0; i<ncaddr; i++)
      { if ((stricmp(msghdr.from, caddr[i].from)==0) &&
           (caddr[i].zone==zone) && (caddr[i].net==net) &&
           (caddr[i].node==node) && (caddr[i].point==point))
        { strcpy(from, caddr[i].to);
          achanged=1;
          debug(3, "Main: from-address changed to %s", from);
          break;
        }
      }
    if (achanged==0)
    { /* change address */
      strcpy(from, msghdr.from);
      if (strchr(from, '@')==NULL)
        fido2rfc(from, msghdr.from, zone, net, node, point, myaka[curaka].domain);
      else if ((from[0]=='@') || (from[0]=='%'))
      { from[0]='_';
        if (curgate!=ngates)
          if (gates[curgate].yes==2) /* ifmail */
            from[0]='.';
        strcpy(from+1, msghdr.from);
      }
      debug(4, "Main: from-address is %s", from);
    }

    if ((area!=-1) || (curgate==ngates))
    {
      /* external checking */
      if (nagate) nagate[0]=0;
      if (nafig)  nafig[0]=0;
      rejreason=NOADDR;
      for (p=to,p1=NULL; p; p=p1)
      {
        if (p1) *p1=' ';
        while (isspace(*p) || (*p==',')) p++;
        p1=strpbrk(p, " ,");
        if (p1) *p1='\0';
        xstrcpy(&curto, &sizecurto, p);
        debug(5, "To-address is '%s'", curto);
        if ((curto[0]=='<') && (curto[strlen(curto)-1]=='>'))
        { strcpy(curto, curto+1);
          curto[strlen(curto)-1]='\0';
        }
        if (curto[0]==0)
          xstrcpy(&curto, &sizecurto, msghdr.to);
        if (strpbrk(curto, "<>"))
        { /* prevent security hole */
          char *p, *p1=NULL;

          p=strchr(curto, '<');
          if (p) p1=strchr(p, '>');
#if 0
          if (p==NULL || p1==NULL)
          { xstrcat(&nafig, &sizenafig, curto);
            continue;
          }
          *p1='\0';
          strcpy(curto, p+1);
#else
          if (p && p1)
          { *p1='\0';
            strcpy(curto, p+1);
          }
#endif
        }
        if (curto[0]==0)
          xstrcpy(&curto, &sizecurto, "All");
        debug(6, "Main: run external checker");
        r=extcheck(curto, &area);
        debug(6, "Main: external checker retcode %d", r);
        if (r==0) /* drop */
        { if (area==-1)
          { if (point)
              logwrite('?', "Message from %s %u:%u/%u.%u to %s moved to /dev/null\n",
                       msghdr.from, zone, net, node, point, curto);
            else
              logwrite('?', "Message from %s %u:%u/%u to %s moved to /dev/null\n",
                       msghdr.from, zone, net, node, curto);
          }
          else
          { if (point)
              logwrite('?', "Message from %s %u:%u/%u.%u to %s in area %s moved to /dev/null\n",
                    msghdr.from, zone, net, node, point, curto, echoes[area].fido);
            else
              logwrite('?', "Message from %s %u:%u/%u to %s in area %s moved to /dev/null\n",
                    msghdr.from, zone, net, node, curto, echoes[area].fido);
          }
          rejreason=EXTERNAL;
          continue;
        }
        if ((r==1) && (area==-1)) /* reject */
        { rejreason=EXTERNAL;
          xstrcat(&nafig, &sizenafig, curto);
          continue;
        }
        if (r==2) /* free */
        { xstrcat(&nagate, &sizenagate, curto);
          continue;
        }
        /* the rest is normal */
        if (area==-1)
        {
          debug(8, "Main: check twit, size, dest_addr, binary");
          if (strchr(curto, '@') == NULL)
            continue;
          /* check again if we should send it */
          /* at first for privel address, then for twit, size, dest addr and binary */
          for (i=0; i<npaddr; i++)
          { if (checkmask(zone, net, node, point, paddr[i].zone, paddr[i].net,
                paddr[i].node, paddr[i].point))
              if ((stricmp(msghdr.from, paddr[i].from)==0) || (paddr[i].from[0]==0))
                break;
          }
          if (i==npaddr)
          { /* not privel address */
            for (i=0; i<ntwit; i++)
            { if (checkmask(zone, net, node, point, twit[i].zone, twit[i].net,
                  twit[i].node, twit[i].point))
                if ((stricmp(msghdr.from, twit[i].from)==0) || (twit[i].from[0]==0))
                  break;
            }
            if (i<ntwit)
            { /* check twit */
              for (i=0; i<nnotwit; i++)
              { if (checkmask(zone, net, node, point, notwit[i].zone, notwit[i].net,
                    notwit[i].node, notwit[i].point))
                  if ((stricmp(msghdr.from, notwit[i].from)==0) || (notwit[i].from[0]==0))
                    break;
              }
              if (i==nnotwit)
              { rejreason=TWITADDR;
                xstrcat(&nafig, &sizenafig, curto);
                continue;
              }
            }
            if (attr & msgFILEATT)
            { for (i=0; i<nattfrom; i++)
              { if (checkmask(zone, net, node, point, attfrom[i].zone, attfrom[i].net,
                    attfrom[i].node, attfrom[i].point))
                  if ((stricmp(msghdr.from, attfrom[i].from)==0) || (attfrom[i].from[0]==0))
                    break;
              }
              if (i==nattfrom)
              { rejreason=FILEATT;
                xstrcat(&nafig, &sizenafig, curto);
                continue;
              }
            }
            /* check 'to' addresses list */
            r=checkaddr(curto);
            if (r==0) /* not address */
              continue;
            if (r==1) /* reject */
            { rejreason=DEST;
              xstrcat(&nafig, &sizenafig, curto);
              continue;
            }
            if (r==2) /* free */
            { xstrcat(&nagate, &sizenagate, curto);
              continue;
            }
            /* the rest is ok */
            /* size */
            if ((maxsize!=0) && (txtsize>maxsize*1024l))
            { rejreason=SIZE;
              xstrcat(&nafig, &sizenafig, curto);
              continue;
            }
            /* binary */
            if (nwords>5)
              if ((wlen/nwords>MAXWLEN) && (uucode==0))
              { rejreason=BINARY;
                xstrcat(&nafig, &sizenafig, curto);
                continue;
              }
            xstrcat(&nagate, &sizenagate, curto);
          } /* not privel */
          else
          { xstrcat(&nagate, &sizenagate, curto);
            continue;
          }
        } /* netmail */
        else
        { xstrcat(&nagate, &sizenagate, curto);
          continue;
        }
      } /* to-addresses loop */
      debug(3, "Main: nagate='%s', nafig='%s'",
            nagate ? nagate : "", nafig ? nafig : "");
      if ((nafig && nafig[0]) || nagate==NULL || nagate[0]==0)
      { if ((nafig && nafig[0]) || rejreason==NOADDR)
          reject(rejreason, nafig ? nafig : "");
      }
      else
        rejreason=0;
      if (!nagate || nagate[0]==0)
      { badmsg(strreason(rejreason, 2));
        if (memtxt) freebuf(memtxt);
        memtxt=NULL;
        return 0;
      }
      *to='\0';
      tofield(nagate ? nagate : "", &to, &sizeto);
    }

    set_table(myintsetname);

    if (area!=-1)
    { /* add own address to path */
      debug(8, "Main: add to Path");
      curaka=group[echoes[area].group].aka;
      if ((npath!=MAX_PATH) && (myaka[curaka].point==0))
      {
        for (k=npath; k>0; k--)
          memcpy(path+k, path+k-1, sizeof(path[0]));
        path[0].net=myaka[curaka].net;
        path[0].node=myaka[curaka].node;
        npath++;
      }
      if ((group[echoes[area].group].type==G_CNEWS) ||
          (group[echoes[area].group].type==G_DIR))
      { sprintf(pheader[cheader], "Path: %s!", local);
        p=pheader[cheader]+strlen(pheader[cheader]);
        for (i=0; i<npath; i++)
        {
          if ((p+ZAPAS>header+MAXHEADER) ||
              (cheader>=MAXFIELDS))
          { logwrite('?', "Too many kludges, messages moved to badmail!\n");
            p="Too many kludges";
            goto lbadmsg;
          }
          sprintf(p, "f%u.n%u.z%u", path[i].node, path[i].net, uplink[upaka].zone);
          if (group[echoes[area].group].domain[0])
          {
            strcat(p, ".");
            strcat(p, group[echoes[area].group].domain);
          }
          strcat(p, "!");
          p+=strlen(p);
        }
        strcpy(p, "not-for-mail\n");
        nextline;
      }
    }
    if (area!=-1)
    { strcpy(str, echoes[area].fido);
      if (point)
        logwrite('-', "Area: %s, From %s %u:%u/%u.%u\tto %s\n",
                 str, msghdr.from, zone, net, node, point, to);
      else
        logwrite('-', "Area: %s, From %s %u:%u/%u\tto %s\n",
                 str, msghdr.from, zone, net, node, to);
    }
    /* Put header */
    /* Add own received */
    if (area==-1)
    { if (!packed)
      {
        debug(8, "Main: add received");
        if ((pheader[cheader]+128>header+MAXHEADER) ||
            (cheader>=MAXFIELDS))
        { logwrite('?', "Too many kludges, messages moved to badmail!\n");
          p="Too many kludges";
          goto lbadmsg;
        }
        sprintf(pheader[cheader], "Received: by ");
        p=pheader[cheader]+strlen(pheader[cheader]);
        sprintf(p, "%u:%u/%u", uplink[upaka].zone,
                uplink[upaka].net, uplink[upaka].node);
        p+=strlen(p);
        if (uplink[upaka].point)
        { sprintf(p, ".%u", uplink[upaka].point);
          p+=strlen(p);
        }
        sprintf(p, "@%s", myaka[curaka].domain);
        p=strpbrk(p+1, "%@");
        if (p) *p=0;
        p=pheader[cheader]+strlen(pheader[cheader]);
        sprintf(p, "; %s, %2u %s %u %02u:%02u:%02u %c%02u00\n",
          weekday[curtm->tm_wday], curtm->tm_mday, montable[curtm->tm_mon],
          curtm->tm_year+1900, curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          (tz<=0) ? '+' : '-', (tz>0) ? tz : -tz);
        nextline;
      }
      if ((curgate==ngates) || gatevia)
      { /* dont put own via if gatevia=no via and double-gating */
        if ((pheader[cheader]+128>header+MAXHEADER) ||
            (cheader>=MAXFIELDS))
        { logwrite('?', "Too many kludges, messages moved to badmail!\n");
          p="Too many kludges";
          goto lbadmsg;
        }
        sprintf(pheader[cheader], "Received: by ");
        p=pheader[cheader]+strlen(pheader[cheader]);
        sprintf(p, NAZVA " %u:%u/%u", myaka[curaka].zone,
                myaka[curaka].net, myaka[curaka].node);
        p+=strlen(p);
        if (myaka[curaka].point)
        { sprintf(p, ".%u", myaka[curaka].point);
          p+=strlen(p);
        }
        sprintf(p, "@%s", myaka[curaka].domain);
        p=strpbrk(p+1, "%@");
        if (p) *p=0;
        p=pheader[cheader]+strlen(pheader[cheader]);
        sprintf(p, "; %s, %2u %s %u %02u:%02u:%02u %c%02u00\n",
          weekday[curtm->tm_wday],
          curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year+1900,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          (tz<=0) ? '+' : '-', (tz>0) ? tz : -tz);
        nextline;
      }
    }
    /* count received */
    for (currcv=i=0; i<cheader; i++)
      if (strncmp(pheader[i], "Received: ", 10)==0)
        currcv++;
    debug(8, "Main: received counter is %d", currcv);
    /* Sort header fields, 'received' to start and in reverse order */
    if ((curgate==ngates) && rcv2via && ((maxrcv==0) || (currcv<=maxrcv)))
    { for (i=0; i<cheader; i++)
      { if (strncmp(pheader[i], "Received: ", 10)==0)
        { p=pheader[i];
          for (k=i; k>0; k--)
            pheader[k]=pheader[k-1];
          pheader[0]=p;
        }
        if (strncmp(pheader[i], "X-FTN-Recd:", 11)==0)
          pheader[i][0]='\0'; /* todo(?): convert to "Received: from ... */
      }
    }
    else /* route-to/to-ifmail or !rcv2via or all more then max-received */
      /* change "received: by" to "x-ftn-via:" */
      for (i=0; i<cheader; i++)
        if (strncmp(pheader[i], "Received: by ", 13)==0)
        { strcpy(pheader[i], "X-FTN-Via: ");
          strcpy(pheader[i]+11, pheader[i]+13);
        }
    if ((curgate==ngates) && (!savehdr))
    { /* remove all x-ftn */
      for (i=0; i<cheader; i++)
      { if (strnicmp(pheader[i], "X-FTN-", 6))
          continue;
        if (strnicmp(pheader[i], "X-FTN-REPLY:", 12)==0)
          continue;
        if (strnicmp(pheader[i], "X-FTN-PID:", 10)==0)
          continue;
        if (strnicmp(pheader[i], "X-FTN-SEEN-BY: ", 15)==0)
          if (area!=-1)
            if (group[echoes[area].group].sb)
              continue;
        pheader[i][0]=0;
      }
    }
    /* change X-FTN-PID to X-Mailer if not to-ifmail */
    if ((curgate==ngates) || (gates[curgate].yes!=2) || (area!=-1))
    { for (i=0; i<cheader; i++)
      { if (strnicmp(pheader[i], "X-FTN-PID:", 10)==0)
        { if (area==-1)
          { strcpy(pheader[i], "X-Mailer:");
            strcpy(pheader[i]+9, pheader[i]+10);
          }
          else
          { memmove(pheader[i]+13, pheader[i]+10, strlen(pheader[i]+10)+1);
            memcpy(pheader[i], "X-Newsreader:", 13);
          }
          continue;
        }
        if (strnicmp(pheader[i], "X-FTN-REPLY:", 12)==0)
          pheader[i][0]=0;
      }
    }
    else
      for (i=0; i<cheader-1; i++)
        if (strnicmp(pheader[i], "X-FTN-REPLY:", 12)==0)
          if (strnicmp(pheader[i+1], "References:", 11)==0)
            pheader[i+1][0]=0;
    /* remove x-ftn-*, if chaddr and netmail */
    if ((area==-1) && (achanged))
      for (i=0; i<cheader; i++)
        if (strnicmp(pheader[i], "X-FTN-", 6)==0)
          pheader[i][0]=0;
    /* remove Content-Length and Lines (we will put own) */
#ifdef __MSDOS__
    /* under msdos put own only with cnews */
    /* so don't remove in other cases */
    if (area!=-1 &&
        (group[echoes[area].group].type==G_DIR ||
         group[echoes[area].group].type==G_CNEWS))
#endif
      for (i=0; i<cheader; i++)
        if ((strnicmp(pheader[i], "Content-Length:", 15)==0) ||
            (strnicmp(pheader[i], "Lines:", 6)==0))
          pheader[i][0]=0;
    /* remove all empty fields */
    for (i=0; i<cheader; i++)
      if (pheader[i][0]==0)
      { for (k=i; k<cheader-1; k++)
          pheader[k]=pheader[k+1];
        cheader--;
        i--;
      }

    if ((area==-1) || (group[echoes[area].group].type==G_FEED))
      rclose();
    /* Put header to file */
    for (i=strlen(msghdr.from)-1; i>=0; i--)
    { if ((msghdr.from[i]!=' ') &&
          (msghdr.from[i]!='\t') &&
          (msghdr.from[i]!='\n'))
        break;
      msghdr.from[i]=0;
    }
    debug(3, "Main: put header to virt file");
    fout=virt_fopen(tmpout, "wb+");
    if (fout==NULL)
    { logwrite('?', "Can't open temporary file %s!\n", tmpout);
      retcode|=RET_ERR;
      badmsg("Can't open temp file");
      if (memtxt) freebuf(memtxt);
      memtxt=NULL;
      return 0;
    }

#ifndef UNIX
    if ((area==-1) || (group[echoes[area].group].type==G_FEED))
    {
#ifdef __MSDOS__
      if ((uupcver!=SENDMAIL) && (uupcver!=KENDRA))
      { virt_fputs("rmail\n--\n", fout); /* end of switches */
        if (area!=-1)
          virt_fprintf(fout, "%s\n", group[echoes[area].group].newsserv);
        else
        { p=to;
          while (p)
          { while (*p==' ') p++;
            if (*p==0) break;
            p1=strchr(p, ' ');
            if (p1) *p1=0;
            /* aliases */
            for (i=0; i<nalias; i++)
              if (stricmp(p, alias[i].from)==0) break;
            if (i==nalias)
              virt_fputs(p, fout);
            else
            { debug(4, "Main: %s is alias to %s", p, alias[i].to);
              virt_fputs(alias[i].to, fout);
            }
            virt_putc('\n', fout);
            if (p1) *p1=' ';
            p=p1;
          }
        }
        virt_fputs("<<NULL>>\n", fout);
      }
#endif
      if (uupcver!=SENDMAIL)
      { virt_fprintf(fout, "From ");
        /* From fidonet!f68.n463.z2.fidonet.org!Pavel_Gulchouck Wed Nov 30
           12:23:45 1994 remote from luckyua */
        if (area==-1)
        { if (env_chaddr && achanged)
          { strncpy(str, from, sizeof(str));
            getaddr(str);
          }
          else if (bangfrom)
          { virt_fprintf(fout, "%s!", fidosystem);
            if (point)
              virt_fprintf(fout, "p%u.", point);
            strcpy(str, myaka[curaka].domain);
            p=strpbrk(str, "@%");
            if (p) *p=0;
            virt_fprintf(fout, "f%u.n%u.z%u.%s!", node, net, zone, str);
            strncpy(str, msghdr.from, sizeof(msghdr.from));
            str[sizeof(msghdr.from)]=0;
            mkusername(str);
          }
          else
          { strncpy(str, msghdr.from, sizeof(msghdr.from));
            str[sizeof(msghdr.from)]=0;
            mkusername(str);
            p=strpbrk(myaka[curaka].domain, "@%");
            strcat(str, p ? "%" : "@");
            if (point)
              sprintf(str+strlen(str), "p%u.", point);
            sprintf(str+strlen(str), "f%u.n%u.z%u.%s",
                    node, net, zone, myaka[curaka].domain);
          }
        }
        else
        { p=strchr(gatemaster, '@');
          if (p && bangfrom)
          { *p='\0';
            sprintf(str, "%s!%s", p+1, gatemaster);
            *p='@';
          }
          else
            strcpy(str, gatemaster);
        }
        virt_fprintf(fout, "%s", str);
        virt_fprintf(fout, " %s %s %02u %02u:%02u:%02u %02u",
          weekday[curtm->tm_wday],
          montable[curtm->tm_mon], curtm->tm_mday,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec, curtm->tm_year+1900);
        if (bangfrom)
        { if (virt_fprintf(fout, " remote from %s\n", local)==EOF)
            goto errwrite1;
        }
        else
        { if (virt_putc('\n', fout)==EOF)
            goto errwrite1;
        }
      }
    }
#endif
    for (i=0; i<cheader; i++)
    {
      if (strnicmp(pheader[i], "Received: by ", 13)==0)
      { convrcv(pheader[i]+13, str);
        if (str[0]=='\0')
          pheader[i][0]='\0';
        else
        { int2ext(str);
          if (virt_fputs(str, fout)==EOF)
            goto errwrite1;
        }
      }
      else
      { char *p1;
        int2ext(pheader[i]);
        p=qphdr(pheader[i]);
        for (p1=p; *p1; p1++)
          if (*p1 & 0x80) wascyr=1;
        if (virt_fputs(p, fout)==EOF)
          goto errwrite1;
        if (p!=pheader[i])
          free(p);
      }
    }
    /* 2nd pass */
    /* Add To:, From:, Subject:, Date: */
    /* Message-Id: (if no), Return-Receipt-To: (if needed) */
    if ((achanged ||
        isfield("From: ")) && (curgate==ngates) && (strchr(msghdr.from, '@')==NULL))
    { if (point)
      { if (virt_fprintf(fout, "X-FTN-Addr: %u:%u/%u.%u\n", zone, net, node, point)==EOF)
          goto errwrite1;
      }
      else
        if (virt_fprintf(fout, "X-FTN-Addr: %u:%u/%u\n", zone, net, node)==EOF)
          goto errwrite1;
      if (virt_fprintf(fout, "X-FTN-From: %s\n", msghdr.from)==EOF)
        goto errwrite1;
    }
    int2ext(from);
    if (!isfield("From: "))
    { char *p1;
      sprintf(str, "From: %s\n", from);
      p=qphdr(str);
      for (p1=p; *p1; p1++)
        if (*p1 & 0x80) wascyr=1;
      if (virt_fputs(p, fout)==EOF)
        goto errwrite1;
      if (p!=str) free(p);
    }
    if (!isfield("Subject: "))
    { strcpy(str, "Subject: ");
      if (attr & msgFILEATT)
      { /* remove pathes to files */
        char c, *p1, *p2;
        for (p=msghdr.subj; *p; p=p1)
        { while (isspace(*p) && (p-msghdr.subj<sizeof(msghdr.subj))) p++;
          if (*p=='\0') break;
          if (p-msghdr.subj>=sizeof(msghdr.subj))
            break;
          for (p1=p; *p1 && !isspace(*p1); p1++)
            if (p1-msghdr.subj>=sizeof(msghdr.subj))
              break;
          c=*p1;
          *p1='\0';
          p2=strrchr(p, '/');
          if (p2) p=p2+1;
#ifndef UNIX
          p2=strrchr(p, '\\');
          if (p2) p=p2+1;
          p2=strrchr(p, ':');
          if (p2) p=p2+1;
#endif
          if (str[strlen(str)-1]!=' ')
            strcat(str, " ");
          strcat(str, p);
          *p1=c;
        }
      }
      else
      { strncpy(str+9, msghdr.subj, sizeof(msghdr.subj));
        str[sizeof(msghdr.subj)+9]=0;
      }
      for (p=str+9 ;*p && isspace(*p); p++);
      if ((*p==0) && (area!=-1))
        strcat(str, NOSUBJ);
      if (str[9])
      { char *p1;
        strcat(str, "\n");
        int2ext(str);
        p=qphdr(str);
        for (p1=p; *p1; p1++)
          if (*p1 & 0x80) wascyr=1;
        if (virt_fputs(p, fout)==EOF)
          goto errwrite1;
        if (p!=str) free(p);
      }
    }
    if (attr & (msgRETRECREQ | msgCFM))
/* Put Return-Receipt-To even if to-ifmail
      if ((curgate==ngates) || (gates[curgate].yes!=2))
*/
        if (!isfield("Return-Receipt-To: "))
        { char *p1;
          sprintf(str, "Return-Receipt-To: %s\n", from);
          p=qphdr(str);
          for (p1=p; *p1; p1++)
            if (*p1 & 0x80) wascyr=1;
          if (virt_fputs(p, fout)==EOF)
            goto errwrite1;
          if (p!=str) free(p);
        }
    if (!isfield("X-FTN-Flags: "))
      if (curgate!=ngates)
        if (gates[curgate].yes==2)
          if (attr)
          { virt_fprintf(fout, "X-FTN-Flags:");
            if (attr & msgPRIVATE)   virt_fputs(" PVT", fout);
            if (attr & msgKILLSENT)  virt_fputs(" K/S", fout);
            if (attr & msgDIRECT)    virt_fputs(" DIR", fout);
            if (attr & msgRETRECREQ) virt_fputs(" RRQ", fout);
            if (attr & msgRETREC)    virt_fputs(" RRC", fout);
            if (attr & msgAUDITTR)   virt_fputs(" ARQ", fout);
            if (attr & msgUPREQ)     virt_fputs(" FPU", fout);
            if (attr & msgCFM)       virt_fputs(" CFM", fout);
            if (attr & msgTFS)       virt_fputs(" TFS", fout);
            if (attr & msgKFS)       virt_fputs(" KFS", fout);
            if (attr & msgLOCAL)     virt_fputs(" LOC", fout);
            if (attr & msgFORWD)     virt_fputs(" TRS", fout);
            if (virt_putc('\n', fout)==EOF)
              goto errwrite1;
          }
    if (msgid[0]==0)
    {
      if (fscmsgid)
      { sprintf(msgid+8, "%u-%u-%u-", zone, net, node);
        if (point)
          sprintf(msgid+strlen(msgid), "%u-", point);
        sprintf(msgid+strlen(msgid), "%08lx",
                (time(NULL)*100ul+getpid()%100+seqf++) & 0xfffffffful);
        strcat(msgid, "@");
      }
      else /* ifmail-style */
      { sprintf(msgid, "%08lx", (time(NULL)*100ul+getpid()%100+seqf++) & 0xfffffffful);
        msgid[8]='@';
        if (point)
          sprintf(msgid+9, "p%u.f%u.n%u.z%u.", point, node, net, zone);
        else
          sprintf(msgid+9, "f%u.n%u.z%u.", node, net, zone);
      }
    }
    if (rfcid==0)
    { if ((zone>0) && (zone<7))
        strcat(msgid, "fidonet.org");
      else
      { p=msgid+strlen(msgid);
        strcpy(p, myaka[curaka].domain);
        p=strpbrk(p, "%@");
        if (p) *p=0;
      }
    }
    if (area!=-1 && group[echoes[area].group].extmsgid)
    { char *p1=strstr(msgid, echoes[area].usenet);
      if (p1) p=p1+strlen(echoes[area].usenet);
      if ((p1==NULL || (*(p1-1)!='|' && *(p1-1)!='<') || *p!='|') &&
          strlen(msgid)+strlen(echoes[area].usenet)+1<sizeof(msgid))
      { int i=strlen(echoes[area].usenet);
        for (p=msgid+strlen(msgid); p>=msgid; p--) p[i+1] = p[0];
        /* memmove(msgid+strlen(echoes[area].usenet)+1, msgid, strlen(msgid));*/
        strcpy(msgid, echoes[area].usenet);
        msgid[i]='|';
      }
    }
    if (!isfield("Message-Id:"))
    { if (virt_fprintf(fout, "Message-Id: <%s>\n", msgid)==EOF)
        goto errwrite1;
      debug(11, "Main: set message-id <%s>", msgid);
    }
    if (!isfield("Date: "))
    { /* try to parse Date */
      dateftn2rfc(msghdr.date, str, msgtz ? msgtz : tz);
      if (virt_fprintf(fout, "Date: %s\n", str)==EOF)
        goto errwrite1;
    }
    if (!isfield("Approved: "))
      if (area!=-1)
      { for (i=0; i<nmoder; i++)
          if (moderator[i].echo==area)
            break;
        if (i!=nmoder)
          if (virt_fprintf(fout, "Approved: %s\n", moderator[i].moderator)==EOF)
            goto errwrite1;
      }
    if (!isfield("Errors-To: "))
      if (area!=-1)
        if (group[echoes[area].group].type==G_FEED)
          if (virt_fprintf(fout, "Errors-To: %s\n", gatemaster)==EOF)
            goto errwrite1;
    if (area!=-1)
    { int2ext(to);
      if (stricmp(to, "all") && stricmp(to, "uucp"))
      { char *p;
        if (xcomment)
        { char *p1;
          sprintf(str, "X-Comment-To: %s\n", to);
          p=qphdr(str);
          for (p1=p; *p1; p1++)
            if (*p1 & 0x80) wascyr=1;
        }
        else
        { /*
          sprintf(str, "\nTo: %s\n", to);
          */
          str[0]='\0';
          p=str;
        }
        if (virt_fputs(p, fout)==EOF)
          goto errwrite1;
        if (p!=str) free(p);
      }
    }
    else if (!isfield("To:"))
    { for (p=to,p1=nagate; *p;)
      { if (isspace(*p) || (*p==','))
        { strcpy(p1, ", ");
          p1+=2;
          while (isspace(*p) || (*p==','))
            p++;
          continue;
        }
        *p1++=*p++;
      }
      *p1++='\0';
      strcpy(to, nagate);
      p=NULL;
      /* if togate and user%domain1@domain2 - strip domain2 */
      if (curgate!=ngates)
        if (strchr(gates[curgate].domain, '@'))
        { p=strchr(to, '@');
          *p=0;
          p1=strrchr(to, '%');
          if (p1) *p1='@';
        }
      if ((strchr(msghdr.to, '@')==NULL) && stricmp(msghdr.to, "uucp"))
        sprintf(str, "To: %s (%s)\n", to, msghdr.to);
      else
        sprintf(str, "To: %s\n", to);
      int2ext(str);
      { char *p1, *p=qphdr(str);
        for (p1=p; *p1; p1++)
          if (*p1 & 0x80) wascyr=1;
        if (virt_fputs(p, fout)==EOF)
          goto errwrite1;
        if (p!=str) free(p);
      }
      if (p)
      { *p='@';
        if (p1) *p1='%';
      }
    }
    if (!isfield("Content-Type:"))
#if 0
      if (wascyr || (attr & msgFILEATT))
#endif
      { if (!isfield("Mime-Version:"))
          virt_fprintf(fout, "Mime-Version: 1.0\n");
        if (attr & msgFILEATT)
        { sprintf(bound, "%ld%d/%s", (unsigned long)time(NULL), seqf++, local);
          virt_fprintf(fout, "Content-Type: multipart/mixed; boundary=\"%s\"\n", bound);
          if (virt_putc('\n', fout)==EOF)
            goto errwrite1;
          virt_fprintf(fout, "This message is in MIME format\n\n");
          if (virt_fprintf(fout, "--%s\n", bound)==EOF)
            goto errwrite1;
        }
        if (virt_fprintf(fout, "Content-Type: text/plain; charset=%s\n",
                    wascyr ? myextsetname : "us-ascii")==EOF)
          goto errwrite1;
        if (!isfield("Content-Transfer-Encoding:"))
          if (virt_fprintf(fout, "Content-Transfer-Encoding: %s\n",
                    wascyr ? "8bit" : "7bit")==EOF)
            goto errwrite1;
      }
    if ((area!=-1) && stricmp(to, "all") && !xcomment)
      if (virt_fprintf(fout, "\nTo: %s\n", to)==EOF)
        goto errwrite1;
    if (virt_putc('\n', fout)==EOF)
      goto errwrite1;
    /* Done, now we need only copy message body */
    debug(6, "Main: put message body, size %lu", txtsize);
    begline=1;
    p=str;
    imemtxt=0; /* total size saved in txtsize */
    while (memgets(p, sizeof(str)-(unsigned)(p-str))/* || (begline==0)*/)
    { int2ext(p);
#ifdef __OS2__
      if (str[0]=='\x1a')
        str[0]=' '; /* pipe! '\x1a' is EOF :-( */
#endif
      if (curgate!=ngates)
      { /* do not split lines */
        if (virt_fputs(str, fout)==EOF)
          goto errwrite1;
        continue;
      }
      if (begline)
      { if (strncmp(str, "From ", 5)==0)
        { virt_putc('>', fout);
          pref[0]=0;
        }
        else
        { p=str;
          for (p1=memchr(p, '>', MAXBEGPREF); p1; p1=memchr(p, '>', MAXBEGPREF))
          { if ((p1-str>MAXPREFIX) || (strlen(p)<(p1-p)))
              break;
            p=p1+1;
          }
          if (p!=str)
          { *--p=0;
            strcpy(pref, str);
            *p='>';
            strcat(pref, "> ");
          }
          else
            pref[0]=0;
        }
      }
      do
      {
        if ((p=strchr(str, '\n'))!=NULL)
          begline=1;
        else
        { p=str+strlen(str);
          begline=0;
        }
        if (p-str<=maxline)
        { if (virt_fputs(str, fout)==EOF)
          {
errwrite1:  r=errno;
            virt_fclose(fout);
            fout=NULL;
            if (area==-1)
            { logwrite('?', "Can't write to file: %s!\n", strerror(r));
              badmsg("Can't write to output file");
              if (memtxt) freebuf(memtxt);
              memtxt=NULL;
              return 0;
            }
errwrite2:
            badpkt();
            if (r)
            { if (r>=0)
                logwrite('?', "Can't write to file: %s!\n", strerror(r));
              else /* fucking Watcom RTL! */
                logwrite('?', "Can't write to pipe!\n");
            }
            if (memtxt) freebuf(memtxt);
            memtxt=NULL;
            return retcode|=RET_ERR;
          }
          str[0]='\0';
          break;
        }
        p=str+maxline;
        while ((*p!=' ') && (p!=str+strlen(pref)+5)) p--;
        if (p==str+strlen(pref)+5)
        { for (p=str+maxline; *p && (*p!=' ') && (p<str+maxline+20); p++);
          if (p==str+maxline+20) p=str+strlen(pref)+5;
          else if (*p=='\0')
          { if (virt_fputs(str, fout)==EOF)
              goto errwrite1;
            str[0]='\0';
            break;
          }
        }
        if (p!=str+strlen(pref)+5)
        { *p=0;
          if (virt_fputs(str, fout)==EOF)
            goto errwrite1;
          virt_putc('\n', fout);
          strcpy(str, pref);
          strcat(str, p+1);
          continue;
        }
        p=str+maxline;
        c=*p;
        *p=0;
        if (virt_fputs(str, fout)==EOF)
          goto errwrite1;
        virt_putc('\n', fout);
        *p=c;
        strcpy(str, pref);
        strcat(str, p);
      }
      while (begline);
      p=str+strlen(str);
    }
    if (attr & msgFILEATT)
    { /* write files */
      strncpy(filelist, msghdr.subj, sizeof(msghdr.subj));
      filelist[sizeof(msghdr.subj)]='\0';
      putfiles(fout, msghdr.subj, bound);
      virt_fprintf(fout, "\n--%s--\n", bound);
    }
    virt_rewind(fout);
    freebuf(memtxt);
    memtxt=NULL;
    if (area!=-1)
      strcpy(to, group[echoes[area].group].newsserv);
    if ((area!=-1) && ((group[echoes[area].group].type==G_CNEWS) ||
        (group[echoes[area].group].type==G_DIR)))
    {
      debug(4, "Main: call rsend");
      if (rsend(to, fout, group[echoes[area].group].type))
      {
        virt_fclose(fout);
        fout=NULL;
        r=0;
        goto errwrite2;
      }
      virt_fclose(fout);
      fout=NULL;
    }
    else
    {
      if (cmdline) *cmdline = '\0';
      xstrcat(&cmdline, &sizecmdline, rmail);
#ifndef UNIX
      if ((uupcver!=SENDMAIL) && (uupcver!=KENDRA))
#ifdef __MSDOS__
        xstrcat(&cmdline, &sizecmdline, "-l -u");
      else
#else
        xstrcat(&cmdline, &sizecmdline, "-u");
#endif
      {
        if (uupcver==SENDMAIL)
#else /* UNIX */
      {
#endif
        {
          xstrcat(&cmdline, &sizecmdline, "-f");
          if (area==-1 && achanged && env_chaddr)
          { strncpy(str, from, sizeof(str));
            getaddr(str);
          }
          else
          { char *p2;
            if (area==-1)
            { strncpy(str, msghdr.from, sizeof(msghdr.from));
              str[sizeof(msghdr.from)]=0;
              mkusername(str);
              /* strcat(cmdline, str); */
	      xexpand(&cmdline, &sizecmdline, strlen(str)*2+strlen(myaka[curaka].domain)+40);
              p2=cmdline+strlen(cmdline);
	      *p2++=' ';
              p=str;
              while (*p)
              {
                if (strchr(METACHARS, *p))
#ifdef UNIX
                  *p2++='\\';
#else
                  *p2++='.';
                else
#endif
                  *p2++=*p;
                p++;
              }
              strcpy(p2, "@");
              if (point)
                sprintf(cmdline+strlen(cmdline), "p%u.", point);
              sprintf(cmdline+strlen(cmdline), "f%u.n%u.z%u.", node, net, zone);
              strcpy(str, myaka[curaka].domain);
              p=strpbrk(str, "@%");
              if (p) *p=0;
              strcat(cmdline, str);
	      *str='\0';
            }
            else
              strcpy(str, gatemaster);
          }
          if (*str) xstrcat(&cmdline, &sizecmdline, str);
        }
        xstrcat(&cmdline, &sizecmdline, "--");
        if (area!=-1)
          xstrcat(&cmdline, &sizecmdline, group[echoes[area].group].newsserv);
        else
        { char *p2;
          p=to;
          while (p)
          { while ((*p==' ') || (*p==',')) p++;
            if (*p==0) break;
            p1=strpbrk(p, " ,");
            if (p1) *p1=0;
            /* aliases */
            for (i=0; i<nalias; i++)
              if (stricmp(p, alias[i].from)==0) break;
            if (i<nalias)
            { debug(4, "Main: %s is alias to %s", p, alias[i].to);
              p = alias[i].to;
            }
            /* strcat(cmdline, p); */
	    xexpand(&cmdline, &sizecmdline, strlen(p)*2+3);
            p2=cmdline+strlen(cmdline);
	    *p2++=' ';
            while (*p)
            { if (strchr(METACHARS, *p))
#ifdef UNIX
                *p2++='\\';
#else
                *p2++='.';
              else
#endif
                *p2++=*p;
              p++;
            }
            strcpy(p2, " ");
            if (p1) *p1=' ';
            p=p1;
          }
        }
      }
#ifdef __MSDOS__
      { int savein = dup(fileno(stdin));
        fflush(fout->file);
        rewind(fout->file);
        dup2(fileno(fout->file), fileno(stdin));
        debug(4, "Main: execute '%s'", cmdline);
        i=swap_system(cmdline);
        dup2(savein, fileno(stdin));
        close(savein);
      }
#else /* OS/2, UNIX */
      debug(5, "Main: call msend('%s')", cmdline);
      i=msend(cmdline, fout);
      if (i!=-1)
      { i&=0xffff;
        i=((i<<8) | (i>>8)) & 0xffff;
      }
#endif
      virt_fclose(fout);
      fout=NULL;
      debug(4, "Main: rmail retcode %d", i);
#if 0
#ifdef __OS2__
      if ((i==64) && (uupcver==SENDMAIL))
      { /* bad from-username, message sent from os2user */
        logwrite('!', "sendmail retcode %d (message sent, incorrect from-name?)\n");
        i=0;
      }
#endif
#endif
#ifndef UNIX
      if ((i==48) && (uupcver!=SENDMAIL))
        i=0; /* 48 -- MAGIC number (c) Ache ;-) */
#endif
      if (i)
      {
        if (i<0)
          sprintf(str, "can't execute rmail: %s", strerror(errno));
        else if (i>255)
          sprintf(str, "sendmail exited by signal %s", strsignal(i>>8));
        else
#ifndef UNIX
          if (uupcver!=SENDMAIL)
            sprintf(str, "rmail retcode %u", i);
          else
#endif
            sprintf(str, "sendmail: %s", strsysexit(i));
        /*
        return retcode|RET_ERR;
        */
        logwrite('?', "ERROR: %s!\n", str);
        badmsg(str);
        if (memtxt) freebuf(memtxt);
        memtxt=NULL;
        return 0;
      }
    }
    if ((area==-1) && packed && rejreason)
    { badmsg("Bad dest address");
      return 0;
    }
    if ((area==-1) && (packed==0))
    { if (rejreason)
        /* some addresses rejected */
        badmsg("Bad dest address");
      else if ((attr & msgKILLSENT) || (attr & msgFORWD) ||
          !(attr & msgLOCAL))
      { flock(h, LOCK_UN);
        close(h);
        h=-1;
        unlink(msgname);
      }
      else
      { /* only set attribute msgSENT */
        lseek(h, (unsigned)(&(msghdr.attr))-(unsigned)(&msghdr), SEEK_SET);
        { msghdr.attr|=msgSENT;
          write(h, &(msghdr.attr), sizeof(msghdr.attr));
        }
      }
    }
    if ((area==-1) && (attr & msgFILEATT) && (rejreason==0))
      delsentfiles(attr, msghdr.subj);
    if (area==-1)
    { retcode|=RET_NETMAIL;
      putaddr(str, zone, net, node, point);
      logwrite('$', "From %s %s\tto %s\t%lu bytes OK\n",
               msghdr.from, str, to, msgsize);
    }
    else
      retcode|=RET_ECHOMAIL;
    return 0;
}

static void reject(int reason, char *to)
{
  debug(3, "Reject: message to %s, reason %d", to, reason);
  genlett(reason, msghdr.from, zone, net, node, point, 0);
  genlett(reason, master, mastzone, mastnet, mastnode, mastpoint, 1);
  if (nagate && nagate[0])
  { if (point)
      sprintf(str, "%u:%u/%u.%u", zone, net, node, point);
    else
      sprintf(str, "%u:%u/%u", zone, net, node);
    logwrite('!', "From %s %s to %s failed (%s)\n",
             msghdr.from, str, to, strreason(reason, 2));
  }
  frescan=1;
  debug(7, "Reject: done");
}

void reset_text_(void)
{ imemtxt=0;
}

int gettextline_(char *str, unsigned size)
{ return memgets(str, size);
}

static int memgets(char *str, int size)
{
  int i;
  char *p;

  if (txtsize-imemtxt<size)
    size=(int)(txtsize-imemtxt)+1;
  frombuf(str, memtxt, imemtxt, size-1);
  str[size-1]=0;
  p=strchr(str, '\n');
  if (p)
    *++p='\0';
  i=strlen(str);
  imemtxt+=i;
  return i;
}
