/*
 * $Id$
 *
 * $Log$
 * Revision 2.4  2004/07/20 18:38:06  gul
 * \r\n -> \n
 *
 * Revision 2.3  2002/10/29 19:40:13  gul
 * MSGID generation minor fix
 *
 * Revision 2.2  2002/10/29 19:05:30  gul
 * Format text, translate comments
 *
 * Revision 2.1  2001/08/16 14:20:39  gul
 * coredumped if malformed X-FTN-MSGID
 *
 * Revision 2.0  2001/01/10 20:42:25  gul
 * We are under CVS for now
 *
 */
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include "gate.h"

#define chkheader(str)  if (chkhdrsize(str)) return 2;
#define nline pheader[cheader+1]=pheader[cheader]+strlen(pheader[cheader])+1; cheader++;

long curhdrsize;
unsigned curnpheader;
char freply[SSIZE], freplydomain[MAXADDR];

static int cont, toheader;
static char *p, *p1;
static int r;
static uword pp, i, j, k;
static char realname[SSIZE];
static int  wasreply;

int chkhdrsize(char *str)
{ long offset;
  char *newheader;
  int  i;

  while ((char _Huge *)pheader[cheader]+strlen(str)+ZAPAS>=(char _Huge *)header+curhdrsize)
  {
    newheader=myrealloc(header, curhdrsize, curhdrsize+MAXHEADER);
    if (newheader==NULL)
    { logwrite('?', "Too large header, message renamed to *.bad!\n");
      return 2;
    }
    curhdrsize+=MAXHEADER;
    offset=(char _Huge *)newheader-(char _Huge *)header;
    for (i=0; i<=cheader; i++)
      pheader[i]=(char *)((char _Huge *)pheader[i]+offset);
    header=newheader;
  }
  if (cheader+NZAPAS>=curnpheader)
  { newheader=myrealloc((char *)pheader, curnpheader*sizeof(pheader[0]),
              (curnpheader+MAXNHEADER)*sizeof(pheader[0]));
    if (newheader==NULL)
    { logwrite('?', "Too large header, message renamed to *.bad!\n");
      return 2;
    }
    curnpheader+=MAXNHEADER;
    pheader=(char **)newheader;
  }
  return 0;
}

int readhdr(void)
{ int firstline, xftnpath;

  debug(7, "ReadHdr");
  if (myorigin)
  { strncpy(origin, organization, sizeof(origin));
    origin[sizeof(origin)-1]='\0';
  }
  cont=toheader=0;
  firstline=1;
  tofield[0]='\0';
  wasreply=0;
  xftnpath=0;
  freply[0]=freplydomain[0]='\0';
  while (hgets())
  {
    chkheader(str);
    if (cont)
    { if (toheader)
      { strcpy(pheader[cheader]-2, str);
        strcat(pheader[cheader]-2, "\r");
        pheader[cheader]=(char *)((char _Huge *)pheader[cheader]+strlen(str));
      }
      if (strchr(str, '\r'))
        cont=0;
      continue;
    }
    if (firstline)
    { if (strncmp(str, "From ", 5)==0)
      { char *p;
        int  i;
        for (p=str+5; isspace(*p); p++);
        for (i=0; p[i] && !isspace(p[i]); i++);
        if (i>=sizeof(envelope_from)) i=sizeof(envelope_from)-1;
        strncpy(envelope_from, p, i);
        envelope_from[i]='\0';
        debug(1, "readhdr: set envelope from to %s", envelope_from);
        firstline=0;
        if (strchr(str, '\r')==NULL)
          cont=1;
        continue;
      }
      else if ((conf && !cnews) || (!conf && !bypipe))
      { logwrite('?', "Bad message header!\n");
        retcode|=RET_ERR;
        return 1;
      }
    }
    firstline=0;
    if ((str[0]==' ') || (str[0]=='\t'))
    { if (toheader)
      { for (p=str+1; (*p==' ') || (*p=='\t'); p++);
        *((char _Huge *)pheader[cheader]-2)=' ';
        strcpy((char *)((char _Huge *)pheader[cheader]-1),p );
        if (strchr(p, '\r')==NULL)
          strcat((char *)((char _Huge *)pheader[cheader]-1), "\r");
        pheader[cheader]=(char *)((char _Huge *)pheader[cheader]+strlen((char *)((char _Huge *)pheader[cheader]-1)));
        pheader[cheader][0]=0;
      }
      if (strchr(str, '\r')==0)
        cont=1;
      continue;
    }
    if (strcmp(str, "\r")==0)
    {
      if (wasreply & 3) /* was "References:" or "In-Reply-To:" */
      { int i;
        unsigned long reply;

        if (wasreply == 3)
        { for (i=0; i<cheader; i++)
          { if (strnicmp(pheader[i], "\x01RFC-In-Reply-To:", 17)==0)
            { if (strchr(pheader[i], '>') == NULL ||
                  strchr(pheader[i], '<') == NULL)
              { wasreply=1;
                pheader[i][0]='\0';
              }
              break;
            }
          }
        }
        for (i=0; i<cheader; i++)
        { if (strnicmp(pheader[i], "\x01RFC-References:", 16)==0)
          { if (wasreply & 6) /* was "FTN-Reply:" or "In-Reply-To:" */
              pheader[i][0]='\0';
            else
            { p=strrchr(pheader[i], '<');
              if (p)
              { p++;
                p1=strchr(p, '>');
                if (p1)
                { *p1='\0';
                  fidomsgid(p, freply, freplydomain, &reply);
                  if (freply[0])
                    sprintf(pheader[i], "\x01REPLY: %s\r", freply);
                  else if (domainmsgid)
                    sprintf(pheader[i], "\x01REPLY: %s %08lx\r",
                            quotemsgid(freplydomain), reply);
                  else
                    pheader[i][0]='\0'; /* unknown aka */
                }
                else
                  pheader[i][0]='\0';
              }
              else
                pheader[i][0]='\0';
            }
          }
          else if (strnicmp(pheader[i], "\x01RFC-In-Reply-To:", 17)==0)
          { if (wasreply & 4) /* was "FTN-Reply:" */
              pheader[i][0]='\0';
            else
            { p=strchr(pheader[i], '<');
              if (p)
              { p++;
                p1=strchr(p, '>');
                if (p1)
                { *p1='\0';
                  fidomsgid(p, freply, freplydomain, &reply);
                  if (freply[0])
                    sprintf(pheader[i], "\x01REPLY: %s\r", freply);
                  else if (domainmsgid)
                    sprintf(pheader[i], "\x01REPLY: %s %08lx\r",
                            quotemsgid(freplydomain), reply);
                  else
                    pheader[i][0]='\0'; /* unknown aka */
                }
                else
                  pheader[i][0]='\0';
              }
              else
                pheader[i][0]='\0';
            }
          }
        }
      }
      debug(7, "ReadHdr exit");
      return 0;
    }
    if (strchr(str, '\r')==NULL)
      cont=1;
    p=strrchr(str, '\r');
    if (p) *p=0;
    while ((p=strchr(str, '\r'))!=NULL)
      *p=' '; /* unfolding */
    toheader=0;
    if (strnicmp(str, "From:", 5)==0)
    { wasfrom=1;
      sprintf(pheader[cheader], "\1RFC-%s\r", str);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "To: ", 4)==0)
    { for (p=str+4; (*p==' ') || (*p=='\t'); p++);
      if (strcmp(addr, p) && (conf==0))
      { sprintf(pheader[cheader], "%s\r", str);
        nline;
        toheader=1;
      }
      parseaddr(p, tofield, realname, -1);
      debug(6, "ReadHdr: toaddr is '%s'", tofield);
      continue;
    }
    if (strnicmp(str, "Summary: ", 9)==0)
    { sprintf(pheader[cheader], "%s\r", str);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "X-Mailer: ", 10)==0)
    { sprintf(pheader[cheader], "\x01PID: %s\r", str+10);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "X-Newsreader: ", 14)==0)
    { sprintf(pheader[cheader], "\x01PID: %s\r", str+14);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "User-Agent: ", 12)==0)
    { sprintf(pheader[cheader], "\x01PID: %s\r", str+12);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "CC: ", 4)==0)
    { sprintf(pheader[cheader], "CC: %s\r", str+4);
      nline;
      toheader=1;
      continue;
    }
    if ((strnicmp(str, "Resent-From: ", 13)==0) ||
        (strnicmp(str, "Recent-From: ", 13)==0))
    { sprintf(pheader[cheader], "%s\r", str);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "Content-", 8)==0)
    { /* Mime - if unmime left it for us, then it was right ;-) */
      sprintf(pheader[cheader], "%s\r", str);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "Received: ", 10)==0)
    { curhops++;
      if (rcv2via==0)
        continue;
      sprintf(pheader[cheader], "\x01Via: %s\r", str+10);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "X-FTN-Flags: ", 13)==0)
    { strupr(str);
      if (strstr(str+13, "CFM"))
      { attrib&=~msgRETRECREQ; /* made from return-receipt-to */
        attrib|=msgCFM;
      }
      if (strstr(str+13, "RRQ")) attrib|=msgRETRECREQ;
      if (strstr(str+13, "RRC")) attrib|=msgRETREC;
      continue;
    }
    if (savehdr!=2)
    {
      if (strnicmp(str, "NNTP-Posting-Host:", 18)==0)
        continue;
      if (strnicmp(str, "NNTP-Posting-Date:", 18)==0)
        continue;
      if (strnicmp(str, "X-Trace:", 8)==0)
        continue;
      if (strnicmp(str, "Resent-", 7)==0)
        continue;
      if (strnicmp(str, "Recent-", 7)==0)
        continue;
      if (strnicmp(str, "Sender: ", 8)==0)
        continue;
      if (strnicmp(str, "Status: ", 8)==0)
        continue;
      if (strnicmp(str, "Lines: ", 7)==0)
        continue;
      if (strnicmp(str, "X-Class: ", 9)==0)
        continue;
      if (strnicmp(str, "X-Sender: ", 10)==0)
        continue;
      if (strnicmp(str, "X-VMS-", 6)==0)
        continue;
      if (strnicmp(str, "Priority: ", 10)==0)
        continue;
      if (strnicmp(str, "Distribution: ", 14)==0)
        continue;
      if (strnicmp(str, "X-Return-Path: ", 15)==0)
        continue;
      if (strnicmp(str, "X-Gate: ", 8)==0)
        continue;
      if (strnicmp(str, "Xref: ", 6)==0)
        continue;
      if (strnicmp(str, "X-Ref: ", 7)==0)
        continue;
      if (strnicmp(str, "Precedence: ", 12)==0)
        continue;
      if (strnicmp(str, "X-Listname: ", 12)==0)
        continue;
      if (strnicmp(str, "Mime-Version: ", 14)==0)
        continue;
      if (strnicmp(str, "Apparently-To: ", 15)==0)
        continue;
      if (strnicmp(str, "Keywords: ", 10)==0)
        continue;
    }
    /*
    if (strnicmp(str, "Followup-To: ", 13)==0)
      continue;
    */
    if (strnicmp(str, "X-NNTP-Path: ", 13)==0)
    { if (cnews)
        continue;
      goto path;
    }
    if (strnicmp(str, "Path: ", 6)==0)
    { if (!cnews)
        continue;
path:
      /* change order and remove all non-ftn domains */
      lastzone=0;
      for (p=strchr(str, ' ')+1; *p; p=p1+1)
      { p1=strpbrk(p, "! \t");
        if ((p1==NULL) || (*p1!='!'))
          break;
        *p1=0;
        if (*p=='p')
          r=sscanf(p, "p%hu.f%hu.n%hu.z%hu", &pp, &i, &j, &k);
        else if (*p=='f')
        { pp=0;
          r=sscanf(p, "f%hu.n%hu.z%hu", &i, &j, &k)+1;
        }
        else
          continue;
        if (r<3)
          continue;
        if (pp!=0)
          continue; /* points should not occure in the path! */
        if ((r==4) && (k!=lastzone))
        { if (lastzone==0)
          { lastzone=k;
            if (xftnpath) break;
          }
          else
            continue;
        }
        if (xftnpath) continue;
        /* add to path */
        for (k=npath; k>0; k--)
          memcpy(path+k, path+k-1, sizeof(path[0]));
        if (npath<MAX_PATH)
        { path[0].net=j;
          path[0].node=i;
          npath++;
        }
      }
      if (savehdr!=2)
        continue;
    }
    if (strnicmp(str, "X-FTN-SEEN-BY: ", 15)==0)
    {
      p=str+15;
      i=-1; /* network */
      for (;*p;)
      { if (nseenby==MAXSEENBY)
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
        if (i==(uword)-1) break;
        for (k=0; k<nseenby; k++)
          if ((seenby[k].net==i) && (seenby[k].node==j))
            break;
        if (k<nseenby)
          continue;
        seenby[k].net=i;
        seenby[k].node=j;
        nseenby++;
      }
      continue;
    }
    if (strnicmp(str, "X-FTN-Path: ", 12)==0)
    {
      if (!xftnpath) npath=0;
      p=str+12;
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
        if (i==(uword)-1) break;
        path[npath].net=i;
        path[npath].node=j;
        npath++;
      }
      xftnpath=1;
      continue;
    }
    if (strnicmp(str, "Reply-To: ", 10)==0)
    { /*
      for (p=str+10; (*p==' ') || (*p=='\t'); p++);
      sprintf(pheader[cheader], "\x01Reply-To: %s\r", p);
      nline;
      toheader=1;
      */
      /*
      if (savehdr==2)
      */
      { sprintf(pheader[cheader], "\x01RFC-%s\r", str);
        nline;
        toheader=1;
      }
      continue;
    }
    if (strnicmp(str, "Organization: ", 14)==0)
    { if ((strcmp(str+14, organization)==0) && (conf) && (!cnews))
        null=1;
      if (!myorigin)
      { strncpy(origin, str+14, sizeof(origin));
        origin[sizeof(origin)-1]=0;
      }
      if (myorigin || (savehdr==2) || ((savehdr==1) && strlen(str+14)>=sizeof(origin)))
      { sprintf(pheader[cheader], "\x01RFC-%s\r", str);
        nline;
        toheader=1;
      }
      continue;
    }
    if (strnicmp(str, "X-FTN-Origin: ", 14)==0)
    { strncpy(xorigin, str+14, sizeof(xorigin));
      xorigin[sizeof(xorigin)-1]=0;
      continue;
    }
    if (strnicmp(str, "Control: ", 9)==0)
    { null=1;
      continue;
    }
    if (strnicmp(str, "Subject: ", 9)==0)
    { p=str+9;
      if (conf && (!cnews))
      { if (strnicmp(p, "[news] ", 7))
          nonews=1;
        else
          p+=7;
      }
      for (; (*p==' ') || (*p=='\t'); p++);
      sprintf(pheader[cheader], "Subject: %s\r", p);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "Message-Id:", 11)==0)
    { if (wasmsgid & 1) continue; /* already was */
      for (p=str+11; (*p==' ') || (*p=='\t'); p++);
      if (*p=='\0') continue;
      wasmsgid|=1;
      if (! (wasmsgid & 2))
      { /* no X-FTN-MSGID */
        /* check, if it's FTN-style -
          <z_n/f[_p]_xxxxxxxx@domain> or
          <z-n-f[-p]-xxxxxxxx[-domain]@domain> or
          <xxxxxxxx@[pP.]fF.nN.zZ.domain> */
        fidomsgid(p, fmsgid, domainid, &msgid);
      }
      if (*p=='<')
      { 
        p=strchr(p+1, '>');
        if (p) *p='\0';
        for (p=str+11; (*p==' ') || (*p=='\t'); p++);
        p++;
      }
      sprintf(pheader[cheader], "\x01RFCID: %s\r", p);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "Date: ", 6)==0)
    { if (parsedate(str+6))
      { sprintf(pheader[cheader], "\x01%s\r", str);
        nline;
        toheader=1;
      }
      continue;
    }
    if (strnicmp(str, "Return-Receipt-To: ", 19)==0)
    { if ((attrib & msgCFM)==0)
        attrib|=msgRETRECREQ;
      continue;
    }
    if ((strnicmp(str, "Newsgroups: ", 12)==0) && conf)
    {
      for (p=str+12; (*p==' ') || (*p=='\t'); p++);
      sprintf(pheader[cheader], "\x01RFC-Newsgroups: %s\r", p);
      nline;
      toheader=1;
      continue;
    }
    if (((strnicmp(str, "Comment-To: ", 12)==0) ||
         (strnicmp(str, "X-To: ", 6)==0) ||
         (strnicmp(str, "X-Comment-To: ",14)==0)) && conf)
    {
      sprintf(pheader[cheader], "\x01RFC-%s\r", str);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "References: ", 12)==0)
    {
      if (wasreply & 7) /* was "FTN-Reply:", "In-Reply-To:" or "References:" */
        continue;
      sprintf(pheader[cheader], "\x01RFC-%s\r", str);
      nline;
      toheader=1;
      wasreply|=1;
      continue;
    }
    if (strnicmp(str, "In-Reply-To: ", 13)==0)
    {
      if (wasreply & 6) /* was "FTN-Reply:" or "In-Reply-To:" */
        continue;
      sprintf(pheader[cheader], "\x01RFC-%s\r", str);
      nline;
      toheader=1;
      wasreply|=2;
      continue;
    }
    if (strnicmp(str, "X-FTN-Kludge: ", 14)==0)
    { sprintf(pheader[cheader], "\x01%s\r", str+14);
      nline;
      toheader=1;
      continue;
    }
    if (strnicmp(str, "X-FTN-To: ", 10)==0)
    { if (conf)
      { strncpy(msghdr.to, str+10, sizeof(msghdr.to)-1);
        msghdr.to[sizeof(msghdr.to)-1]='\0';
        toheader=0;
        continue;
      }
    }
    if ((strnicmp(str, "X-FTN-", 6)==0) ||
        (strnicmp(str, "X-FSC-", 6)==0))
    { if (strnicmp(str+6, "MsgId: ", 7)==0)
      { if (wasmsgid & 2)
          continue; /* already was */
        wasmsgid|=2;
#if 0
        if (str[13]=='<')
        { p=strchr(str+14,'>');
          if (p) *p=0;
          p=str+14;
        }
        else
#endif
          p=str+13;
        sprintf(pheader[cheader], "\x01MSGID: %s\r", p);
      }
      else if (strnicmp(str+6, "Reply: ", 7)==0)
      { if (wasreply & 4)
          continue; /* already was */
        wasreply|=4;
        sprintf(pheader[cheader], "\x01REPLY: %s\r", str+13);
      }
      else
      { if (strnicmp(str+6, "Flags:", 6)==0)
          continue;
        if (strnicmp(str+6, "Intl:", 5)==0)
          continue;
        if (strnicmp(str+6, "Topt:", 5)==0)
          continue;
        if (strnicmp(str+6, "Fmpt:", 5)==0)
          continue;
        if (strnicmp(str+6, "RFCID:", 6)==0)
          continue;
        if (strnicmp(str+6, "AREA:", 5)==0)
          continue;
        if (strnicmp(str+6, "Replyaddr:", 10)==0)
          continue;
        if (strnicmp(str+6, "Replyto:", 8)==0)
          continue;
        if (strnicmp(str+6, "Tearline:", 9)==0)
        { strcpy(tearline, str+16);
          continue;
        }
        if ((strnicmp(str+6, "Addr:", 5)==0) || (strnicmp(str+6, "Address:", 8)==0))
        { for (p=str; *p!=':'; p++);
          for (p++; (*p==' ') || (*p=='\t'); p++);
          if (getfidoaddr(&xftnaddr.zone, &xftnaddr.net, &xftnaddr.node,
                          &xftnaddr.point, p))
            xftnaddr.zone=-1;
          continue;
        }
        if (strnicmp(str+6, "From:", 5)==0)
        { for (p=str+11; (*p==' ') || (*p=='\t'); p++);
          strcpy(xftnfrom, p);
          continue;
        }
        if (strnicmp(str+6, "Via:", 4)==0)
        { curhops++;
          sprintf(pheader[cheader], "\x01Via %s\r", str+11);
          continue;
        }
        if (strnicmp(str+6, "Recd:", 5)==0)
        { curhops++;
          sprintf(pheader[cheader], "\x01Recd %s\r", str+12);
          continue;
        }
        sprintf(pheader[cheader], "\x01%s\r", str+6);
      }
      nline;
      toheader=1;
      continue;
    }
    /* other header fields simple copy as hiddens */
    if (!savehdr)
      continue;
    sprintf(pheader[cheader], "\x01RFC-%s\r", str);
    nline;
    toheader=1;
  }
  logwrite('?', "Bad message header\n");
  retcode|=RET_ERR;
  return 1;
}
