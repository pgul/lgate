/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2002/09/22 08:02:09  gul
 * translate comments
 *
 * Revision 2.0  2001/01/10 20:42:17  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <string.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <sys/types.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <stdlib.h>
#include <time.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
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
#include "gate.h"

int  packmail=0;
int  seqf=0;

static struct message msg;
static DIR *d;
static struct dirent *df;
static unsigned r;
static FILE *f=NULL;
static int i;
static char tstr[80], msgname[FNAME_MAX], *p;
static uword mzone, mnet, mnode, mpoint;

char *strreason(int reason, int whatfor)
{ /* whatfor:
       0 - [reason] in template;
       1 - verbouse describtion in template;
       2 - for "Reason:" in badmail
  */
  static char *verbreason[][3]= {
   { "unknown", "there are some bugs now", "Internal error" },
   { "destination", "you can't send messages to %s", "Incorrect dest address" },
   { "Size", "it was too large", "Message too large" },
   { "Binary", "it contain binary information", "Binary data" },
   { "Twit", "you can't use our gate", "Twit" },
   { "noaddress", "you didn't specify valid TO address", "No valid dest address" },
   { "external", "i can't gate it", "External checker" },
   { "attach", "you can't send fileattach via gate", "FileAttaches disabled" }
  };

  if (reason>=sizeof(verbreason)/sizeof(verbreason[0]) || reason<0)
    reason=0;
  return verbreason[reason][whatfor];
}

void setvars(int reason)
{
  time_t curtime;
  struct tm *curtm;

  debug(6, "SetVars");
  curtime=time(NULL);
  curtm=localtime(&curtime);
  setvar("gatename","FTN-Internet Gate");
  debug(9, "SetVars: set GateName to '%s'", getvar("GateName"));
  setvar("subject","Your message was not sent");
  debug(9, "SetVars: set Subject to '%s'", getvar("Subject"));
  setvar("oldsubject",msghdr.subj);
  debug(9, "SetVars: set OldSubject to '%s'", getvar("OldSubject"));
  putaddr(tstr, myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node, myaka[curaka].point);
  setvar("gateaddr", tstr);
  debug(9, "SetVars: set GateAddr to '%s'", getvar("GateAddr"));
  setvar("toaddr", tstr);
  debug(9, "SetVars: set ToAddr to '%s'", getvar("ToAddr"));
  setvar("fromname", msghdr.from);
  debug(9, "SetVars: set FromName to '%s'", getvar("FromName"));
  putaddr(tstr, zone, net, node, point);
  setvar("fromaddr", tstr);
  debug(9, "SetVars: set FromAddr to '%s'", getvar("FromAddr"));
  if (reason==NOADDR)
    setvar("toname", msghdr.to);
  else
    setvar("toname", to);
  debug(9, "SetVars: set ToName to '%s'", getvar("ToName"));
  setvar("date", msghdr.date);
  debug(9, "SetVars: set Date to '%s'", getvar("Date"));
  sprintf(tstr,"%ld", txtsize);
  setvar("size", tstr);
  debug(9, "SetVars: set Size to '%s'", getvar("Size"));
  setvar("mastname", master);
  debug(9, "SetVars: set MastName to '%s'", getvar("MastName"));
  putaddr(tstr, mastzone, mastnet, mastnode, mastpoint);
  setvar("mastaddr", tstr);
  debug(9, "SetVars: set MastAddr to '%s'", getvar("MastAddr"));
  sprintf(tstr,"%02u %s %02u", curtm->tm_mday, montable[curtm->tm_mon],
          curtm->tm_year%100);
  setvar("localdate", tstr);
  debug(9, "SetVars: set LocalDate to '%s'", getvar("LocalDate"));
  sprintf(tstr, "%02u:%02u:%02u", curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
  setvar("localtime", tstr);
  debug(9, "SetVars: set LocalTime to '%s'", getvar("LocalTime"));
  setvar("reason", strreason(reason, 0));
  debug(9, "SetVars: set Reason to '%s'", getvar("Reason"));
}

void closepkt(void)
{ unsigned i;

  if (f==NULL) return;
  i=0;
  fwrite(&i, 2, 1, f);
  fclose(f);
}

int writemsghdr(struct message *msghdr, FILE *fout)
{ uword two;
  struct message msg;

  debug(9, "WriteMsgHeader");
  memcpy(&msg, msghdr, sizeof(msg));
  msghdr_byteorder(&msg);
  two=chorders(htons(2));
  fwrite(&two, 2, 1, fout);
  fwrite(&(msg.orig_node), 2, 1, fout);
  fwrite(&(msg.dest_node), 2, 1, fout);
  fwrite(&(msg.orig_net), 2, 1, fout);
  fwrite(&(msg.dest_net), 2, 1, fout);
  fwrite(&(msg.attr), 2, 1, fout);
  fwrite(&(msg.cost), 2, 1, fout);
  fwrite(msghdr->date, strlen(msghdr->date)+1, 1, fout);
  fwrite(msghdr->to, strlen(msghdr->to)+1, 1, fout);
  fwrite(msghdr->from, strlen(msghdr->from)+1, 1, fout);
  if (fwrite(msghdr->subj, strlen(msghdr->subj)+1, 1, fout))
    return 0;
  else
    return 1;
}

static void writepkthdr(FILE *f)
{
  time_t curtime;
  struct tm *curtm;

  debug(9, "WritePktHeader");
  curtime=time(NULL);
  curtm=localtime(&curtime);
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
  pkthdr_byteorder(&pkthdr);
  fwrite(&pkthdr, sizeof(pkthdr), 1, f);
}

void genlett(int reason, char *toname,
             uword tozone, uword tonet, uword tonode, uword topoint,
             int tomaster)
{
  time_t curtime;
  struct tm *curtm;

  /* create bounce .msg */
  /* init vars */
  debug(9, "GenLett, to='%s', %d:%d/%d.%d, reason=%d", toname,
        tozone, tonet, tonode, topoint, reason);
  curtime=time(NULL);
  curtm=localtime(&curtime);
  tplout=0;
  r=init_tpl(tpl_name);
  reset_text=reset_text_;
  gettextline=gettextline_;
  setvars(reason);
  if (tomaster)
    setvar("tomaster", "yes");
  if (msghdr.attr & msgRETREC)
    setvar("DontSend", "yes");
  if (r==0)
    while (templateline(tstr, sizeof(tstr)));
  if (getvar("dontsend"))
  { close_tpl();
    debug(6, "GenLett: DoNotSend set, don't send message");
    return;
  }
  strcpy(msg.to, toname);
  if (getfidoaddr(&mzone, &mnet, &mnode, &mpoint, getvar("gateaddr")))
  { mzone=myaka[curaka].zone;
    mnode=myaka[curaka].node;
    mnet=myaka[curaka].net;
    mpoint=myaka[curaka].point;
  }
  strncpy(msg.from, getvar("gatename"), sizeof(msg.from)-1);
  strncpy(msg.subj, getvar("subject"), sizeof(msg.subj)-1);
  close_tpl();
  sprintf(msg.date, "%02u %s %02u  %02u:%02u:%02u",
          curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year%100,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
  msg.times_read=msg.cost=0;
  msg.dest_zone=tozone;
  msg.dest_node=tonode;
  msg.dest_net=tonet;
  msg.dest_point=topoint;
  msg.orig_zone=mzone;
  msg.orig_node=mnode;
  msg.orig_net=mnet;
  msg.orig_point=mpoint;
  msg.replyto=msg.next_reply=0;
  msg.attr=msgPRIVATE|msgKILLSENT|msgLOCAL|msgRETREC;
  if (!packmail)
  { unsigned maxnum;
    /* find maximum *.msg number */
    maxnum=0;
    d=opendir(netmaildir);
    while ((d!=NULL) && ((df=readdir(d))!=NULL))
    { i=atoi(df->d_name);
      if (i>maxnum) maxnum=i;
    }
    if (d) closedir(d);
    strcpy(msgname, netmaildir);
    if (netmaildir[strlen(netmaildir)-1]!=PATHSEP)
      strcat(msgname, PATHSTR);
    sprintf(msgname+strlen(msgname), "%u.msg", maxnum+1);
    f=fopen(msgname, "wb");
    for (i=0; i<5; i++)
      if (flock(fileno(f), LOCK_EX|LOCK_NB))
        sleep(1);
      else
        break;
    if (i==5)
    { fclose(f);
      f=NULL;
    }
  }
  else if (f==NULL)
  { unsigned long maxnum, initmax;
    initmax=time(0);
    for (maxnum=initmax+1; maxnum!=initmax; maxnum++)
    { sprintf(msgname, "%s%lx.pkt", pktout, maxnum);
      if (access(msgname, 0)==0) continue;
      f=fopen(msgname, "wb");
      if (f!=NULL)
        break;
    }
    if (f!=NULL)
    { for (i=0; i<5; i++)
        if (flock(fileno(f), LOCK_EX|LOCK_NB))
          sleep(1);
        else
          break;
      if (i==5)
      { fclose(f);
        f=NULL;
      }
    }
    if (f!=NULL)
      writepkthdr(f);
  }
  debug(6, "GenLett: msgname is %s", msgname);
  if (f==NULL)
  { logwrite('?', "Error! Can't create reject message to %s %u:%u/%u.%u!\n",
             toname, tozone, tonet, tonode, topoint);
    return;
  }
  debug(9, "GenLett: %s created", msgname);
  if (!packmail)
  {
    if (fwrite(&msg, sizeof(msg), 1, f)!=1)
    {
errwrite:
      flock(fileno(f), LOCK_UN);
      fclose(f);
      f=NULL;
      unlink(msgname);
      logwrite('?', "Error! Can't create reject message to %s %u:%u/%u.%u!\n",
               toname, tozone, tonet, tonode, topoint);
      return;
    }
  }
  else if (writemsghdr(&msg, f)!=0)
    goto errwrite;
  fprintf(f, "\x01INTL %u:%u/%u %u:%u/%u\r", tozone, tonet, tonode,
              mzone, mnet, mnode);
  if (mpoint)
    fprintf(f, "\x01""FMPT %u\r", mpoint);
  if (topoint)
    fprintf(f, "\x01TOPT %u\r", topoint);
  fprintf(f, "\x01MSGID: %u:%u/%u", mzone, mnet, mnode);
  if (mpoint)
    fprintf(f, ".%u", mpoint);
  fprintf(f, " %08lx\r", curtime*100+getpid()%100+seqf++);
  tplout=1;
  r=init_tpl(tpl_name);
  setvars(reason);
  if (tomaster)
    setvar("tomaster", "yes");
  if (r==0)
  { while (templateline(tstr, sizeof(tstr)))
    { for (p=tstr; *p; p++) if (*p=='\n') *p='\r';
      fputs(tstr, f);
    }
  }
  else
  { fprintf(f, "   Hello %s!\r", getvar("fromname"));
    fprintf(f, "   Your message was rejected because ");
    fprintf(f, strreason(reason, 1), to);
    fprintf(f, ".\r");
    fprintf(f, "Original message was:\r"
              "==============\r"
              "From: %s %s\r"
              "To:   %s %s\r"
              "Subj: %s\r"
              "Date: %s\r"
              "==============\r",
              getvar("fromname"), getvar("fromaddr"),
              getvar("to"), getvar("toaddr"),
              getvar("oldsubject"), getvar("date"));
    if (!tomaster)
    { reset_text_();
      while (gettextline_(tstr, sizeof(tstr)))
        fputs(tstr, f);
      fputs("==============\r", f);
    }
    fprintf(f, "  Send your proposes and bug reports to %s %s.\r",
            getvar("mastname"), getvar("mastaddr"));
    fprintf(f, "                   Lucky Carrier,\r");
    fprintf(f, "                             Gate Daemon.\r");
  }
  close_tpl();
  fprintf(f, "--- "COPYRIGHT"\r");
  if (fputc(0, f)==EOF)
    goto errwrite;
  if (fflush(f))
    goto errwrite;
  if (!packmail)
  { flock(fileno(f), LOCK_UN);
    fclose(f);
    f=NULL;
  }
  debug(9, "GenLett: done");
}
