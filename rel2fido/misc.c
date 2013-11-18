/*
 * $Id$
 *
 * $Log$
 * Revision 2.21  2013/11/18 21:08:42  gul
 * Fixed some arrays overflow
 *
 * Revision 2.20  2011/11/19 08:39:03  gul
 * Fix strcpy(p,p+1) to own mstrcpy(p,p+1) which works correctly in this case
 *
 * Revision 2.19  2007/09/29 08:49:39  gul
 * Debug
 *
 * Revision 2.18  2007/09/04 08:48:43  gul
 * parse fidogate-style Message-Id
 *
 * Revision 2.17  2005/10/29 22:52:19  gul
 * *** empty log message ***
 *
 * Revision 2.16  2004/07/20 18:38:05  gul
 * \r\n -> \n
 *
 * Revision 2.15  2004/07/20 18:35:25  gul
 * Work with perl 5.8
 *
 * Revision 2.14  2004/03/24 19:22:12  gul
 * Fix syntax error (thx to Andrey Slusar)
 *
 * Revision 2.13  2002/10/29 19:46:36  gul
 * fix msgid conversion
 *
 * Revision 2.12  2002/03/21 11:19:15  gul
 * Added support of msgid style <newsgroup|123@domain>
 *
 * Revision 2.11  2002/01/28 22:47:37  gul
 * %hdr hash fix
 *
 * Revision 2.10  2002/01/28 22:35:12  gul
 * Bugfix in %hdr hash with folded header lines
 *
 * Revision 2.9  2002/01/28 14:02:04  gul
 * bugfix in %hdr hash
 *
 * Revision 2.8  2002/01/09 09:40:57  gul
 * Added $hdr{"From "}
 *
 * Revision 2.7  2002/01/07 09:57:24  gul
 * Added init_textline() for hrewind()
 *
 * Revision 2.6  2002/01/07 08:52:35  gul
 * Bugfix for yesterday changes
 *
 * Revision 2.5  2002/01/06 21:17:41  gul
 * %hdr in perl hook
 *
 * Revision 2.4  2001/04/22 15:42:44  gul
 * Buffer overflow in date parser fixed
 *
 * Revision 2.3  2001/01/25 18:41:39  gul
 * myname moved to debug.c
 *
 * Revision 2.2  2001/01/25 13:14:09  gul
 * quiet var moved to logwrite.c
 *
 * Revision 2.1  2001/01/24 02:16:06  gul
 * translate comments and cosmetic changes
 *
 * Revision 2.0  2001/01/10 20:42:25  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
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
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#include <time.h>
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef __OS2__
#define INCL_DOSPROCESS
#define INCL_DOSFILEMGR
#define INCL_DOSQUEUES
#include <os2.h>
#ifdef __WATCOMC__
#include <rexxsaa.h>
#endif
#endif
#include "gate.h"

#if defined(DO_PERL) && defined(OS2)
/* Perl for OS2 has own malloc/free but does not have strdup :( */
char *strdup(const char *str)
{
  char *p = malloc(strlen(str)+1);
  if (p) strcpy(p, str);
  return p;
}
#endif

wildcard *itwit, *itwitto, *itwitfrom, *itwitvia;
int  nitwit, nitwitto, nitwitfrom, nitwitvia;
char tofield[MAXADDR];
long seekfix, fsize;
unsigned ibuffix, potolok;
int  fix;
char remote[MAXADDR], local[MAXADDR];
char envelope_from[MAXADDR]="";
char pktpwd[9];
char tmpdir[FNAME_MAX];
char organization[80], pktout[FNAME_MAX];
unsigned pktsize=50;
char packmail, gatevia, routeattach;
keepatttype keepatt;
int  nosplit;
long begdel;
int  ndomains;
char netmaildir[FNAME_MAX];
char binkout[FNAME_MAX];
char tboxes[FNAME_MAX];
#ifndef __MSDOS__
char lbso[FNAME_MAX], tlboxes[FNAME_MAX], longboxes[FNAME_MAX];
#endif
char rescan[FNAME_MAX];
char rmail[FNAME_MAX], postmast[MAXADDR];
char userbox[FNAME_MAX];
int  cnews, conf, funix, empty, netmail2pst;
int  maxhops, curhops, shortvia;
struct akatype *myaka;
long maxpart;
struct echo_type _Huge *echoes;
int  nechoes, ncaddr, ncdomain, nchecker;
char badmail[FNAME_MAX];
int  waschaddr;
char holdpath[FNAME_MAX];
char held_tpl[FNAME_MAX], badaddr_tpl[FNAME_MAX];
unsigned holdsize;
char softCR='H';
struct packet pkthdr;
struct caddrtype *caddr;
struct cdomaintype *cdomain;
struct checktype *checker;
struct message msghdr;
ftnaddr *uplink;
int  nuplinks;
int  tossbad, nonet, noecho, bypipe, tabsize;
int  myorigin, notfile, fake, holdhuge;
unsigned long pipetype;
char *msgbuf;
long imsgbuf;
long maxmsgbuf;
char waseof;
long hdrsize;
replytype replyform;
int  msgtz;
#ifdef __MSDOS__
int  share;
#endif
int  putchrs;
struct ftnchrs_type *ftnchrs=NULL;
static long tsize;
static char tstr[80];
static char s[MAXSTR];

int hstrcpy(char *dest, char *src)
{
  while (*src)
  {
    *dest=*src;
    src=(char *)((char _Huge *)src+1);
    dest=(char *)((char _Huge *)dest+1);
  }
  *dest='\0';
  return 0;
}

long hstrlen(char _Huge *str)
{
  long l;
  for (l=0; *str; str++) l++;
  return l;
}

int fidomsgid(char *str, char *s, char *domainid, unsigned long *msgid)
{ /* str - usenet msgid,
     s   - FTN (if it can be converted)
     write domainid and msgid
     sizeof(s) = SSIZE
     sizeof(domainid) = MAXADDR
  */
  char *p, *p1;
  uword zz, nn, ff, pp;
  unsigned i, j, k;

  debug(8, "FidoMsgId(%s)", str);
  s[0]=domainid[0]=0;
  p=strchr(str, '|');
  if (conf && p && newsgroups && p-str>strlen(newsgroups) &&
      *(p-strlen(newsgroups)-1)=='<')
    mstrcpy(p-strlen(newsgroups), p+1);
  p=strchr(str, '@');
  if (p==NULL)
  { /* must not occure */
    if (domainmsgid==2)
    { if (str[0]=='<')
      { strncpy(domainid, str, MAXADDR);
        domainid[MAXADDR-1]='\0';
      }
      else
      { domainid[0]='<';
        strncpy(domainid+1, str, MAXADDR-2);
        domainid[MAXADDR-2]='\0';
        strcat(domainid, ">");
      }
      *msgid=crc32(domainid)^0xfffffffflu;
      return 0;
    }
    if (str[0]=='<')
    { p=strchr(str, '>');
      if (p) *p=0;
      *msgid=crc32(str+1);
      if (p) *p='>';
      return 0;
    }
    *msgid=crc32(str);
    return 0;
  }
  /* check for ifmail-style */
  strncpy(domainid, p+1, MAXADDR);
  domainid[MAXADDR-1]='\0';
  p=strchr(domainid, '>');
  if (p) *p=0;
  p1=str;
  if (p1[0]=='<') p1++;
  for (i=j=0; (p1[i]!='@') && p1[i]; i++)
  { if (!isxdigit(p1[i]))
      j|=2;
    if (!isdigit(p1[i]))
      j|=1;
  }
  strlwr(domainid);
  if (domainid[0]=='p')
    k=sscanf(domainid, "p%hu.f%hu.n%hu.z%hu.", &pp, &ff, &nn, &zz);
  else if (domainid[0]=='f')
  { pp=0;
    k=sscanf(domainid, "f%hu.n%hu.z%hu.", &ff, &nn, &zz)+1;
  }
  else k=0;
  if (k==4)
  { /* yes! */
    if ((i<=8) && (i>=4) && (j<2))
      sscanf(p1, "%lx", msgid);
    else if ((i<=10) && (j==0))
      sscanf(p1, "%lu", msgid);
    else
    { p1[i]=0;
      *msgid=crc32(str);
      p1[i]='@';
    }
    if (pp)
      sprintf(s, "%u:%u/%u.%u %lx", zz, nn, ff, pp, *msgid);
    else
      sprintf(s, "%u:%u/%u %lx", zz, nn, ff, *msgid);
    return 1;
  }
  /* check for fidogate-style */
  if (memcmp(p1, "MSGID_", 6) == 0)
  { for (p1+=6, p=domainid; *p1 && *p1!='@' && *p1!='>' && (p-domainid) < MAXADDR-10; p1++)
    { if (*p1 == '_') *p++ = ' ';
      else if (*p1=='=' && isxdigit(p1[1]) && isxdigit(p1[2]))
      { *p++=(isdigit(p1[1]) ? p1[1]-'0' : tolower(p1[1])-'a'+10) * 16 +
              (isdigit(p1[2]) ? p1[2]-'0' : tolower(p1[2])-'a'+10);
        p1+=2;
      }
      else
        *p++ = *p1;
    }
    /* is it valid MSGID in result? */
    p=strchr(domainid, ' ');
    if (p && strlen(p+1) == 8)
    { for (p1=p+1; *p1; p1++)
        if (!isxdigit(*p1)) break;
      if (!*p1)
      {
        sscanf(p+1, "%08lx", msgid);
        return 1;
      }
    }
    p1 = str;
    if (*p1 == '>') p1++;
  }
  strncpy(domainid, p1+i+1, MAXADDR);
  domainid[MAXADDR-1]='\0';
  p=strchr(domainid, '>');
  if (p) *p=0;
  /* calculate msgid */
  if (domainmsgid==2)
  { if (str[0]=='<')
    { strncpy(domainid, str, MAXADDR);
      domainid[MAXADDR-1]='\0';
    }
    else
    { domainid[0]='<';
      strncpy(domainid+1, str, MAXADDR-2);
      domainid[MAXADDR-2]='\0';
      strcat(domainid, ">");
    }
    *msgid=crc32(domainid)^0xfffffffflu;
  }
  else if (domainmsgid==1)
  { p=strchr(p1, '@');
    *p=0;
    *msgid=crc32(p1);
    *p='@';
  }
  else
    *msgid=crc32(p1);
  /* check for fsc-style */
  p=p1;
  if (!isdigit(*p)) return 0;
  zz=atoi(p);
  while (isdigit(*p)) p++;
  if ((*p!='_') && (*p!='-')) return 0;
  p++;
  if (!isdigit(*p)) return 0;
  nn=atoi(p);
  while (isdigit(*p)) p++;
  if ((*p!='/') && (*p!='-')) return 0;
  p++;
  if (!isdigit(*p)) return 0;
  ff=atoi(p);
  while (isdigit(*p)) p++;
  if ((*p!='_') && (*p!='-')) return 0;
  p++;
  p1=strchr(p, '@');
  *p1=0;
  if (strpbrk(p, "_-"))
  { /* point */
    pp=atoi(p);
    while (isdigit(*p)) p++;
    if ((*p!='_') && (*p!='-'))
    { *p1='@';
      return 0;
    }
    p++;
  }
  else
    pp=0;
  *p1='@';
  for (i=0; i<8; i++)
    if (!isxdigit(p[i]))
      return 0;
  if ((p[i]!='@') && (p[i]!='-')) return 0;
  sscanf(p, "%lx", msgid);
  if (pp)
    sprintf(s, "%u:%u/%u.%u", zz, nn, ff, pp);
  else
    sprintf(s, "%u:%u/%u", zz, nn, ff);
  p+=8;
  p1=s+strlen(s);
  if (*p=='-')
  { /* '-' -> '.' */
    *p1++='@';
    for (p++; *p && (*p!='@'); p++)
      if (*p=='-') *p1++='.';
      else *p1++=*p;
  }
  sprintf(p1, " %08lx", *msgid);
  return 1;
}

char *quotemsgid(char *msgid)
{
  static char *quotedmsgid=NULL;
  static int sizequotedmsgid=0;
  char *p;
  if (domainmsgid!=2) return msgid;
  if (strpbrk(msgid, "\" ")==NULL) return msgid;
  if (sizequotedmsgid<strlen(msgid)*2+3)
  { sizequotedmsgid=strlen(msgid)*2+80;
    quotedmsgid = realloc(quotedmsgid, sizequotedmsgid);
    if (quotedmsgid==NULL)
    { logwrite('!', "quotemsgid: not enough memory!\n");
      return msgid;
    }
  }
  quotedmsgid[0]='\"';
  for (p=quotedmsgid+1; *msgid; msgid++)
  { if (*msgid=='\"') *p++='\"';
    *p++=*msgid;
  }
  strcpy(p, "\"");
  return quotedmsgid;
}

static int gettz(char *str)
{ int i;
/* RFC822:
zone        =  "UT"  / "GMT"                ; Universal Time
                                    ; North American : UT
    /  "EST" / "EDT"                ;  Eastern:  - 5/ - 4
    /  "CST" / "CDT"                ;  Central:  - 6/ - 5
    /  "MST" / "MDT"                ;  Mountain: - 7/ - 6
    /  "PST" / "PDT"                ;  Pacific:  - 8/ - 7
    /  1ALPHA                       ; Military: Z = UT;
                                    ;  A:-1; (J not used)
                                    ;  M:-12; N:+1; Y:+12
    / ( ("+" / "-") 4DIGIT )        ; Local differential
                                    ;  hours+min. (HHMM)
*/
  if ((*str=='+') || (*str=='-'))
    { i=atoi(str+1);
      if (i>=100) i/=100;
      if (i>=24) i=0;
      if (*str=='-') i=-i;
      return i;
    }
  if (strnicmp(str, "est", 3)==0) return -5;
  if (strnicmp(str, "edt", 3)==0) return -4;
  if (strnicmp(str, "cst", 3)==0) return -6;
  if (strnicmp(str, "cdt", 3)==0) return -5;
  if (strnicmp(str, "mst", 3)==0) return -7;
  if (strnicmp(str, "mdt", 3)==0) return -6;
  if (strnicmp(str, "pst", 3)==0) return -8;
  if (strnicmp(str, "pdt", 3)==0) return -7;
  if ((strnicmp(str, "ut", 2)==0) || (strnicmp(str, "gmt", 3)==0)) return 0;
  if (*str=='Z') return 0;
  if (*str=='A') return -1;
  if (*str=='M') return -12;
  if (*str=='N') return 1;
  if (*str=='Y') return 12;
  return 0;
}

int akamatch(uword zone, uword net, uword node)
{ int match=0; /* 0 - no match, 1 - fido, 2 - zone, 3 - net, 4 - node */
  int curaka=0;
  int i;

  for (i=0; i<naka; i++)
  {
    if ((zone==myaka[i].zone) && (net==myaka[i].net) && (node==myaka[i].node))
      if (match<4)
      { match=4;
        curaka=i;
        continue;
      }
    if ((zone==myaka[i].zone) && (net==myaka[i].net))
      if (match<3)
      { match=3;
        curaka=i;
        continue;
      }
    if (zone==myaka[i].zone)
      if (match<2)
      { match=2;
        curaka=i;
        continue;
      }
    if ((zone>0) && (zone<7) && (myaka[i].zone>0) && (myaka[i].zone<7))
      if (match<1)
      { match=1;
        curaka=i;
        continue;
      }
  }
  return curaka;
}

static int shortdate(char *full, char *small)
{ int year, mon, day, hour, min, sec, tz;

  debug(8, "ShortDate('%s')", full);
  while (isspace(*full)) full++;
  if (!isdigit(*full))
  { /* day of week? */
    while (*full && !isspace(*full)) full++;
    while (isspace(*full) || (*full==',')) full++;
    if (!isdigit(*full))
      return 1;
  }
  day=atoi(full);
  if ((day<1) || (day>31))
    return 1;
  while (isdigit(*full)) full++;
  while (isspace(*full)) full++;
  /* month */
  for (mon=0; mon<12; mon++)
    if (strnicmp(full, montable[mon], 3)==0)
      break;
  if (mon==12) return 1;
  full+=3;
  while (isspace(*full)) full++;
  /* year */
  if (!isdigit(*full))
    return 1;
  year=atoi(full);
  if (year<50) year+=100;
  if (year<150) year+=1900;
  if ((year<1970) || (year>2050))
    return 1;
  while (isdigit(*full)) full++;
  while (isspace(*full)) full++;
  /* time */
  if (sscanf(full, "%u:%u:%u", &hour, &min, &sec)!=3) return 1;
  if ((hour<0) || (hour>23) || (min<0) || (min>59) || (sec<0) || (sec>59))
    return 1;
  while (*full && ((*full==':') || isdigit(*full)))
    full++;
  while (isspace(*full)) full++;
  /* TZ */
  tz=gettz(full);
#if 1
  { struct tm t, *gt;
    time_t tt;
    t.tm_year=year-1900;
    t.tm_mon=mon;
    t.tm_mday=day;
    t.tm_hour=hour;
    t.tm_min=min;
    t.tm_sec=sec;
    t.tm_isdst=-1;
    tt=mktime(&t)-tz*3600l;
    gt=localtime(&tt);
    /* ohhh :( */
    if (t.tm_isdst>gt->tm_isdst)
      gt->tm_hour++;
    else if (t.tm_isdst<gt->tm_isdst)
      gt->tm_hour--;
    gt->tm_isdst=-1;
    memcpy(&t, gt, sizeof(t));
    mktime(&t);
    sprintf(small, "@%4u%02u%02u.%02u%02u%02u.UTC",
            t.tm_year+1900, t.tm_mon+1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);
  }
#elif 0
  sprintf(small, "@%4u%02u%02u.%02u%02u%02u.UTC", year, mon+1, day,
          hour, min, sec);
  if (tz)
    sprintf(small+strlen(small), "%c%02u", (tz>=0) ? '+' : '-',
            (tz>0) ? tz : -tz);
#else
  tz++; /* to satisfy compiler */
  sprintf(small, "@%4u%02u%02u.%02u%02u%02u", year, mon+1, day,
          hour, min, sec);
#endif
  return 0;
}

static char *recvdate(char *recv, char *date)
{ char *p1, *p2;
  int  np;

  date[0]='\0';
  p1=strrchr(recv, ';');
  if (p1)
  { if (strnicmp(p1, "; id ", 5)==0)
      /* uupc bug */
      p1=strrchr(p1, ',');
    if (p1)
    { p1++;
      while (isspace(*p1)) p1++;
    }
  }
  if (p1==NULL)
  { /* malformed received, find date */
    for (p1=recv; *p1; p1++)
    { if (!isdigit(*p1)) continue;
      np=atoi(p1);
      if ((np<1) || (np>31)) continue;
      for (p2=p1; isdigit(*p2); p2++);
      if ((*p2!=' ') && (*p2!='\t')) continue;
      while ((*p2==' ') || (*p2=='\t')) p2++;
      for (np=0; np<12; np++)
        if (strnicmp(p2, montable[np], 3)==0)
          break;
      if (np==12) continue;
      p2+=3;
      if ((*p2!=' ') && (*p2!='\t')) continue;
      /* fuck! */
      break;
    }
    if (*p1==0) p1=NULL;
  }
  if (p1)
  { while (isspace(*p1)) p1++;
    if (*p1=='(')
    { p2=strchr(p1, ')');
      if (p2)
      { p1=p2+1;
        while (isspace(*p1)) p1++;
      }
    }
    if ((*p1=='\0') || (*p1=='(') || (*p1=='[') || (*p1=='\0'))
      return NULL;
    p2=strrchr(p1, '(');
    if (p2)
      if (strlen(p2)>12)
      { *p2--='\0';
        while (isspace(*p2)) *p2--='\0';
      }
    p2=strrchr(p1, '[');
    if (p2)
    { *p2--='\0';
      while (isspace(*p2)) *p2--='\0';
    }
    if (strlen(p1)>60)
    { /* too long */
      return NULL;
    }
    if (shortvia)
    { *date=' ';
      if (shortdate(p1, date+1))
      { strcpy(date, "; ");
        strcpy(date+2, p1);
      }
    }
    else
    { strcpy(date, "; ");
      strcpy(date+2, p1);
    }
    p2=strchr(date, '\r');
    if (p2) *p2='\0';
  }
  return p1;
}

static int ftndomain(char *str, ftnaddr *addr, char *domain)
{ char *p;
  int i;
  /* check for ftn-style */
  if ((tolower(str[0])=='p') && isdigit(str[1]))
  { addr->point=atoi(str+1);
    for (p=str+1; isdigit(*p); p++);
    if (*p!='.')
      return 1;
    p++;
  }
  else
  { addr->point=0;
    p=str;
  }
  if (tolower(*p)!='f') return 1;
  if (!isdigit(*++p)) return 1;
  addr->node=atoi(p);
  for (p++; isdigit(*p); p++);
  if (*p!='.') return 1;
  p++;
  if (tolower(*p)!='n') return 1;
  if (!isdigit(*++p)) return 1;
  addr->net=atoi(p);
  for (p++; isdigit(*p); p++);
  if (*p!='.') return 1;
  p++;
  if (tolower(*p)!='z') return 1;
  if (!isdigit(*++p)) return 1;
  addr->zone=atoi(p);
  for (p++; isdigit(*p); p++);
  if (*p++!='.') return 1;
  /* change domain to ftndomain */
  for (i=0; i<naka; i++)
    if (stricmp(p, myaka[i].domain)==0)
      break;
  if (i==naka)
    for (i=0; i<naka; i++)
      if (strnicmp(p, myaka[i].domain, strlen(p))==0 &&
          myaka[i].domain[strlen(p)]=='%')
        break;
  if (i==naka)
    i=akamatch(addr->zone, addr->net, addr->node);
  strcpy(domain, myaka[i].ftndomain);
  return 0;
}

char *rcvfrom(char *recv) /* save string recv */
{
  static char ftnrecv[256];
  char domain[80];
  ftnaddr addr;
  char *from, *p, *p1;
  int  incomment, wasspace;

  /* find " from " section */
  incomment=0;
  wasspace=1;
  from=NULL;
  for (p=recv; *p; p++)
  { if (*p=='(')
    { incomment++;
      continue;
    }
    if (*p==')' && incomment)
    { incomment--;
      continue;
    }
    if (incomment) continue;
    if (isspace(*p))
    { wasspace=1;
      continue;
    }
    if (*p==';') break;
    if (!wasspace) continue;
    if (strncmp(p, "from", 4)==0 && isspace(p[4]))
    { from=p;
      continue;
    }
    if (!from) continue;
    if ((strncmp(p, "for",  3)==0 && isspace(p[3])) ||
        (strncmp(p, "with", 4)==0 && isspace(p[4])) ||
        (strncmp(p, "via",  3)==0 && isspace(p[3])) ||
        (strncmp(p, "id",   2)==0 && isspace(p[2])) ||
        (strncmp(p, "by",   2)==0 && isspace(p[2])))
      break;
  }
  if (from==NULL) return NULL;
  p1=recvdate(recv, domain);
  if (p1<p) p=p1;
  if (p<=from) return NULL;
  p1=malloc((unsigned)(p-from)+1);
  if (p1==NULL) return NULL;
  strncpy(p1, from, (unsigned)(p-from));
  p1[(unsigned)(p-from)]='\0';
  from=p1;
  /* remove trailing spaces */
  for (p=from+strlen(from)-1; isspace(*p); *p--='\0');
  /* remove double comments */
  p1=NULL;
  for (p=from; *p; p++)
  { if (*p=='(')
    { if (incomment==1)
        p1=p;
      incomment++;
      continue;
    }
    if (*p==')')
    { if (incomment==2)
      { mstrcpy(p1, p+1);
        p=p1-1;
      }
      incomment--;
      continue;
    }
  }
  /* look into last brackets */
rcvagain:
  p=strrchr(from, '(');
  if (p)
  { if (strstr(p, "localhost"))
    { *p='\0';
      goto rcvagain;
    }
    else
    { /* simple get first word */
      if (isdigit(p[1]) && strstr(p, "bytes"))
      { for (*p--='\0'; isspace(*p) && p>=from; *p--='\0');
        goto rcvagain;
      }
      p++;
      if (strnicmp(p, "src addr", 8)==0)
        p+=8;
      else if (strnicmp(p, "ident:", 6)==0)
        p+=6;
      else if (strnicmp(p, "unverified", 11)==0)
        p+=11;
      else if (strnicmp(p, "helo=", 5)==0)
        p+=5;
      while (isspace(*p)) p++;
      mstrcpy(from, p);
      if (*from=='[')
      { mstrcpy(from, from+1);
        p=strchr(from, ']');
        if (p) *p='\0';
      }
      for (p=from; *p; p++)
      { if (isspace(*p) || *p==')' || *p=='(' || *p=='[' || *p==']')
        { *p='\0';
          break;
        }
      }
      goto makerecv;
    }
  }
  /* nothing in the brackets - simple get first word */
  for (p=from+4; isspace(*p); p++);
  if (strncmp(p, "helo=", 5)==0)
    p+=5;
  mstrcpy(from, p);
  for (p=from; *p && (!isspace(*p)) && (*p!='(') && (*p!='['); p++);
  *p='\0';
  if (strcmp(from, "localhost")==0)
    *from='\0';
makerecv:
  if (*from=='\0')
  { /* Oops! */
    free(from);
    return NULL;
  }
  if (strlen(from)>128)
  { /* too long */
    free(from);
    return NULL;
  }
  /* in from - name, that must be in the "Recd from" */
  if (strnicmp(from, "root@", 5)==0)
    mstrcpy(from, from+5);
  p=strchr(from, '@');
  if (p) p++;
  else p=from;
  if (ftndomain(p, &addr, domain)==0)
  { if (addr.point)
      sprintf(from, "%u:%u/%u.%u@%s",
              addr.zone, addr.net, addr.node, addr.point, domain);
    else
      sprintf(from, "%u:%u/%u@%s",
              addr.zone, addr.net, addr.node, domain);
  }
  recvdate(recv, domain);
#ifdef HAVE_SNPRINTF
  snprintf(ftnrecv, sizeof(ftnrecv)-1, "\x01Recd:from %s%s", from, domain);
  strcat(ftnrecv, "\r");
#else
  sprintf(ftnrecv, "\x01Recd:from %s%s\r", from, domain);
#endif
  free(from);
  return ftnrecv;
}

void rcvconv(char *recv)
{ 
  char *p, *p1, *by;
  int  incomment, wasspace;
  char domain[80];
  ftnaddr addr;
  static char product[80], date[80];

  /* leave only "by" section and date */
  /* parse domain, if ftn-style and (...) - to start */
  debug(8, "RcvConv('%s')", recv);
  s[0]=0;
  product[0]=0;
  /* find " by " section */
  incomment=0;
  wasspace=1;
  by=NULL;
  for (p=recv; *p; p++)
  { if (*p=='(')
    { incomment++;
      continue;
    }
    if (*p==')' && incomment)
    { incomment--;
      continue;
    }
    if (incomment) continue;
    if (isspace(*p))
    { wasspace=1;
      continue;
    }
    if (*p==';') break;
    if (!wasspace) continue;
    if (strncmp(p, "by", 2)==0 && isspace(p[2]))
    { by=p;
      continue;
    }
    if (!by) continue;
    if ((strncmp(p, "for",  3)==0 && isspace(p[3])) ||
        (strncmp(p, "with", 4)==0 && isspace(p[4])) ||
        (strncmp(p, "via",  3)==0 && isspace(p[3])) ||
        (strncmp(p, "id",   2)==0 && isspace(p[2])) ||
        (strncmp(p, "from", 4)==0 && isspace(p[4])))
      break;
  }
  p1=recvdate(recv, date);
  if (p1<p) p=p1;
  if (p<=by) by=NULL;
  if (by)
  { char c=*p;
    *p='\0';
    if (by[3])
      p1=strdup(by+3);
    else
      p1=strdup("?");
    debug(20, "by=%p", p1);
    *p=c;
    mstrcpy(recv+5, by+3);
    by=p1;
  }
  else
  { by=strdup("?");
    debug(20, "by=%p", by);
  }
  if (by==NULL)
  { logwrite('!', "rcvconv: not enough memory!\n");
    return;
  }
  /* All from brackets to product */
  incomment=0;
  for (p=by; *p; p++)
  { 
nextprod:
    if (*p==')' && incomment)
      if (--incomment==0)
      { mstrcpy(p, p+1);
        if (*p=='\0') break;
        goto nextprod;
      }
    if (*p=='(')
    { if (incomment++==0)
      { if (product[0] && (strlen(product)>=sizeof(product)-3))
          strcat(product, ", ");
        mstrcpy(p, p+1);
        if (*p=='\0') break;
        goto nextprod;
      }
    }
    if (!incomment) continue;
    if (strlen(product)>=sizeof(product)-3)
      continue;
    product[strlen(product)+1]='\0';
    product[strlen(product)]=*p;
    mstrcpy(p, p+1);
    if (*p=='\0') break;
    goto nextprod;
  }
  for (p=by; isspace(*p); p++);
  if (p!=by) mstrcpy(by, p);
  if (*by=='\0')
    strcpy(by, "?");
  for (p=by+strlen(by)-1; isspace(*p); *p--='\0');
  if (strlen(by)>60 || ftndomain(by, &addr, domain))
  { mstrcpy(recv+5, by);
    debug(20, "free(%p)", by);
    free(by);
    debug(20, "free(%p) done", by);
    strcat(recv, date);
    if (shortvia && product[0])
    { strcat(recv, " ");
      strcat(recv, product);
    }
    debug(8, "RcvConv: not fido via, returning '%s'", recv);
    strcat(recv, "\r");
    return;
  }
  debug(20, "free(%p)", by);
  free(by);
  debug(20, "free(%p) done", by);
  /* ftn-style */
  if (date[0]==';')
  { strcpy(s, product);
    if (s[0]) strcat(s, " ");
  }
  else
    s[0]=0;
  sprintf(s+strlen(s), "%u:%u/%u", addr.zone, addr.net, addr.node);
  if (addr.point)
    sprintf(s+strlen(s), ".%u", addr.point);
  strcat(s, "@");
  strcat(s, domain);
  strcat(s, date);
  if (date[0]!=';' && product[0])
  { strcat(s, " ");
    strcat(s, product);
  }
  strcpy(recv+5, s);
  debug(8, "RcvConv: returning '%s'", recv);
  strcat(recv, "\r");
}

#ifndef UNIX
void renbad(char *fname)
{ int  i, r, h;
  char *p;

  if (bypipe) return;
  debug(4, "RenBad(%s)", fname);
  if (!conf)
  { /* move namec to uupc\spool\bad.job */
    strcpy(named, spool_dir);
    strcat(named, "bad.job");
    mkdir(named);
    strcat(named, PATHSTR);
    p=strrchr(namec, PATHSEP);
    if (p) p++;
    else p=namec;
    strcat(named, p);
    if (rename(namec, named))
    { /* copy file */
      debug(4, "RenBad: can't rename %s to %s, trying to copy", namec, named);
      f=open(namec, O_BINARY | O_RDONLY);
      if (f==-1)
      { logwrite('?', "Can't open %s: %s!\n", namec, strerror(errno));
        return;
      }
      h=open(named, O_CREAT | O_EXCL | O_BINARY | O_RDWR, S_IREAD | S_IWRITE);
      if (h==-1)
      { logwrite('?', "Can't create %s: %s!\n", named, strerror(errno));
        close(f);
        f=-1;
        return;
      }
      while ((r=read(f, str, sizeof(str)))!=0)
        write(h, str, r);
      close(f);
      close(h);
      unlink(namec);
      f=-1;
    }
    naddr=0; /* not c-file processing */
    logwrite('!', "%s moved to %s\n", namec, named);
    return;
  }
  strcpy(str, fname);
  p=strrchr(str, PATHSEP);
  if (p==NULL) p=str;
  p=strchr(p, '.');
  if (p==NULL) p=str+strlen(str);
  strcpy(p, ".bad");
  i=0;
  while (!access(str, 0))
    p[3]=(char)((i++)+'0');
  rename(fname, str);
  logwrite('!', "%s renamed to %s\n", fname, str);
}
#endif

void badlet(void)
{
  if (bypipe) return;
  if (f!=-1)
    close(f);
  f=-1;
  debug(4, "BadLet");
#ifndef UNIX
  renbad(named);
#endif
}

void stripspc(char *str)
{ char *p;
  for (p=str+strlen(str)-1; ((*p==' ') || (*p=='\t')) && (p>=str); p--)
    *p=0;
}

static char *HOLDTXT1 =
"   Hello %s!\r"
"   Here's message from internet to you, but I can't gate it and send "
"by default routing because it's too large. :-(  I held it for you.\r"
"   Please, don't send binary information via my gate.\r"
"Your message header:\r"
"===============================\r";
static char *ATTTXT1 =
"   Hello %s!\r"
"   Here's attach from internet to you.\r"
"   Please, don't send binary information via my gate.\r"
"Your message header:\r"
"===============================\r";
static char *HOLDTXT2 =
"===============================\r"
"  Poll %u:%u/%u.%u for get message body.\r"
"                         Lucky carrier,\r"
"                                   Gate Daemon.\r";

static void putaddr(char *str, uword zone, uword net, uword node, uword point)
{ if (point)
    sprintf(str, "%u:%u/%u.%u", zone, net, node, point);
  else
    sprintf(str, "%u:%u/%u", zone, net, node);
}

static void setvars(char *realname, char *fromaddr, char *subj)
{ int i;
  char *p;
  time_t curtime;
  struct tm *curtm;

  curtime=time(NULL);
  curtm = localtime(&curtime);
  if (attname[0])
    setvar("subject", "Attach held");
  else
    setvar("subject", "Too large message held");
  debug(12, "SetVars: set Subject to '%s'", getvar("Subject"));
  setvar("fromname", realname);
  debug(12, "SetVars: set FromName to '%s'", getvar("FromName"));
  setvar("fromaddr", fromaddr);
  debug(12, "SetVars: set FromAddr to '%s'", getvar("FromAddr"));
  setvar("gatename", MYNAME);
  debug(12, "SetVars: set GateName to '%s'", getvar("GateName"));
  putaddr(tstr, myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node,
          myaka[curaka].point);
  setvar("gateaddr", tstr);
  debug(12, "SetVars: set GateAddr to '%s'", getvar("GateAddr"));
  setvar("toname", msghdr.to);
  debug(12, "SetVars: set ToName to '%s'", getvar("ToName"));
  putaddr(tstr, zone, net, node, point);
  setvar("toaddr", tstr);
  debug(12, "SetVars: set ToAddr to '%s'", getvar("ToAddr"));
  if (subj)
  { strncpy(tstr, subj, sizeof(tstr));
    tstr[sizeof(tstr)-1]='\0';
    if (strlen(tstr)>60)
    { tstr[60]='\0';
      strcat(tstr, "...");
    }
  }
  else
    tstr[0]='\0';
  setvar("oldsubject", tstr);
  debug(12, "SetVars: set OldSubject to '%s'", getvar("OldSubject"));
  setvar("date", s);
  sprintf(tstr, "%lu", tsize);
  setvar("size", tstr);
  debug(12, "SetVars: set Size to '%s'", getvar("Size"));
  sprintf(tstr, "%02u %s %02u", curtm->tm_mday, montable[curtm->tm_mon],
          curtm->tm_year%100);
  setvar("localdate", tstr);
  debug(12, "SetVars: set LocalDate to '%s'", getvar("LocalDate"));
  sprintf(tstr, "%02u:%02u:%02u",
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
  setvar("localtime", tstr);
  debug(12, "SetVars: set LocalTime to '%s'", getvar("LocalTime"));
  putaddr(tstr, uplink[myaka[curaka].uplink].zone,
          uplink[myaka[curaka].uplink].net, uplink[myaka[curaka].uplink].node,
          uplink[myaka[curaka].uplink].point);
  setvar("uplink", tstr);
  debug(12, "SetVars: set Uplink to '%s'", getvar("Uplink"));
  if (attname[0])
  { setvar("reason", "attach");
    if (longname)
    { setvar("filename", longname);
      debug(12, "SetVars: set FileName to '%s'", getvar("FileName"));
    }
    p=strrchr(attname, PATHSEP);
    if (p) *p='\0';
    setvar("filepath", p ? attname : "");
    setvar("storefilename", p ? p+1 : attname);
    if (p) *p=PATHSEP;
  }
  else
    setvar("reason", "size");
  debug(12, "SetVars: set Reason to '%s'", getvar("Reason"));
  if (origmsgid)
  { getvalue(origmsgid, tstr, sizeof(tstr));
    if (tstr[0])
    { setvar("Message-Id", tstr);
      debug(12, "SetVars: set Message-Id to '%s'", getvar("Message-Id"));
    }
  }
  else
  { for (i=0; i<cheader; i++)
    { if (strnicmp(pheader[i], "\1RFCID:", 7)==0)
      { for (p=pheader[i]+7; isspace(*p); p++);
        p=strdup(p-1);
        if (p==NULL) break;
        *p='<';
        p[strlen(p)-1]='>'; /* change '\r' to '>' */
        setvar("Message-Id", p);
        debug(12, "SetVars: set Message-Id to '%s'", getvar("Message-Id"));
        free(p);
        break;
      }
    }
  }
}

void voidfunc(void)
{}
int voidgets(char *str, unsigned size)
{ str[size-1]='\0'; /* for satisfy compiler */
  return 0;
}

static char dhex(int i)
{ return (i>9) ? 'a'+i-10 : '0'+i;
}

int createattach(char *fname)
{ FILE *fatt=NULL;
  int  fhold;
  char *p;
  int  i, j;
  DIR  *dd;
  struct dirent *df;
  time_t curtime;
  struct tm *curtm;

  curtime = time(NULL);
  curtm = localtime(&curtime);
  /* write attach */
  for (i=0; i<nuplinks; i++)
    if ((zone==uplink[i].zone) &&
        (net==uplink[i].net) &&
        (node==uplink[i].node) &&
        (point==uplink[i].point))
      break;
  if (i!=nuplinks)
    /* do not create attach for uplink */
    return 0;
  debug(4, "CreateAttach(%s)", fname);
  strcpy(msghdr.subj, fname);
  strcpy(msghdr.from, MYNAME);
  msghdr.orig_node=myaka[curaka].node;
  msghdr.orig_net=myaka[curaka].net;
  sprintf(msghdr.date, "%02u %s %02u  %02u:%02u:%02u",
          curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year%100,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec);
  if (routeattach)
  {
    msghdr.attr=msgPRIVATE | msgFORWD | msgKILLSENT | msgFILEATT;
    if (nextmsg())
      return 1;
    p=strrchr(fname, PATHSEP);
    if (p) strcpy(msghdr.subj, p+1);
    writehdr();
    fatt=fout;
    goto writeattbody;
  }
  if (binkout[0]==0 &&
#ifndef __MSDOS__
      lbso[0]==0 && tlboxes[0]==0 && longboxes[0]==0 &&
#endif
      tboxes[0]==0)
  {
createatt:
    msghdr.attr=msgPRIVATE | msgLOCAL | msgHOLD | msgKILLSENT | msgFILEATT;
    /* create .msg not by nextmsg() for packmail case */
    i=0;
    removeslash(netmaildir);
    dd=opendir(netmaildir);
    addslash(netmaildir);
    if (dd==NULL)
      logwrite('!', "Can't opendir %s: %s\n", netmaildir, strerror(errno));
    else
    { while ((df=readdir(dd))!=NULL)
      { if (chkregexp(df->d_name, MSGREGEX
#ifndef __MSDOS__
                      , &regbufmsg
#endif
                      ))
          continue;
        if (atoi(df->d_name)>i)
          i=atoi(df->d_name);
      }
      closedir(dd);
    }
    for (j=i+1; j>0 && j<i+1000; j++)
    { sprintf(str, "%s%u.msg", netmaildir, j);
      fatt=myfopen(str, "wb");
      if (fatt!=NULL)
        break;
    }
    if (fatt==NULL)
    { logwrite('?', "Can't create %s: %s!\n", str, strerror(errno));
      unlink(msghdr.subj);
      return 1;
    }
    for (i=0; i<5; i++)
      if (flock(fileno(fatt), LOCK_EX | LOCK_NB))
        sleep(1);
      else
        break;
    if (i==5)
    { logwrite('?', "Can't lock %s: %s!\n", str, strerror(errno));
      fclose(fatt);
      unlink(str);
      return 1;
    }
    debug(5, "CreateAttach: write to %s", str);
    fwrite(&msghdr, sizeof(msghdr), 1, fatt);
writeattbody:
    fprintf(fatt, "\x01INTL %u:%u/%u %u:%u/%u\r", zone, net, node,
            myaka[curaka].zone, myaka[curaka].net, myaka[curaka].node);
    fprintf(fatt, "\x01""FLAGS %sKFS\r", routeattach ? "" : "DIR ");
    if (myaka[curaka].point)
      fprintf(fatt, "\x01MSGID: %u:%u/%u.%u %lx\r", myaka[curaka].zone,
            myaka[curaka].net, myaka[curaka].node, myaka[curaka].point, msgid);
    else
      fprintf(fatt, "\x01MSGID: %u:%u/%u %lx\r", myaka[curaka].zone,
              myaka[curaka].net, myaka[curaka].node, msgid);
    fprintf(fatt, "\x01PID: " NAZVA "\r");
    if (point)
      fprintf(fatt, "\x01TOPT %u\r", point);
    if (myaka[curaka].point)
      fprintf(fatt, "\x01""FMPT %u\r", myaka[curaka].point);
    if (!routeattach)
    { fwrite("", 1, 1, fatt);
      fflush(fatt);
      flock(fileno(fatt), LOCK_UN);
      fclose(fatt);
    }
  }
  else if (binkout[0])
  { /* create .hlo */
    ftnaddr fnode;
    char *bsyname;
    fnode.zone=zone, fnode.net=net, fnode.node=node, fnode.point=point;
    if ((bsyname=GetBinkBsyName(&fnode, binkout, myaka[0].zone))==NULL)
      goto createatt;
    if (access(bsyname, 0)==0)
      goto createatt;
    if (SetBinkSem(&fnode, binkout, myaka[0].zone))
      goto createatt;
    p=strrchr(bsyname, '.');
    strcpy(p+1, "hlo");
    if (access(bsyname, 0)==0)
      fhold=open(bsyname, O_TEXT | O_RDWR);
    else
      fhold=open(bsyname, O_TEXT | O_RDWR | O_EXCL | O_CREAT, S_IREAD|S_IWRITE);
    if (fhold==-1)
    { DelBinkSem(&fnode, binkout, myaka[0].zone);
      goto createatt;
    }
    debug(5, "CreateAttach: write to %s", str);
    lseek(fhold, 0, SEEK_END);
    str[0]='^';
    strcpy(str+1, msghdr.subj);
    strcat(str, "\n");
    write(fhold, str, strlen(str));
    close(fhold);
    DelBinkSem(&fnode, binkout, myaka[0].zone);
  }
#ifndef __MSDOS__
  else if (lbso[0])
  { /* create .Hold.List */
    ftnaddr fnode;
    char *bsyname;
    fnode.zone=zone, fnode.net=net, fnode.node=node, fnode.point=point;

    if ((bsyname=GetLBSOBsyName(&fnode, myaka[curaka].ftndomain, lbso))==NULL)
      goto createatt;
    if (access(bsyname, 0)==0)
      goto createatt;
    if (SetLBSOSem(&fnode, myaka[curaka].ftndomain, lbso))
      goto createatt;
    p=strrchr(bsyname, '.');
    strcpy(p+1, "Hold.List");
    if (access(bsyname, 0)==0)
      fhold=open(bsyname, O_TEXT | O_RDWR);
    else
      fhold=open(bsyname, O_TEXT | O_RDWR | O_EXCL | O_CREAT, S_IREAD|S_IWRITE);
    if (fhold==-1)
    { DelLBSOSem(&fnode, myaka[curaka].ftndomain, lbso);
      goto createatt;
    }
    debug(5, "CreateAttach: write to %s", bsyname);
    lseek(fhold, 0, SEEK_END);
    str[0]='^';
    strcpy(str+1, msghdr.subj);
    strcat(str, "\n");
    write(fhold, str, strlen(str));
    close(fhold);
    DelLBSOSem(&fnode, myaka[curaka].ftndomain, lbso);
  }
  else if (longboxes[0])
  { sprintf(str, "%s%s.%hu.%hu.%hu.%hu.hold", longboxes,
            myaka[curaka].ftndomain, zone, net, node, point);
    mkdir(str);
    strcat(str, PATHSTR);
    p=strrchr(msghdr.subj, PATHSEP);
    if (p) p++;
    else p=msghdr.subj;
    strcat(str, p);
    if (rename(msghdr.subj, str))
    { if (copyfile(msghdr.subj, str))
        goto createatt;
      unlink(msghdr.subj);
    }
  }
  else if (tlboxes[0])
  { sprintf(str, "%s%hu.%hu.%hu.%hu.h", tlboxes,
            zone, net, node, point);
    mkdir(str);
    strcat(str, PATHSTR);
    p=strrchr(msghdr.subj, PATHSEP);
    if (p) p++;
    else p=msghdr.subj;
    strcat(str, p);
    if (rename(msghdr.subj, str))
    { if (copyfile(msghdr.subj, str))
        goto createatt;
      unlink(msghdr.subj);
    }
  }
#endif
  else if (tboxes[0])
  { sprintf(str, "%s%c%c%c%c%c%c%c%c.%c%ch", tboxes,
            dhex(zone/32),   dhex(zone%32),
            dhex(net/1024),  dhex((net/32)%32),  dhex(net%32),
            dhex(node/1024), dhex((node/32)%32), dhex(node%32),
            dhex(point/32),  dhex(point%32));
    mkdir(str);
    strcat(str, PATHSTR);
    p=strrchr(msghdr.subj, PATHSEP);
    if (p) p++;
    else p=msghdr.subj;
    strcat(str, p);
    if (rename(msghdr.subj, str))
    { if (copyfile(msghdr.subj, str))
        goto createatt;
      unlink(msghdr.subj);
    }
  }
  msgid++;
  return 0;
}

void writekludges(void)
{
  uword mzone, mnet, mnode, mpoint;

  debug(6, "WriteKludges");
  strncpy(msghdr.subj, getvar("subject"),  sizeof(msghdr.subj)-1);
  strncpy(msghdr.from, getvar("gatename"), sizeof(msghdr.from)-1);
  if (getfidoaddr(&mzone, &mnet, &mnode, &mpoint, getvar("gateaddr")))
  { mzone=myaka[curaka].zone;
    mnet=myaka[curaka].net;
    mnode=myaka[curaka].node;
    mpoint=myaka[curaka].point;
  }
  msghdr.orig_node=mnode;
  msghdr.orig_net=mnet;
  msghdr.attr=(unsigned)attr;
  writehdr();
  fprintf(fout, "\x01INTL %u:%u/%u %u:%u/%u\r", zone, net, node,
          mzone, mnet, mnode);
  if (mpoint)
    fprintf(fout, "\x01MSGID: %u:%u/%u.%u %lx\r", mzone,
            mnet, mnode, mpoint, msgid);
  else
    fprintf(fout, "\x01MSGID: %u:%u/%u %lx\r", mzone,
            mnet, mnode, msgid);
  fprintf(fout, "\x01PID: " NAZVA "\r");
  if (point)
    fprintf(fout, "\x01TOPT %u\r", point);
  if (mpoint)
    fprintf(fout, "\x01""FMPT %u\r", mpoint);
  if (attr>0xFFFF)
  { fprintf(fout, "\x01""FLAGS");
    if (attr & msgDIRECT)
      fprintf(fout, " DIR");
    if (attr & msgCFM)
      fprintf(fout, " CFM");
    fprintf(fout, "\r");
  }
}

static int holdnotify(char *realname, char *fromaddr, char *subj)
{ int tpl;
  char *p;

  /* create notify */
  /* first pass by template - get subj, gatename etc. */
  debug(6, "HoldNotify");
  reset_text=voidfunc;
  gettextline=voidgets;
  tplout=0;
  tpl=init_tpl(held_tpl);
  setvars(realname, fromaddr, subj);
#ifdef __OS2__
  easet(msghdr.subj, "DESTNAME", getvar("toname"));
  easet(msghdr.subj, "DESTADDR", getvar("toaddr"));
  easet(msghdr.subj, "FROMNAME", getvar("fromaddr"));
  easet(msghdr.subj, "FROMADDR", getvar("gateaddr"));
  easet(msghdr.subj, "DATE", getvar("date"));
  sprintf(tstr, "%s  %s", getvar("localdate"), getvar("localtime"));
  easet(msghdr.subj, "VIADATE", tstr);
#endif
  if (tpl==0)
    while(templateline(tstr, sizeof(tstr)));
  tplout=1;
  if (getvar("dontsend")==NULL)
  {
    if (nextmsg())
    { unlink(msghdr.subj);
      unlink(str);
      close_tpl();
      debug(6, "HoldNotify ends (nothing to do, dontsend set)");
      return 1;
    }
    /* put header */
    writekludges();
    close_tpl();
    /* body */
    if (tpl==0)
      tpl=init_tpl(held_tpl);
    if (tpl)
    { if (attname[0])
        fprintf(fout, ATTTXT1, msghdr.to);
      else
        fprintf(fout, HOLDTXT1, msghdr.to);
      if (realname[0])
        fprintf(fout, "From: %s <%s>\r", realname, fromaddr);
      else
        fprintf(fout, "From: %s\r", fromaddr);
      fprintf(fout, "To:   %s, %u:%u/%u.%u\r",
              msghdr.to, zone, net, node, point);
      fprintf(fout, "Date: %s\r", s);
      if (subj)
        fprintf(fout, "Subj: %s\r", subj);
      if (longname)
        fprintf(fout, "File: %s\r", longname);
      fprintf(fout, "Size: %lu bytes\r", tsize);
      fprintf(fout, HOLDTXT2, uplink[myaka[curaka].uplink].zone,
              uplink[myaka[curaka].uplink].net,
              uplink[myaka[curaka].uplink].node,
              uplink[myaka[curaka].uplink].point);
    }
    else
    { setvars(realname, fromaddr, subj);
      while (templateline(tstr, sizeof(tstr)))
      { for (p=tstr; *p; p++)
          if (*p=='\n') *p='\r';
        fputs(tstr, fout);
      }
      close_tpl();
    }
  }
  else
    close_tpl();
  if (attname[0]=='\0')
    logwrite('$', "From %s\tto %s %u:%u/%u.%u (Held)\n", fromaddr,
             msghdr.to, zone, net, node, point);
  else
    logwrite('$', "From %s\tto %s %u:%u/%u.%u file %s held\n", fromaddr,
             msghdr.to, zone, net, node, point, attname);
  debug(6, "HoldNotify ends");
  return 0;
}

int holdmsg(char *realname, char *fromaddr, char *subj)
{ int  fhold;
  char *p;
  int  i;

  debug(6, "HoldMsg, realname='%s', fromaddr='%s', subj='%s'",
        realname, fromaddr, subj);
  if (subj)
  { while (isspace(*subj)) subj++;
    p=strchr(subj, '\r');
    if (p) *p='\0';
  }
  hrewind();
  strncpy(msghdr.subj, holdpath, sizeof(msghdr.subj)-10);
  p=msghdr.subj+strlen(msghdr.subj);
  for (i=1; i<99999; i++)
  { sprintf(p, "%u.txt", i);
    if (access(msghdr.subj, 0))
      break;
  }
  fhold=myopen(msghdr.subj, O_TEXT | O_RDWR | O_CREAT);
  if (fhold==-1)
  { logwrite('?', "Can't create %s: %s!\n", msghdr.subj, strerror(errno));
    return 1;
  }
  /* copy */
  debug(6, "HoldMsg: copy message to %s", msghdr.subj);
  while ((i=hread(s, sizeof(s)))>0)
  { if (write(fhold, s, i)!=i)
    { close(fhold);
      unlink(msghdr.subj);
      logwrite('?', "Error writing to %s: %s!\n", msghdr.subj, strerror(errno));
      return 1;
    }
  }
  tsize=filelength(fhold);
  close(fhold);
  strcpy(s, msghdr.date);
  /* attach this */
  if (createattach(msghdr.subj))
    return 1;
  return holdnotify(realname, fromaddr, subj);
}

int holdatt(char *realname, char *fromaddr, char *subj)
{ char *p;
  struct stat st;

  debug(6, "HoldAtt, realname='%s', fromaddr='%s', subj='%s'",
        realname, fromaddr, subj);
  if (subj)
  { while (isspace(*subj)) subj++;
    p=strchr(subj, '\r');
    if (p) *p='\0';
  }
  hrewind();
  strncpy(msghdr.subj, attname, sizeof(msghdr.subj)-1);
  stat(attname, &st);
  tsize=st.st_size;
  strcpy(s, msghdr.date);
  /* attach */
  if (createattach(msghdr.subj))
    return 1;
  return holdnotify(realname, fromaddr, subj);
}

int hread(char *str, unsigned size)
{ int i, r;

  for (i=0; i<size; i++)
  { r=hgetc();
    if (r==EOF) return i;
    *str++=r;
  }
  return i;
}

int hgets(void)
{ int i, r;
  for (i=0; i<sizeof(str)-1; )
  { r=hgetc();
    if (r==EOF)
    { str[i]=0;
      if (i==0)
        return 0;
      return 1;
    }
    if (r=='') r=softCR;
#if 0
    if (r=='\n') r='\r';
    str[i++]=r;
    if (r=='\r')
      break;
#else
    if (r=='\n')
    { str[i++]='\r';
      break;
    }
    str[i++]=r;
#endif
  }
  str[i]=0;
  return 1;
}

char *myrealloc(char *oldptr, long oldsize, long newsize)
{ /* save old area if realloc fail */
  char *newptr;

  newptr=farmalloc(newsize);
  if (newptr==NULL) return NULL;
/* #ifdef __MSDOS__ */
#if 1
  { char _Huge *p1, _Huge *p2;
    long i;

    p1=newptr, p2=oldptr;
    for(i=0; i<oldsize; i++)
      *p1++=*p2++;
  }
#else
  memcpy(newptr, oldptr, oldsize);
#endif
  farfree(oldptr);
  return newptr;
}

void badpst(char *reason)
{
  int  inhdr, fbad, i, j, cont, wasnews, wasmime, wasconttype;
  char *p;
  time_t curtime;
  struct tm *curtm;

  curtime = time(NULL);
  curtm = localtime(&curtime);
  logwrite('?', "Message moved to "BADPSTNAME", reason: %s\n", reason);
  ibuf=BUFSIZE;
  hrewind();
  if (access(badmail, 0))
    fbad=myopen(badmail, O_TEXT | O_RDWR | O_CREAT | O_EXCL);
  else
    fbad=myopen(badmail, O_TEXT | O_RDWR | O_APPEND);
  if (fbad==-1)
  { logwrite('?', "Can't open %s: %s!\n", badmail, strerror(errno));
    return;
  }
  for (i=0; i<5; i++)
  { if (flock(fbad, LOCK_EX | LOCK_NB))
      sleep(1);
    else
      break;
  }
  if (i==5)
  { logwrite('?', "Can't lock %s: %s!\n", badmail, strerror(errno));
    return;
  }
#ifndef UNIX
  if (uupcver==KENDRA)
    write(fbad, UUPCEXTSEP "\n", 21);
#endif
  if (cnews)
  { sprintf(str, "From uucp %s %s %02u %02u:%02u:%02u %02u\n",
    weekday[curtm->tm_wday],
    montable[curtm->tm_mon], curtm->tm_mday,
    curtm->tm_hour, curtm->tm_min, curtm->tm_sec, curtm->tm_year+1900);
  }
  else
  { hgets();
    p=strchr(str, '\r');
    if (p) *p='\n';
  }
  write(fbad, str, strlen(str));
  inhdr=1;
  empty=0;
  cont=0;
  wasnews=0;
  wasmime=0;
  wasconttype=0;
  while (hgets())
  { if (cont)
    { if (strpbrk(str, "\n\r"))
        cont=0;
      write(fbad, str, strlen(str));
      continue;
    }
    if (strpbrk(str, "\n\r")==NULL)
      cont=1;
    p=strchr(str, '\r');
    if (p) *p='\n';
    if (inhdr && strnicmp(str, "Newsgroups:", 11)==0)
      wasnews=1;
    if (inhdr && strnicmp(str, "Mime-Version:", 13)==0)
    { if (wasmime)
        continue;
      wasmime=1;
    }
    if (inhdr && (!wasmime) && strnicmp(str, "Content-", 8)==0)
    { write(fbad, "Mime-Version: 1.0\n", 18);
      wasmime=1;
    }
    if (inhdr && strnicmp(str, "Content-Type:", 13)==0)
      wasconttype=1;
    if (inhdr && (strcmp(str, "\n")==0))
    { if (conf && !wasnews && newsgroups)
      { write(fbad, "Newsgroups: ", 12);
        write(fbad, newsgroups, strlen(newsgroups));
        write(fbad, "\n", 1);
      }
      if (!wasmime)
        write(fbad, "Mime-Version: 1.0\n", 18);
      if (!wasconttype)
      { write(fbad, "Content-Type: text/plain; charset=", 34);
        write(fbad, intsetname, strlen(intsetname));
        write(fbad, "\n", 1);
      }
      inhdr=0;
    }
    if (cnews && inhdr && !cont)
    { if (strnicmp(str, "Subject:", 8)==0)
      { write(fbad, "Subject: [News] ", 16);
        mstrcpy(str, str+8);
        while ((str[0]==' ') || (str[0]=='\t')) mstrcpy(str, str+1);
      }
    }
    write(fbad, str, strlen(str));
  }
  if (fsize)
  { logwrite('?', "Incorrect cnews packet, renamed to *.bad!\n");
    strcpy(str, "\n\n");
    write(fbad, str, 2);
    flock(fbad, LOCK_UN);
    close(fbad);
    if (fout) fclose(fout);
    fout=NULL;
    for (i=1; i<packnews; i++)
      unlink(namedel[i]);
    if (packnews==0)
      strcpy(namedel[0], msgname);
    else
      unlink(msgname);
    if (begdel==0)
      unlink(namedel[0]);
    else
    { i=myopen(namedel[0], O_BINARY | O_RDWR | O_EXCL);
      if (i!=-1)
      { chsize(i, begdel);
        lseek(i, begdel, SEEK_SET);
        j=0;
        write(i, &j, 2);
        close(i);
      }
    }
    badlet();
    return;
  }
  inhdr='\n';
  if (cont)
    write(fbad, &inhdr, 1);
#ifndef UNIX
  if (uupcver!=KENDRA)
#endif
    write(fbad, &inhdr, 1);
  flock(fbad, LOCK_UN);
  close(fbad);
  debug(6, "BadPst ends");
}

void badmess(char *reason)
{
  int empty, inhdr, ftmp, r, cont;
  char *p;
  static char cmdline[128];
#ifndef __MSDOS__
  int pid;
#endif

  debug(6, "BadMess, reason='%s'", reason);
  if (netmail2pst || cnews)
  { badpst(reason);
    return;
  }
  hrewind();
#ifdef __MSDOS__
  mktempname(TMPNAME, tstr);
  if (access(tstr, 0)==0)
    unlink(tstr);
  ftmp=myopen(tstr, O_TEXT | O_RDWR | O_CREAT | O_EXCL);
  if (ftmp==-1)
  { logwrite('?', "Can't open %s: %s!\n", tstr, strerror(errno));
    badpst(reason);
    return;
  }
#else /* OS/2 */
#ifndef UNIX
  if (uupcver!=SENDMAIL)
    sprintf(cmdline, "%s %s-- %s", rmail,
            (uupcver==KENDRA) ? "" : "-u ", postmast);
  else
#endif
    sprintf(cmdline, "%s -f %s@%s %s", rmail, "uucp", localdom, postmast);
  debug(4, "BadMess: run '%s'", cmdline);
  pid=pipe_system(&ftmp, NULL, cmdline);
  if (pid==-1)
  { logwrite('?', "Can't execute '%s'!\n", cmdline);
    badpst(reason);
    return;
  }
#endif
  logwrite('?', "Message resent to %s, reason: %s\n", postmast, reason);
  hgets();
  p=strchr(str, '\r');
  if (p) *p='\n';
  inhdr=1;
  empty=0;
  cont=0;
  while (hgets())
  { altkoi8(str);
#ifdef __OS2__
    if (str[0]=='\x1a')
      str[0]=' ';
#endif
    if (cont)
    { if (strpbrk(str, "\r\n"))
        cont=0;
      write(ftmp, str, strlen(str));
      continue;
    }
    if (strpbrk(str, "\r\n")==NULL)
      cont=1;
    if ((isbeg(str)==0) && (inhdr==0) && empty && !cont)
    { close(ftmp);
      break;
    }
    p=strchr(str, '\r');
    if (p) *p='\n';
    if (strcmp(str, "\n")==0)
    { if (inhdr)
        inhdr=0;
      else
        empty=1;
    }
    else empty=0;
    write(ftmp, str, strlen(str));
  }
  close(ftmp);
#ifdef __MSDOS__
  if (uupcver==SENDMAIL)
    sprintf(cmdline, "%s -f %s@%s %s <%s",
            rmail, "uucp", localdom, postmast, tstr);
  else
    sprintf(cmdline, "%s %s-- %s <%s",
            rmail, (uupcver==KENDRA) ? "" : "-u ", postmast, tstr);
  debug(4, "BadMess: run '%s'", cmdline);
  r=swap_system(cmdline);
  unlink(tstr);
#else /* OS/2 */
  waitpid(pid, &r, 0);
  r&=0xffff;
  r=((r<<8) | (r>>8)) & 0xffff;
#endif
  if (r && (r!=48))
  { logwrite('?', "rmail retcode %d, message moved to " BADPSTNAME "!\n", r);
    badpst(reason);
  }
  else
    debug(6, "BadMess: rmail retcode %d", r);
}

int params(int argc, char *argv[])
{ int help, i;
  char *p, *p1;

  nconf[0]=0;
  tossbad=nonet=noecho=help=bypipe=nglobal=quiet=cnews=fake=0;
  inconfig=1;
  myname=argv[0];
#ifdef __OS2__
  { PPIB pib;
    PTIB tib;
    DosGetInfoBlocks(&tib, &pib);
    if (pib)
    { if (pib->pib_pchcmd && (strnicmp(pib->pib_pchcmd, "rnews", 5)==0))
      { bypipe=1;
        cnews=1;
      }
      for (myname=pib->pib_pchenv; myname[0] || myname[1]; myname++);
      myname+=2;
    }
  }
#endif
  p=strrchr(myname, '\\');
  if (p==NULL) p=myname;
  else p++;
  if (strchr(p, '/'))
    p=strrchr(p, '/')+1;
  if (strnicmp(p, "rnews", 5)==0)
  { bypipe=1;
    cnews=1;
  }
  for (i=1; i<argc; i++)
  {
    if ((argv[i][0]!='-') && (argv[i][0]!='/'))
    { if (!bypipe)
        printf("Incorrect parameter \"%s\" ignored!\n", argv[i]);
      else
        break;
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
    if ((stricmp(argv[i]+1, "help")==0) || (stricmp(argv[i]+1, "-help")==0) ||
        (stricmp(argv[i]+1, "h")==0) || (stricmp(argv[i]+1, "?")==0))
    { help=1;
      continue;
    }
    if (stricmp(argv[i]+1, "c")==0)
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
    if (stricmp(argv[i]+1, "l")==0)
    {
#ifdef ONLYFILE /* __MSDOS__ */
      if ((ioctl(fileno(stdin), 0) & 0xA0) || (argc<5))
        fprintf(stderr, "Incorrect used switch \"%s\" ignored!\n", argv[i]);
      else
#endif
      {
        bypipe=1;
        noecho=1;
      }
      continue;
    }
    if (stricmp(argv[i]+1, "r")==0)
    {
      bypipe=1;
      cnews=1;
      continue;
    }
    if (stricmp(argv[i]+1, "q")==0)
    { quiet=1;
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
        fprintf(stderr, "Incorrect %s switch ignored!\n", argv[i]);
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
    if (bypipe && (strcmp(argv[i], "--")==0))
    { i++;
      break; /* end of switches */
    }
    fprintf(stderr, "Unknown switch \"%s\" ignored!\n", argv[i]);
  }
  if (help)
  {
    puts(VERSION);
    puts("Internet -> FTN Gate");
    puts("Copyright (C) Pavel Gulchouck 2:463/68 aka gul@gul.kiev.ua");
    puts("   Usage:");
    puts("rel2fido" EXEEXT " [<switches>]");
    puts("   Switches:");
    puts("-noecho         - don't gating echomail");
    puts("-nonet          - don't gating netmail");
    puts("-tossbad        - retoss bad messages");
    puts("-c<filename>    - config file (default is gate.cfg)");
    puts("-D<var>=<value> - set variable for config and templates");
    puts("-l              - run by pipe in hostpath");
    puts("-r              - run as rnews");
    puts("-q              - be quiet");
    puts("-[x|X]<level>   - debug level");
    puts("-fake           - do nothing, only save params and stdin");
    puts("--              - no switches after this (use only with -l)");
    puts("-?, -h          - this help");
  }
  if (help && (!tossbad) && (!nonet) && (!noecho) && (nconf[0]==0))
  { /* /? only */
    return 1;
  }
#if defined(HAVE_GETUID) && defined(HAVE_GETEUID) && defined(HAVE_GETGID) && defined(HAVE_GETEGID)
  if (nconf[0] && (getuid()!=geteuid() || getgid()!=getegid()))
  { puts("You do not allowed to use -c switch");
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
  debug(4, "bypipe: %u, cnews: %u, noecho: %u, nonet: %u",
        bypipe, cnews, noecho, nonet);
  if (bypipe && !cnews)
  {
    i++;
    if (i+1>argc)
    { fprintf(stderr, "Incorrect params!\n");
      return 5;
    }
    if (i+1==argc)
      strcpy(addr, argv[i]);
    else if (strpbrk(argv[i], "@!"))
    { strcpy(addr, argv[i]);
      strcat(addr, "!");
      strcat(addr, argv[i+1]);
    }
    else
    { strcpy(addr, argv[i+1]);
      strcat(addr, "@");
      strcat(addr, argv[i]);
    }
    i+=2;
    if (i+1==argc)
      strcpy(envelope_from, argv[i]);
    else if (i+1<argc)
    { if (strpbrk(argv[i], "@!"))
      { strcpy(envelope_from, argv[i]);
        strcat(envelope_from, "!");
        strcat(envelope_from, argv[i+1]);
      }
      else
      { strcpy(envelope_from, argv[i+1]);
        strcat(envelope_from, "@");
        strcat(envelope_from, argv[i]);
      }
    }
    if (envelope_from[0])
      debug(1, "Set envelope_from to %s", envelope_from);
  }
  return 0;
}

void copybad(void)
{ int fbad, fbox, i;
  long oldlen;
  struct stat st;

  debug(7, "CopyBad");
  if (stat(badmail, &st))
    return;
  if (st.st_size==0)
  { unlink(badmail);
    return;
  }
  if (access(userbox, 0))
  { if (rename(badmail, userbox)==0)
      return;
    fbox=myopen(userbox, O_RDWR | O_BINARY | O_CREAT | O_EXCL);
  }
  else
    fbox=myopen(userbox, O_RDWR | O_BINARY | O_APPEND);
  if (fbox==-1)
  { logwrite('?', "Can't open %s: %s!\n", userbox, strerror(errno));
    return;
  }
  for (i=0; i<5; i++)
  { if (flock(fbox, LOCK_EX | LOCK_NB))
      sleep(1);
    else
      break;
  }
  if (i==5)
  { logwrite('?', "Can't lock %s: %s!\n", userbox, strerror(errno));
    return;
  }
  oldlen=filelength(fbox);
  fbad=myopen(badmail, O_RDONLY | O_BINARY);
  if (fbad==-1)
  { logwrite('?', "Can't open %s: %s!\n", badmail, strerror(errno));
    flock(fbox, LOCK_UN);
    close(fbox);
    return;
  }
  for (i=0; i<5; i++)
  { if (flock(fbad, LOCK_EX | LOCK_NB))
      sleep(1);
    else
      break;
  }
  if (i==5)
  { logwrite('?', "Can't lock %s: %s!\n", badmail, strerror(errno));
    flock(fbox, LOCK_UN);
    close(fbox);
    close(fbad);
    return;
  }
  for (i=read(fbad, buffer, BUFSIZE); i; i=read(fbad, buffer, BUFSIZE))
  {
    if (write(fbox, buffer, i)!=i)
    {
      logwrite('?', "Can't write to %s: %s!\n", userbox, strerror(errno));
      lseek(fbox, oldlen, SEEK_SET);
      chsize(fbox, oldlen);
      flock(fbox, LOCK_UN);
      close(fbox);
      flock(fbad, LOCK_UN);
      close(fbad);
      return;
    }
    if (i<BUFSIZE) break;
  }
  flock(fbox, LOCK_UN);
  close(fbox);
  flock(fbad, LOCK_UN);
  close(fbad);
  unlink(badmail);
}

static char smon[8];

int parsedate(char *p)
{ int k;
  int day, year, hour, min, sec;

  debug(14, "ParseDate('%s')", p);
  while (*p && (!isdigit(*p))) p++;
  day = atoi(p);
  if (day<1 || day>31) return 1;
  while (*p && (isdigit(*p) || isspace(*p))) p++;
  if (strlen(p)<4) return 1;
  strncpy(smon, p, 4);
  smon[3]='\0';
  p+=3;
  if (!isspace(*p)) return 1;
  while (*p && isspace(*p)) p++;
  if (!isdigit(*p)) return 1;
  year = atoi(p);
  while (*p && isdigit(*p)) p++;
  if (!isspace(*p)) return 1;
  while (isspace(*p)) p++;
  if (!isdigit(*p)) return 1;
  hour=atoi(p);
  while (*p && isdigit(*p)) p++;
  if (*p!=':' || !isdigit(p[1])) return 1;
  min=atoi(++p);
  while (*p && isdigit(*p)) p++;
  if (*p==':' && isdigit(p[1]))
  { sec = atoi(++p);
    while (*p && isdigit(*p)) p++;
  } else
    sec = 0;
  for (k=0; k<12; k++)
    if (stricmp(smon, montable[k])==0)
      break;
  if (k==12) return 1;
  /* look TZ */
  p=strpbrk(p, " \t");
  msgtz=0; /* his TZ */
  if (p)
  { while (*p && isspace(*p)) p++;
    msgtz=gettz(p);
  }
  /* make shift */
  /* my tz=-2, i=+2 */
  if (msgtz==0) /* else put TZUTC kludge */
  {
    hour-=(msgtz+tz);
    if (hour<0)
    { day--;
      hour+=24;
      if (day==0)
      { if (k!=12)
        {
          k--;
          if (k<0)
          { year--;
            k=11;
          }
          day=daymon[k];
        }
        else
        { day=1;
          hour=0;
        }
      }
    }
    else if (hour>=24)
    { day++;
      hour-=24;
      if (day>daymon[k])
      { day=1;
        if (k!=12)
        {
          k++;
          if (k>=12)
          { k=1;
            year++;
          }
        }
      }
    }
    if (k<12)
      strcpy(smon, montable[k]);
  }
  /* paranoid checking... */
  if (day<1) day=1;
  if (day>31) day=31;
  if (year>=100) year%=100;
  if (hour<0) hour=0;
  if (hour>=24) hour%=24;
  if (min<0) min=0;
  if (min>=60) min%=60;
  if (sec<0) sec=0;
  if (sec>=60) sec%=60;
  sprintf(msghdr.date, "%02u %s %02u  %02u:%02u:%02u",
          day, smon, year, hour, min, sec);
  return 0;
}

void putvia(char *str)
{ char *p;
  time_t curtime;
  struct tm *curtm;

  curtime = time(NULL);
  curtm = localtime(&curtime);
  strcpy(str, "\x01Via: by ");
  if (myaka[curaka].point)
    sprintf(str+strlen(str), "p%u.", myaka[curaka].point);
  strcpy(s, myaka[curaka].domain);
  p=strpbrk(s, "%@");
  if (p) *p=0;
  sprintf(str+strlen(str), "f%u.n%u.z%u.%s (" NAZVA ")",
          myaka[curaka].node, myaka[curaka].net, myaka[curaka].zone, s);
  sprintf(str+strlen(str), "; %s, %2u %s %u %02u:%02u:%02u %c%02u00\r",
    weekday[curtm->tm_wday],
    curtm->tm_mday, montable[curtm->tm_mon], curtm->tm_year+1900,
    curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
    (tz<=0) ? '+' : '-', (tz<0) ? -tz : tz);
  debug(14, "PutVia: %s", str);
}

#ifdef __OS2__
void rexx_extchk(void *param)
{ char *p;
  char *cmdline = param;
  RXSTRING arg;
  RXSTRING rexxretval;
  short rexxrc=0;
  int   rc;
  
  debug(7, "Rexx_ExtChk('%s')", cmdline);
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
  { logwrite('?', "Can't run external checker, RexxStart retcode %d!\n", rc);
    rexxrc=EXT_DEFAULT;
  }
  DosFreeMem(rexxretval.strptr);
  debug(7, "Rexx_ExtChk returns %d", rexxrc);
  *(int *)cmdline=rexxrc;
  _endthread();
}
#endif

#ifdef DO_PERL
#include <EXTERN.h>
#include <perl.h>

#ifndef pTHXo
#define pTHXo
#endif
#ifndef pTHXo_
#define pTHXo_
#endif

static PerlInterpreter *my_perl;
static int do_perl=1;
extern char perlfile[];
static char *perlargs[]={"", perlfile, NULL};
char *newintsetname;
void boot_DynaLoader(pTHXo_ CV *cv);
void xs_init(pTHXo)
{
#ifndef __OS2__
  dXSUB_SYS;
#endif
  newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, "callperl");
}

static void exitperl(void)
{
  if (my_perl)
  { perl_destruct(my_perl);
    perl_free(my_perl);
    my_perl=NULL;
  }
}
#endif

externtype extcheck(char *to, char *from, char **news
#ifdef DO_PERL
                    , char *subj
#endif
                    )
{
/* 0 - default for stdout,
   1 - default,
   2 - send for stdout,
   3 - send,
   4 - /dev/null,
   5 - bounce,
   6 - hold for stdout,
   7 - hold.
*/

  int  i, area;
  char *p1;
  static char tmpaddr[MAXADDR];
  static char conflist[1024];
  static char extstr[256];
#if defined(__MSDOS__)
  char *p;
#elif defined(__OS2__)
  TID tid;
  int saveout;
  int hpipe[2];
#ifdef DO_PERL
  int h;
#endif
#else
  pid_t pid;
  int h;
#endif
#ifdef DO_PERL
  SV *svfrom, *svto, *svsize, *svarea, *svattname, *svtext, *svsubj;
  SV *svintsetname;
  HV *hdr;
  STRLEN n_a;
  int psize;
  char *hstr;
#endif
  static char cmdline[CMDLINELEN+128];
  FILE *f;

  if (stricmp(*news, "netmail")==0)
    area=-1;
  else
    area=0;

  for (i=0; i<nchecker; i++)
  {
    if (stricmp(checker[i].mask, "any")==0) break;
    if (stricmp(checker[i].mask, "echo")==0)
    { if (area!=-1)
        break;
    }
    else
      if (area==-1)
        if (cmpaddr(to, checker[i].mask)==0)
          break;
  }
  if ((i==nchecker) || (checker[i].cmdline[0]=='\0'))
    return EXT_DEFAULT;
#ifdef DO_PERL
  if (perlfile[0] == '\0')
    goto ext_noperl;
  if (!do_perl)
    return 3;
  if (my_perl==NULL)
  { int saveerr, perlpipe[2];
    if (access(perlfile, R_OK))
    { logwrite('!', "Can't read %s: %s, perl filtering disabled\n",
               perlfile, strerror(errno));
      do_perl=0;
      return EXT_DEFAULT;
    }
    my_perl = perl_alloc();
    perl_construct(my_perl);
#ifdef HAVE_FORK
    pipe(perlpipe);
chk_fork:
    if ((pid=fork())>0)
    {
      saveerr=dup(fileno(stderr));
      dup2(perlpipe[1], fileno(stderr));
      close(perlpipe[0]);
      close(perlpipe[1]);
      h=perl_parse(my_perl, xs_init, 2, perlargs, NULL);
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
      return EXT_DEFAULT;
    }
#else /* not HAVE_FORK */
    saveerr=dup(fileno(stderr));
    perlpipe[0]=open("/dev/null", O_WRONLY);
    if (perlpipe[0]!=-1)
    { dup2(perlpipe[0], fileno(stderr));
      close(perlpipe[0]);
    }
    h=perl_parse(my_perl, xs_init, 2, perlargs, NULL);
    dup2(saveerr, fileno(stderr));
    close(saveerr);
#endif
    if (h)
    { logwrite('!', "Can't parse %s, perl filtering disabled\n", perlfile);
      exitperl();
      do_perl=0;
      return EXT_DEFAULT;
    }
    atexit(exitperl);
  }
  { dSP;
    svfrom=perl_get_sv("from", TRUE);
    svto  =perl_get_sv("to"  , TRUE);
    svsize=perl_get_sv("size", TRUE);
    svarea=perl_get_sv("area", TRUE);
    svattname=perl_get_sv("attname", TRUE);
    svtext=perl_get_sv("body", TRUE);
    svsubj=perl_get_sv("subject", TRUE);
    svintsetname=perl_get_sv("intsetname", TRUE);
    sv_setpv(svfrom, from);
    sv_setpv(svto, addr);
    sv_setiv(svsize, (conf && !cnews) ? fsize-1 : fsize);
    sv_setpv(svarea, *news);
    if (attname[0])
      sv_setpv(svattname, attname);
    if (msgloc == LOC_MEMORY)
      sv_setpvn(svtext, msgbuf, (conf && !cnews) ? fsize-1 : fsize);
    if (subj)
      sv_setpv(svsubj, subj);
    sv_setpv(svintsetname, intsetname);
    /* Create %hdr */
    hdr = perl_get_hv("hdr", 1);
    hrewind();
    hstr=NULL;
    psize=0;
    if (!textline(str, sizeof(str))) str[0]='\0';
    while (str[0])
    { int plen, slen;
      char *p;
      plen=0;
      p1=hstr;
      for (;;)
      {
        slen=strlen(str);
        if (plen+slen>=psize)
        { if (psize)
            p=realloc(hstr, psize*=2);
          else
            p=malloc(psize=sizeof(str)*2);
          if (p==NULL)
          { if (hstr) free(hstr);
            logwrite('!', "Not enough memory (needed %d bytes)\n", psize);
            p1=hstr=NULL;
            break;
          }
          hstr=p;
        }
        p1=hstr;
        strcpy(p1+plen, str);
        plen+=slen;
        if (slen && str[slen-1]!='\n')
        { if (textline(str, sizeof(str))) continue;
          str[0]='\0';
          break;
        }
        if (!textline(str, sizeof(str))) str[0]='\0';
        if (str[0]!=' ' && str[0]!='\t') break;
        /* unfolding */
        hstr[plen-1]=' ';
        for (p=str; *p==' ' || *p=='\t'; p++);
        if (*p=='\0') p--;
        mstrcpy(str, p);
      }
      if (p1==NULL) break;
      if (plen) p1[--plen]='\0'; /* remove last '\n' */
      if (strnicmp(p1, "From ", 5)==0)
        hv_store(hdr, p1, 5, newSVpv(p1+5, 0), 0);
      else if ((p=strchr(p1, ':')) != NULL)
      { plen=p-p1;
        *p++='\0';
        while (isspace(*p)) p++;
        strlwr(p1);
        *p1=toupper(*p1);
        hv_store(hdr, p1, plen, newSVpv(p, 0), 0);
      }
    }
    if (hstr) free(hstr);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUTBACK;
    perl_call_pv(checker[i].cmdline, G_EVAL | G_SCALAR);
    SPAGAIN;
    i=POPi;
    PUTBACK;
    FREETMPS;
    LEAVE;
    strncpy(extstr, SvPV(perl_get_sv("to", FALSE), n_a), sizeof(extstr));
    strncpy(tmpaddr, SvPV(perl_get_sv("from", FALSE), n_a), sizeof(tmpaddr));
    strncpy(conflist, SvPV(perl_get_sv("area", FALSE), n_a), sizeof(conflist));
    newintsetname=SvPV(perl_get_sv("intsetname", FALSE), n_a);
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
  chsubstr(cmdline, "%from", from);
  chsubstr(cmdline, "%to", to);
  if (conf && !cnews)
    sprintf(tmpaddr, "%lu", fsize-1); /* last line */
  else
    sprintf(tmpaddr, "%lu", fsize);
  chsubstr(cmdline, "%size", tmpaddr);
  chsubstr(cmdline, "%area", *news);
  chsubstr(cmdline, "%attname", attname);
  conflist[0]='\0';
  debug(5, "ExtCheck: running '%s'", cmdline);
#if defined(__MSDOS__)
  strcat(cmdline, " >");
  p=cmdline+strlen(cmdline);
  mktempname(TMPOUT, p);
  i=swap_system(cmdline);
#elif defined(__OS2__) 
  if (pipe(hpipe))
  { logwrite('?', "Can't create pipe for external checker!\n");
    return EXT_DEFAULT;
  }
  DosSetFHState(hpipe[0], OPEN_FLAGS_NOINHERIT);
  saveout=dup(fileno(stdout));
  dup2(hpipe[1], fileno(stdout));
  close(hpipe[1]);
  i=EXT_DEFAULT;
  f=fdopen(hpipe[0], "r");
  if (f==NULL)
  { logwrite('?', "Can't fdopen pipe!\n");
    close(hpipe[0]);
  }
  else
  { tid=_beginthread(rexx_extchk, NULL, STACK_SIZE, cmdline);
    fgets(extstr, sizeof(extstr), f);
    if (fgets(tmpaddr, sizeof(tmpaddr), f)==NULL)
      tmpaddr[0]='\0';
    else fgets(conflist, sizeof(conflist), f);
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
  debug(7, "ExtCheck: retcode %d", i);
  if (area!=-1)
  { if ((i==EXT_HOLD) || (i==EXT_HOLDOUT) || (i==EXT_REJECT))
    { logwrite('?', "External checker incorrect retcode %d for echomail!\n", i);
      i=0;
    }
  }
  if ((i>255) || (i<0))
  { logwrite('?', "Can't execute external checker!\n");
    i=EXT_DEFAULT;
  }
  else if (i>7)
  { logwrite('?', "External checker unknown retcode %d!\n", i);
    i=EXT_DEFAULT;
  }
  else
    debug(2, "External checker retcode %d", i);
  if ((i==EXT_DEFOUT) || (i==EXT_FREEOUT) || (i==EXT_HOLDOUT))
  {
#ifdef __MSDOS__
    f=myfopen(p, "r");
    if (f==NULL)
    { logwrite('?', "Can't read checker's stdout!\n");
      if (i==EXT_DEFOUT) i=EXT_DEFAULT;
      else if (i==EXT_FREEOUT) i=EXT_FREE;
      else if (i==EXT_HOLDOUT) i=EXT_HOLD;
      tmpaddr[0]=0;
    }
    else
    { fgets(extstr, sizeof(extstr), f);
      if (fgets(tmpaddr, sizeof(tmpaddr), f)==NULL)
        tmpaddr[0]=0;
      else
        fgets(conflist, sizeof(conflist), f);
      fclose(f);
    }
#endif
    p1=strchr(extstr, '\n');
    if (p1) *p1=0;
    if (stricmp(to, extstr))
      debug(4, "ExtChk: to-addr changed to '%s'", extstr);
    strcpy(to, extstr);
    p1=strchr(tmpaddr, '\n');
    if (p1) *p1=0;
    if (*tmpaddr)
    { if (stricmp(fromaddr, tmpaddr))
        debug(4, "ExtChk: from-addr changed to '%s'", tmpaddr);
      strcpy(fromaddr, tmpaddr);
    }
    p1=strchr(conflist, '\n');
    if (p1) *p1=0;
    if (*conflist)
    { if (stricmp(*news, conflist))
        debug(4, "ExtChk: area changed to '%s'", tmpaddr);
      *news=conflist;
    }
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
    mstrcpy(p, p+strlen(from));
    j=strlen(to);
    for (i=strlen(p); i>=0; i--)
      p[i+j]=p[i];
    strncpy(p, to, j);
    p+=strlen(to);
  }
}

int mktempname(char *sample, char *dest)
{
  int  i, k, l1, l2, l3;
  long l;
  char *p;

  if (strchr(sample, PATHSEP))
    dest[0]='\0';
  else
    strcpy(dest, tmpdir);
  strcat(dest, sample);
  p=strchr(dest, '?');
  if (p==NULL)
  { debug(8, "MkTempName(%s) returns %s", sample, dest);
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
    { debug(8, "MkTempName(%s) returns %s", sample, dest);
      return 0;
    }
    l1=(l1+1)%(int)l;
    if (l1==l2)
      return 1;
  }
}
