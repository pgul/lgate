/*
 * $Id$
 *
 * $Log$
 * Revision 2.7  2011/11/19 08:39:03  gul
 * Fix strcpy(p,p+1) to own mstrcpy(p,p+1) which works correctly in this case
 *
 * Revision 2.6  2004/07/20 18:38:06  gul
 * \r\n -> \n
 *
 * Revision 2.5  2004/07/04 09:01:05  gul
 * Fixes for gcc 3.3.3
 *
 * Revision 2.4  2002/01/07 09:57:24  gul
 * Added init_textline() for hrewind()
 *
 * Revision 2.3  2001/02/27 10:18:11  gul
 * "Memory allocation failed" fixed
 *
 * Revision 2.2  2001/01/29 17:45:33  gul
 * Bugfix: corrupt memory when size=0 and --with-perl on large messages
 *
 * Revision 2.1  2001/01/25 16:35:46  gul
 * Translate comments and cosmetic changes
 *
 * Revision 2.0  2001/01/10 20:42:26  gul
 * We are under CVS for now
 *
 */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <stdarg.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

#include "gate.h"
#include "raw.h"

#define HDRCONTENT    /* recode header according to "charset" */
#define BOUNCEBADHDR  /* bounce messages with bad message (part) hdr */
#ifndef __MSDOS__
/* #define ALLOWLONGNAMES */ /* allow longnames in file attaches */
#endif

char gotstr[MAXLINE];
char *newsgroups=NULL;
static char *bound;
static int  was_eof, was_eol, was_empty, inreport;
static char *xtable;
static char cont_type[128];
static char encoding[64];
static char charset[256];
static int  is_utf8;
static short int *inttable;
static char *ext;
static FILE *fatt;
int  split_report, subj1line=1;
static int  (*func_decode)(int (*getbyte)(void), int (*putbyte)(char));
static char *lastword;
static char _Huge *cur_hdr, _Huge *pcur_hdr;
msgloctype msgloc;
static int  wasCR;
static char namemsg[FNAME_MAX];
static long mbufsize;
int  known_charset, nottext;
int  kill_vcard, do_alternate;
long msgsize, omsgsize, begsrcpos;
unsigned potoloksrc;
char *bufsrc;
unsigned ibufsrc;
char attname[FNAME_MAX];
char destname[256];
char *longname;
char *origmsgid=NULL;
char charsetsdir[FNAME_MAX]="";

static void get_uniq(char * attname)
{ int i=0;
  char *p;

  while (!access(attname, 0))
  { if (strchr(attname, '.')==NULL)
      strcat(attname, ".001");
    p=strchr(attname, '.')+1;
    while (strlen(p)<3) strcat(p, "0");
    if (i>99)
      sprintf(attname+strlen(attname)-3, "%3d", i);
    else if (i>9)
      sprintf(attname+strlen(attname)-2, "%2d", i);
    else
      sprintf(attname+strlen(attname)-1, "%1d", i);
    i++;
  }
  debug(7, "UnMime: result filename is %s", attname);
}

static void set_path(char *fname)
{
  char *p, *p1;
  static char tstr[FNAME_MAX];

  p=strrchr(fname, '\\');
  if (p==NULL) p=strrchr(fname, '/');
  else if (strrchr(p, '/')) p=strrchr(p, '/');
  if (p==NULL) p=strrchr(fname, ':');
  else if (strrchr(p, ':')) p=strrchr(p, ':');
  if (p) p++;
  else p=fname;
  strncpy(tstr, p, sizeof(tstr)-1);
  tstr[sizeof(tstr)-1]='\0';
  for (p=tstr; *p; p++)
  { if (*p=='>') *p='}';
    if (*p=='<') *p='{';
    if (*p=='|') *p='!';
    if (*p=='+') *p='_';
    if (*p=='?') *p='_';
    if (*p=='*') *p='_';
    if (*p=='=') *p='-';
    if (*p<0x20) *p='_';
#if 0 /* only alphabet-letters and digits */
    if (*p & 0x80) *p='_';
    if (*p==',') *p='_';
#endif
  }
#ifndef ALLOWLONGNAMES
  for (p=tstr; *p; p++)
    if (*p==' ') *p='_';
  p=strchr(tstr, '.');
  if (p)
  { if (p-tstr>8)
      mstrcpy(tstr+8, p);
  }
  else
    if (strlen(tstr)>8)
      tstr[8]='\0';
  p=strchr(tstr, '.');
  if (p)
  { p1=strrchr(p+1, '.');
    if (p1)
    { if (strlen(tstr)>7)
        p1=tstr+strlen(tstr)-7;
      else
        p1=p;
      if ((stricmp(p1, ".tar.gz")==0) || (stricmp(p1+1, ".tar.z")==0))
        strcpy(p, ".tgz");
      else
        strcpy(p, strrchr(p+1, '.'));
    }
    if (stricmp(p, ".jpeg")==0)
      strcpy(p, ".jpg");
    else if (stricmp(p, ".mpeg")==0)
      strcpy(p, ".mpg");
    if (strlen(p)>4)
      p[4]='\0';
  }
#endif
  strcpy(fname, holdpath);
  strcat(fname, tstr);
}

static int unqp(int (*getbyte)(void), int (*putbyte)(char))
{
  int  c;
  char s[3];
  char *p;

  for (;;)
  {
    c=getbyte();
nextqpbyte:
    if (c==0x1a) continue;
    if (c==-1) return 0;
    if (c!='=')
    { if (putbyte(c)==0)
        continue;
      else
        return -1;
    }
    c=getbyte();
    if (c==-1)
    { putbyte('=');
      break;
    }
    s[0]=(char)c;
    if (s[0]=='\n') continue;
    if (s[0]=='\r')
    { c=getbyte();
      if (c==-1)
        break;
      if (c=='\n') continue;
      goto nextqpbyte;
    }
    if (!isxdigit(s[0]))
    { putbyte('=');
      break;
    }
    c=getbyte();
    if (c==-1)
    { putbyte('=');
      putbyte(s[0]);
      break;
    }
    s[1]=(char)c;
    if (!isxdigit(s[1]))
    { putbyte('=');
      putbyte(s[0]);
      break;
    }
    s[2]=0;
    if (putbyte((char)strtol(s, &p, 16)))
      return -1;
  }
  logwrite('!', "Bad quoted-printable code\n");
  for (; c!=-1; c=getbyte())
    if (putbyte(c))
      return -1;
  return 1;
}

#include "cunb64.h"

static int unbase64(int (*getbyte)(void), int (*putbyte)(char))
{
  int  ret=0;
  int  i;
  char s[4];
  int  c=-1;

  for (;;)
  {
    for (i=0; i<4;)
    { c=getbyte();
      if (c==0x1a) continue;
      if (c==-1)
      { if (i)
        { ret=1;
          break;
        }
        return 0;
      }
      s[i]=(char)c;
      if (isspace(s[i])) continue;
      s[i]=cunbase64[(int)s[i]];
      if (s[i]==(char)0xff)
      { ret=1;
        break;
      }
      i++;
    }
    if (ret) break;
    if ((s[0]==64) || (s[1]==64))
    { ret=1;
      break;
    }
    if (putbyte((s[0]<<2) | (s[1]>>4))) return -1;
    if (s[2]==64)
    { if (s[3]!=64) ret=1;
      break;
    }
    if (putbyte(((s[1]<<4)|(s[2]>>2)) & 0xff)) return -1;
    if (s[3]==64)
      break;
    if (putbyte(((s[2]<<6)|s[3]) & 0xff)) return -1;
  }
  /* waiting for end of file */
  if (ret==0) c=getbyte();
  for(; c!=-1; c=getbyte())
  { if (!isspace(c))
      ret=1;
    if (ret)
      if (putbyte(c))
        return -1;
  }
  if (ret==1)
    logwrite('!', "Bad base64 code\n");
  return ret;
}

static int get_line(char *str, unsigned size, int (*getbyte)(void))
{
  int i, c;

  for (i=0; i<size-1; i++)
  { c=getbyte();
    if (c==-1)
    { str[i]=0;
      return i;
    }
    str[i]=(char)c;
    if (c=='\n')
    { str[++i]='\0';
      return i;
    }
  }
  str[i]='\0';
  return i;
}

#define DEC(c)		(((c) - ' ') & 077)
#define updatesum(sum, c) sum = ((sum >> 1) & 0x7FFF) + ((sum << 15) & 0x8000u) + c;

static int uudecode(int (*getbyte)(void), int (*putbyte)(char))
{
  static char uustr[128];
  char *p, c;
  int  i, n, expected;
  unsigned short sum=0, fsum;
  long len=0, flen;

  while ((n=get_line(uustr, sizeof(uustr), getbyte))!=0)
    if (strncmp(uustr, "begin ", 6)==0)
      break;
  if (n==0)
  { logwrite('!', "Bad uucode!\n");
    return 1;
  }
  for (p=uustr+strlen(uustr)-1; isspace(*p); p--);
  p[1]='\0';
  for (p=uustr+5; isspace(*p); p++);
  while (isdigit(*p)) p++;
  while (isspace(*p)) p++;
  if (longname==NULL)
  { strcpy(destname, p);
    longname=destname;
    debug(4, "uudecode: get filename %s", longname);
    fclose(fatt);
    unlink(attname);
    strcpy(attname, destname);
    set_path(attname);
    get_uniq(attname);
  
    fatt=fopen(attname, "wb");
    if (fatt==NULL)
    { logwrite('?', "Can't create attached file %s: %s!\n", attname,
               strerror(errno));
      while (getbyte()!=-1);
      return -1;
    }
  }
  n=1; /* EOF is error */
  while (get_line(uustr, sizeof(uustr), getbyte))
  {
    if (uustr[0]=='\n') continue;
    n=DEC(uustr[0]);
    if (n<=0)
      break;
    /* Calculate expected number of chars and pad if necessary */
    expected = ((n+2)/3)<<2;
    if (expected>=sizeof(uustr))
    { expected=sizeof(uustr)-1;
      n=((sizeof(uustr)-1)/4)*3;
    }
    for (i=strlen(uustr)-1; i<=expected; uustr[i++]=' ');
    p = uustr+1;
    while (n>0)
    {
      if (n >= 1)
      { c=(DEC(*p) << 2) | (DEC(p[1]) >> 4);
        if (putbyte(c))
        { while (getbyte()!=-1);
          return -1;
        }
        updatesum(sum, c);
        len++;
      }
      if (n >= 2)
      { c=(DEC(p[1]) << 4) | (DEC(p[2]) >> 2);
        if (putbyte(c))
        { while (getbyte()!=-1);
          return -1;
        }
        updatesum(sum, c);
        len++;
      }
      if (n >= 3)
      { c=(DEC(p[2]) << 6) | (DEC(p[3]));
        if (putbyte(c))
        { while (getbyte()!=-1);
          return -1;
        }
        updatesum(sum, c);
        len++;
      }
      p+=4;
      n-=3;
    }
    n=1; /* EOF is error */
  }
  if (n!=0)
  { logwrite('!', "Bad uucode!\n");
    while (getbyte()!=-1);
    return 1;
  }
  while (get_line(uustr, sizeof(uustr), getbyte))
  { if (uustr[0]=='\n') continue;
    if (strcmp(uustr, "end\n"))
    { while (getbyte()!=-1);
      logwrite('!', "Bad uucode!\n");
      return 0;
    }
    /* good uucode */
    while (get_line(uustr, sizeof(uustr), getbyte))
    { if (strncmp(uustr, "sum -r/size ", 12)) continue;
      if (strstr(uustr, " entire input file")==NULL) continue;
      if (sscanf(uustr+12, "%hu/%lu", &fsum, &flen)!=2) continue;
      if ((fsum!=sum) || (flen!=len))
      { logwrite('!', "warning: uudecode crc error!\n");
        while (getbyte()!=-1);
        return 0;
      }
      else
        debug(2, "uucode checksum ok");
    }
    return 0;
  }
  logwrite('!', "Bad uucode!\n");
  return 1;
}

static int raw_func(int (*getbyte)(void), int (*putbyte)(char))
{ int c;

  for (c=getbyte(); c!=-1; c=getbyte())
    if (putbyte((char)c))
      return -1;
  return 0;
}

static char *pstrgetbyte, *pstrputbyte;

static int strgetbyte(void)
{ char c;

  c=*pstrgetbyte;
  if (c)
    return *pstrgetbyte++;
  return -1;
}

static int strputbyte(char c)
{ *pstrputbyte++=c;
  return 0;
}

static int fgetbyte(void)
{ /* remove empty line before bound */
  if (was_eol & 2)
  { was_eol &= ~2;
    return '\n';
  }
  if (pstrgetbyte)
    if (*pstrgetbyte)
      return *pstrgetbyte++;
  if (was_eof)
  { if (pstrgetbyte==NULL || *pstrgetbyte=='\0')
      return -1;
    else
      return *pstrgetbyte++;
  }
gbagain:
  if (!myfgets(gotstr, sizeof(gotstr)))
  { if ((!conf) || cnews) /* not from box */
      if (was_empty)
      { strcpy(gotstr, CRLF);
        pstrgetbyte=gotstr;
        was_empty=0;
        return *pstrgetbyte++;
      }
    return -1;
  }
  if (was_eol && bound && (strncmp(gotstr, bound, strlen(bound))==0))
    if (bound && strcmp(bound, "From "))
      return -1;
  if (was_empty && (isbeg(gotstr)==0) && bound && (strcmp(bound, "From ")==0))
  { was_eof=1;
    was_empty=0;
    return -1; /* it's not boundary in another case */
  }
  pstrgetbyte=gotstr;
  if ((strcmp(gotstr, CRLF)==0) && was_eol)
  { was_eol=1;
    if (was_empty)
      return *pstrgetbyte++;
    was_empty=1;
    goto gbagain;
  }
  else
  {
    if (strchr(gotstr, '\n'))
      was_eol=1;
    else
      was_eol=0;
    if (was_empty)
    { was_empty=0;
      was_eol |= 2;
      pstrgetbyte=gotstr;
      return '\r';
    }
  }
  return *pstrgetbyte++;
}

static int fputattbyte(char c)
{
  if (putc(c, fatt)==EOF)
    return -1;
  return 0;
}

static int fputbyte(char c)
{
  if (c & 0x80)
    c=xtable[c & 0x7f];
  if ((imsgbuf==0) && (msgloc==LOC_MEMORY))
  { /* first time */
    wasCR=0;
  }
  /* "\r\n" -> "\n" */
  if (wasCR && (c!='\r'))
    if (c!='\n')
      fputbyte('\r');
  if (c=='\r')
  { if (!wasCR)
    { wasCR=1;
      return 0;
    }
  }
  else
    wasCR=0;
  bufcopy(msgbuf, imsgbuf++, &c, 1);
  if (imsgbuf<mbufsize) return 0;
  if (msgloc==LOC_MEMORY)
  { /* not enough memory - create file */
#ifdef DO_PERL
    char *newmsgbuf;
    if ((newmsgbuf=bufrealloc(msgbuf, mbufsize+(maxpart ? maxpart*1024l : MSGBUFSIZE))) != NULL)
    { msgbuf = newmsgbuf;
      mbufsize += (maxpart ? maxpart*1024l : MSGBUFSIZE);
      return 0;
    }
#endif
    debug(7, "fputbyte: create temp file");
    mktempname(TMPIN, namemsg);
    f=open(namemsg, O_BINARY|O_EXCL|O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
    if (f==-1)
    { logwrite('?', "Can't create temp file: %s!\n", strerror(errno));
      return -1;
    }
    msgloc=LOC_FILE;
  }
  if (bufwrite(f, msgbuf, imsgbuf)!=imsgbuf)
  { logwrite('?', "Can't write to file: %s!\n", strerror(errno));
    close(f);
    unlink(namemsg);
    return -1;
  }
  imsgbuf=0;
  return 0;
}

/*************************************************************/
/* UTF-8 support                                             */
/* from mutt sources                                         */

/* macros for the various bit maps we need */

#define IOOOOOOO 0x80
#define IIOOOOOO 0xc0
#define IIIOOOOO 0xe0
#define IIIIOOOO 0xf0
#define IIIIIOOO 0xf8
#define IIIIIIOO 0xfc
#define IIIIIIIO 0xfe
#define IIIIIIII 0xff

static struct unicode_mask
{
  short int mask;
  short int value;
  short int len;
}
unicode_masks[] = 
{
  { IOOOOOOO,	    0,   1 },
  { IIIOOOOO, IIOOOOOO,  2 },
  { IIIIOOOO, IIIOOOOO,  3 },
  { IIIIIOOO, IIIIOOOO,  4 },
  { IIIIIIOO, IIIIIOOO,  5 },
  { IIIIIIIO, IIIIIIOO,  6 },
  {        0,	     0,  0 }
};

static char *utf_to_unicode(short int *out, char *in)
{
  struct unicode_mask *um = NULL;
  short int i;
  
  for(i = 0; unicode_masks[i].mask; i++)
  {
    if((*in & unicode_masks[i].mask) == unicode_masks[i].value)
    {
      um = &unicode_masks[i];
      break;
    }
  }
  
  if(!um)
  {
    *out = (short int) '?';
    return in + 1;
  }

  for(i = 1; i < um->len; i++)
  {
    if((in[i] & IIOOOOOO) != IOOOOOOO)
    {
      *out = (short int) '?';
      return in + i;
    }
  }

  *out = ((short int)in[0]) & ~um->mask & 0xff;
  for(i = 1; i < um->len; i++)
    *out = (*out << 6) | (((short int)in[i]) & ~IIOOOOOO & 0xff);

  if(!*out) 
    *out = (short int)'?';
  
  return in + um->len;
}

static char utfstr[6];
static int nutfstr=0;

static int utf_putbyte(char c)
{
  struct unicode_mask *um = NULL;
  short int i, out;

  utfstr[nutfstr++]=c;

  for(i = 0; unicode_masks[i].mask; i++)
  {
    if((*utfstr & unicode_masks[i].mask) == unicode_masks[i].value)
    {
      um = &unicode_masks[i];
      break;
    }
  }
  if(!um)
  {
badutfbyte:
    if (fputbyte('?'))
      return -1;
    memcpy(utfstr, utfstr+1, --nutfstr);
    if (nutfstr)
    { nutfstr--;
      return utf_putbyte(c);
    }
    return 0;
  }
  for(i = 1; i < um->len && i < nutfstr; i++)
    if((utfstr[i] & IIOOOOOO) != IOOOOOOO)
      goto badutfbyte;
  if (nutfstr < um->len)
    return 0;

  out = ((short int)utfstr[0]) & ~um->mask & 0xff;
  for(i = 1; i < um->len; i++)
    out = (out << 6) | (((short int)utfstr[i]) & ~IIOOOOOO & 0xff);

  if(!out) 
    out = (short int)'?';
  for (i=0; i<256; i++)
    if (inttable[i] == out)
    { c = (char)i;
      break;
    }
  if (i == 256)
    c = '?';
  nutfstr = 0;
  return fputbyte(c);
}

static void utf_flushputbyte(void)
{
  while (nutfstr)
  {
    fputbyte('?');
    if (--nutfstr==0)
      return;
    memcpy(utfstr, utfstr+1, nutfstr);
    utf_putbyte(utfstr[--nutfstr]);
  }
}

static void decode_utf8_string(char *str)
{
  char *s, *t;
  short int ch, i;
  short int *inttable;

  if ((inttable = findtable(intsetname, charsetsdir)) == NULL)
    return;

  for( s = t = str; *t; s++)
  {
    t = utf_to_unicode(&ch, t);
    for(i = 0, *s = '\0'; i < 256; i++)
    {
      if(inttable[i] == ch)
      {
        *s = i;
        break;
      }
    }
    if(!*s) *s = '?';
  }
  *s = '\0';
}

static int eomessage(void)
{ int r;
  char _Huge *p;

  if (wasCR) fputbyte('\r');
  if (msgloc==LOC_FILE)
  { bufwrite(f, msgbuf, imsgbuf);
    fsize=lseek(f, 0, SEEK_CUR);
    ibuf=BUFSIZE;
    lseek(f, 0, SEEK_SET);
    debug(7, "eomessage: message in file");
  }
  else /* LOC_MEMORY */
  { fsize=imsgbuf;
    imsgbuf=0;
    debug(7, "eomessage: message in memory");
  }
  maxmsgbuf=fsize;
  hdrsize=1;
  for (p=pcur_hdr; *p; p+=hstrlen(p)+1)
    hdrsize+=hstrlen(p);
  debug(7, "eomessage: call one_message");
  r=one_message();
  debug(7, "eomessage: one_message returns %d", r);
  if (msgloc==LOC_FILE)
  { if (f!=-1) close(f);
    unlink(namemsg);
  }
  if (r) return -1;
  return 0;
}

static void strunqp(char *src, char *dest)
{ char *p;
  pstrgetbyte=src;
  pstrputbyte=dest;
  /* only header! */
  for (p=src; *p; p++)
    if (*p=='_') *p=' ';
  unqp(strgetbyte, strputbyte);
  strputbyte(0);
}

static void strunb64(char * src, char * dest)
{
  pstrgetbyte=src;
  pstrputbyte=dest;
  unbase64(strgetbyte, strputbyte);
  strputbyte(0);
}

static char *set_table(char *charset, char *def_charset)
{
  short int *inttable, *xtable;
  static char tmpxtable[128];
  int i, j;

  debug(8, "Set_Table charset=%s, def_charset=%s", charset, def_charset);
  known_charset=1;
  if ((inttable = findtable(intsetname, charsetsdir)) == NULL)
  { known_charset = 0;
    return raw_table;
  }
  charset=canoncharset(charset);
  debug(15, "Set_Table: canon charset is %s", charset);
  if (charsetsdir[0] && stricmp(charset, "utf-8")==0)
    return raw_table;
  if ((xtable=findtable(charset, charsetsdir)) == NULL)
  {
    if (charset[0]!='\0') /* unknown charset */
    { known_charset=0;
      debug(6, "Set_table: unknown charset %s, don't recode", charset);
      return raw_table;
    }
    if ((xtable=findtable(def_charset, charsetsdir)) == NULL)
      return raw_table;
  }
  memset(tmpxtable, '?', 128);
  for (i=128; i<256; i++)
  { for (j=0; j<256; j++)
      if (xtable[i]==inttable[j])
      { tmpxtable[i & 0x7f]=j;
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
          if (inttable[j]==newc)
            tmpxtable[i & 0x7f]=j;
    }
  }
  return tmpxtable;
}

void altkoi8(char *s)
{ int i;
  xtable=set_table(extsetname, extsetname);
  for(; *s; s=(char *)((char _Huge *)s+1))
    if (*s & 0x80)
    { for(i=0; i<128; i++)
        if (xtable[i]==*s)
          break;
      if (i<128)
        *s=i+128;
    }
}

static void strxlat(char *s, char *charset)
{
  char *xtable;

  charset=canoncharset(charset);
  if (stricmp(charset, "utf-8") == 0 && charsetsdir[0])
  { decode_utf8_string(s);
    return;
  }
  xtable=set_table(charset, extsetname); /* only for header */
  for(; *s; s=(char *)((char _Huge *)s+1))
    if (*s & 0x80)
      *s=xtable[*s & 0x7f];
}

static char * unmime_header(char *header)
{ char *pch, *pp;
  char *p, *cword;
  int  nq, i;
  char charset[256];

  p=header;
  if (isspace(*p))
  { for (; *p && (!isspace(*p)) && (*p!=':'); p++);
    if ((*p!=':') && strncmp(header, "From ", 5))
      return NULL; /* bad header */
    else
      p++;
  }
  lastword=NULL;
  for (;;)
  {
    for (; isspace(*p); p++)
      if (subj1line && (*p=='\n') && (hstrlen(p)>1))
        if (strnicmp(header, "Subject:", 8)==0)
        { *p=' ';
          for (pp=p+1; isspace(*pp); pp++);
          hstrcpy(p+1, pp);
        }
    if (*p=='\0')
      return p;
    if (strncmp(p, "=?", 2))
    { lastword=NULL;
      /* p++; */ p=(char *)((char _Huge *)p+1);
      continue;
    }
    cword=p;
    for (nq=0; *p && (strncmp(p, "?=", 2) || nq<3); p++)
      if (*p=='?') nq++;
    if (*p=='\0')
    { lastword=NULL;
      p=cword+1;
      continue;
    }
    *p='\0';
    debug(7, "Unmime_Header: found '%s?='", cword);
    /* mimed word - unmime it */
    for (pp=cword+2, pch=charset; *pp!='?' && *pp!='*'; *pch++=*pp++);
    *pch++='\0';
    for (; *pp!='?'; pp++);
    pp++;
    if (pp[1]!='?')
    { *p='?';
      lastword=NULL;
      p=cword+1;
      continue;
    }
    switch(toupper(*pp))
    { case 'Q': strunqp(pp+2, cword);
                strxlat(cword, charset);
                break;
      case 'B': strunb64(pp+2, cword);
                strxlat(cword, charset);
                break;
      default:  *p='?';
                lastword=NULL;
                p=cword+1;
                continue;
    }
    debug(7, "Unmime_Header: result is '%s'", cword);
    pp=(char *)((char _Huge *)cword+hstrlen(cword));
    if (lastword)
    { /* remove spaces */
      i=(int)(cword-lastword);
      hstrcpy(lastword, cword);
      cword=(char *)((char _Huge *)pp-i);
    }
    else
      cword=pp;
    hstrcpy(cword, p+2);
    p=cword;
    lastword=cword;
  }
}

static char *getfield(char _Huge *header, char *field)
{
  while (*header)
  {
    if (strnicmp((char *)header, field, strlen(field))==0)
      if (header[strlen(field)]==':')
        return (char *)header;
    header+=hstrlen(header)+1;
  }
  return NULL;
}

void getvalue(char *field, char *value, unsigned valsize)
{ char *p;

  if (valsize==0) return;
  value[0]='\0';
  for (p=field; *p && !isspace(*p); p++);
  if (*p=='\0') return;
  for (p++; isspace(*p); p++);
  if (*p!='"')
  { for (; *p && (!isspace(*p)) && (*p!=';'); *value++=*p++)
      if (valsize--==1) break;
  }
  else
    for (p++; *p && (*p!='"') && (*p!='\n') && (*p!='\r'); *value++=*p++)
      if (valsize--==1) break;
  *value='\0';
}

static void getparam1(char *field, char *argname, char *value, unsigned valsize)
{ char *p;

  if (valsize==0) return;
  value[0]='\0';
  for (p=field; *p && !isspace(*p); p++);
  if (*p=='\0') return;
  for (;;)
  {
    for (; *p && (*p!=';') && (*p!='"'); p++);
    if (*p=='"')
    { for(p++; *p && (*p!='"'); p++);
      if (*p!='"') return;
      p++;
      continue;
    }
    if (*p!=';') return;
    for (p++; isspace(*p); p++);
    if (*p=='\0') return;
    if (strnicmp(p, argname, strlen(argname)))
      continue;
    p+=strlen(argname);
    while (isspace(*p)) p++;
    if (*p++!='=') continue;
    while (isspace(*p)) p++;
    /* found */
    if (*p!='"')
    { for (; *p && !isspace(*p) && (*p!=';'); *value++=*p++)
        if (valsize--==1) break;
    }
    else
      for (p++; *p && (*p!='"') && (*p!='\n') && (*p!='\r'); *value++=*p++)
        if (valsize--==1) break;
    *value='\0';
    return;
  }
}

static char *decode2231(char *str, char *charset)
{ /* charset*=koi8-r'ru'koi8-r */
  char *src, *dest;

  if (charset==NULL)
  {
    src=strchr(str, '\'');
    if (src)
    { *src='\0';
      charset=strdup(str);
      *src='\'';
      src=strchr(src+1, '\'');
    }
    if (src==NULL)
    { if (charset)
      { free(charset);
        charset=NULL;
      }
      src=str;
    }
    else
      src++;
  }
  else
    src=str;
  for (dest=str; *src;)
  { if (*src!='%' || !isxdigit(src[1]) || !isxdigit(src[2]))
    { *dest++=*src++;
      continue;
    }
    src++;
    dest[0]=src[0];
    dest[1]=src[1];
    dest[2]='\0';
    *dest=(unsigned char)strtol(dest, NULL, 16);
    dest++;
  }
  *dest='\0';
  if (charset)
    strxlat(str, charset);
  return charset;
}

static void getparam(char *field, char *argname, char *value, unsigned valsize)
{ int i;
  char *p, *charset=NULL;

  if (valsize==0) return;
  getparam1(field, argname, value, valsize);
  if (value[0]) return;
  p = malloc(strlen(argname)+10);
  if (p == NULL) return;
  strcpy(p, argname);
  strcat(p, "*");
  getparam1(field, p, value, valsize);
  if (value[0])
  { charset=decode2231(value, NULL);
    free(p);
    if (charset) free(charset);
    return;
  }
  for (i=0; i<9999; i++)
  { sprintf(p, "%s*%d", argname, i);
    getparam1(field, p, value, valsize);
    if (value[0])
    { value+=strlen(value);
      valsize-=strlen(value);
      continue;
    }
    strcat(p, "*");
    getparam1(field, p, value, valsize);
    if (value[0]=='\0')
    { if (i==0)
        continue;
      else
      { free(p);
        if (charset) free(charset);
        return;
      }
    }
    charset=decode2231(value, charset);
    value+=strlen(value);
    valsize-=strlen(value);
  }
  free(p);
  if (charset) free(charset);
}

static void delmimehdr(char _Huge *header, int savecontenttype, msg_type mtype)
{
  char _Huge *p, *pconttype=NULL;
  char _Huge *p1, _Huge *p2;
  char val[128];
  int  i;

  for (p1=header; *p1; p1+=hstrlen(p1)+1);
  hdrsize=p1-header+1;
  
  for (p=header; *p; p+=hstrlen(p)+1)
  {
begdelhdr:
    if (strnicmp((char *)p, "Content-", 8))
      continue;
    if (strnicmp((char *)p, "Content-Type:", 13)==0)
    { if (savecontenttype)
        continue;
      if (mtype==MSG_ENTITY)
      { pconttype=(char *)p;
        continue;
      }
    }
    if ((mtype==MSG_ENTITY) &&
        (strnicmp((char *)p, "Content-Transfer-Encoding:", 26)==0))
    { getvalue((char *)p, val, sizeof(val));
      if ((stricmp(val, "base64")==0) ||
          (stricmp(val, "quoted-printable")==0) ||
          (stricmp(val, "x-uue")==0) ||
          (stricmp(val, "x-uucode")==0) ||
          (stricmp(val, "x-uuencode")==0))
      { /* change to "8bit" */
        p2=p+hstrlen(p)+1;
        strcpy((char *)p+26, " 8bit" CRLF);
        p1=p+hstrlen(p)+1;
        while (*p2)
        { *p1++=*p2++;
          if (*p2=='\0') *p1++=*p2++;
        }
        *p1++=*p2++;
      }
      continue;
    }
    if ((mtype==MSG_ENTITY) && strnicmp((char *)p, "Content-Length:", 15))
      continue;
    /* del this line */
    p2=p+hstrlen(p)+1;
    p1=p;
    while (*p2)
    { *p1++=*p2++;
      if (*p2=='\0') *p1++=*p2++;
    }
    *p1++=*p2++;
    goto begdelhdr;
  }
  if (header[0]=='\0')
    header[1]='\0';
  if (pconttype==NULL) return;
  sprintf(val, "Content-Type: text/plain; charset=%s" CRLF, intsetname);
  i=strlen(val)-strlen(pconttype);
  if (i==0)
  { strcpy(pconttype, val);
    return;
  }
  if (i<0)
  { p=pconttype;
    p2=p+hstrlen(p)+1;
    hstrcpy((char *)p, val);
    p1=p+hstrlen(p)+1;
    while (*p2)
    { *p1++=*p2++;
      if (*p2=='\0') *p1++=*p2++;
    }
    *p1++=*p2++;
    return;
  }
  if ((p-header+1+i)/MAXHEADER>hdrsize/MAXHEADER)
  { /* allocated buffer too small */
    p2=pconttype+strlen(pconttype)+1;
    for (p1=pconttype; *p2; )
    while (*p2)
    { *p1++=*p2++;
      if (*p2=='\0') *p1++=*p2++;
    }
    *p1++=*p2++;
    if (header[0]=='\0') header[1]='\0';
    return;
  }
  p2=pconttype+strlen(pconttype);
  for (p1=p; p1>p2; p1--)
    p1[i]=p1[0];
  strcpy(pconttype, val);
}

static int unmime(char *boundary, msg_type mtype, int alternate, char _Huge *up_header)
{ int  inhdr;
  char _Huge *header, _Huge *pheader, _Huge *oldheader=NULL;
  char _Huge *save_cur_hdr=NULL;
  char *p, *new_bound, *canonchrs;
  long hdrsize;
  int  r;
  long save_imsgbuf=0;
  msgloctype save_msgloc=0;
#ifdef __OS2__
  char *sheader=NULL;
#endif
#ifdef HDRCONTENT
  char *our_header;
#else
  char *lastfield;
#endif

  debug(6, "Unmime, boundary='%s'", boundary ? boundary : "NULL");
  was_eol=1;
  inhdr=1;
  hdrsize=MAXHEADER;
  header=farmalloc(hdrsize);
  func_decode = raw_func;
  if (header==NULL)
  { logwrite('?', "Not enough memory  :-(\n");
    return -1;
  }
  pheader=header;
  /* copy up_header to header */
  if (up_header && (mtype!=MSG_ENTITY))
  { for (p=(char *)up_header; *p; p=(char *)((char _Huge *)p+hstrlen(p)+1))
    { if ((strnicmp(p, "Content-", 8)==0) ||
          (strnicmp(p, "Message-Id:", 11)==0))
        continue;
      while (pheader-header+hstrlen(p)+2>hdrsize)
      { oldheader=header;
        if ((header=myrealloc((char *)header, hdrsize, hdrsize+MAXHEADER))==NULL)
        { logwrite('?', "Too large header :-(\n");
          break;
        }
        hdrsize+=MAXHEADER;
        pheader+=(header-oldheader);
      }
      if (header==NULL) break;
      hstrcpy((char *)pheader, p);
      pheader+=hstrlen(pheader)+1;
    }
    if (*p)
    { farfree((char *)header);
      return -1;
    }
  }
  if (up_header && (mtype==MSG_ENTITY))
  { if (strncmp((char *)header, "From ", 5)==0)
    { strcpy((char *)header, (char *)up_header); /* "From " */
      pheader=header+strlen((char *)header)+1;
    }
    else
    { header[0]=header[1]='\0';
      pheader=header;
    }
  }
  if (mtype==MSG_RFC)
    origmsgid=NULL;
#ifndef HDRCONTENT
  if (funix)
    xtable=set_table("", extsetname);
  else
    xtable=set_table("", intsetname);
  lastfield=NULL;
#else
  our_header=(char *)pheader;
#endif
  while (myfgets(gotstr, sizeof(gotstr)))
  {
    if (was_eol)
    { if (mtype!=MSG_RFC && boundary)
        if (strncmp(boundary, gotstr, strlen(boundary))==0)
          break;
      if (strcmp(gotstr, CRLF)==0)
      { inhdr=0;
        break;
      }
    }
    if (strchr(gotstr, '\n'))
      was_eol=1;
    else
      was_eol=0;
#ifndef HDRCONTENT
    for (p=gotstr; *p; p++)
      if (*p & 0x80)
        *p=xtable[*p & 0x7f];
#endif
    while (pheader-header+strlen(gotstr)+2>hdrsize)
    { oldheader=header;
      if ((header=myrealloc((char *)header, hdrsize, hdrsize+MAXHEADER))==NULL)
      { logwrite('?', "Too large header :-(\n");
        break;
      }
      hdrsize+=MAXHEADER;
      pheader+=(header-oldheader);
#ifdef HDRCONTENT
      our_header=(char*)((char _Huge *)our_header+(header-oldheader));
#else
      if (lastfield)
        lastfield=(char*)((char _Huge *)lastfield+(header-oldheader));
#endif
    }
    if (header==NULL) break;
    strcpy((char *)pheader, gotstr);
    p=(char *)pheader;
    if (isspace(gotstr[0]) && (pheader!=header))
    { pheader--;
      hstrcpy((char *)pheader, (char *)(pheader+1));
      p=NULL;
    }
#ifndef BOUNCEBADHDR /* Incorrect hdr line is continuation of previous */
    if ((!isspace(gotstr[0])) && (pheader!=header))
    { for (p=gotstr; *p && *p!=';' && (!isspace(*p)); p++);
      if (*p!=':' && strncmp(gotstr, "From ", 5) && mtype!=MSG_RFC)
      { *(pheader-1)=' ';
        p=NULL;
      }
    }
#endif
#ifndef HDRCONTENT
    if (p)
    { if (lastfield)
      { p=unmime_header(lastfield);
        if (p)
        { p++;
          hstrcpy(p, (char *)pheader);
          pheader=p;
        }
        else
        { lastfield=NULL;
          break;
        }
      }
      lastfield=(char *)pheader;
    }
#endif
    pheader+=hstrlen(pheader)+1;
  }
#ifndef HDRCONTENT
  if (lastfield)
  { p=unmime_header(lastfield);
    if (p)
      pheader=p+1;
  }
#endif
  *pheader='\0'; /* to '\0' - end of header */
  if (inhdr)
  { if (header==NULL)
    { header=oldheader;
      r=-1; /* farmalloc fail */
    }
    else if (mtype!=MSG_RFC)
    { if (boundary && strncmp(boundary, gotstr, strlen(boundary))==0)
      { logwrite('!', "Incorrect message part!\n");
        r=0;
      }
      else
      { /* logwrite('!', "End-boundary missed in multipart-message!\n"); */
        r=1;
      }
    }
    else
    { logwrite('?', "Incorrect message!\n");
      r=-1;
    }
    farfree((char *)header);
    if (r==-1)
      retcode|=RET_ERR;
    return r;
  }

  debug(6, "Unmime: header is correct");
  if (conf && (mtype==MSG_RFC))
  { if (newsgroups)
      free(newsgroups);
    p=getfield(header, "Newsgroups");
    if (p)
    { for (p+=11; isspace(*p); p++);
      newsgroups=strdup(p);
      if (newsgroups==NULL)
      { logwrite('?', "Not enough memory for newsgroups list!\n");
        farfree((char *)header);
        retcode|=RET_ERR;
        return -1;
      }
      /* canonize newsgroups format */
      for (p=newsgroups; *p; p++)
      { if (isspace(*p)) *p=',';
        if (*p!=',') continue;
        while (isspace(p[1]) || (p[1]==','))
          mstrcpy(p, p+1);
        if (p[1]=='\0')
        { *p='\0';
          break;
        }
      }
      debug(9, "Unmime: newsgroups is '%s'", newsgroups);
    }
    else
      newsgroups=NULL;
  }
  /* header in memory, now parse it */
  p=getfield(header, "Content-Type");
  if (p)
  { getvalue(p, cont_type, sizeof(cont_type));
    getparam(p, "charset", charset, sizeof(charset));
  }
  else
  { strcpy(cont_type, "text/plain");
    charset[0]='\0';
  }
  p=getfield(header, "Content-Transfer-Encoding");
  if (p) getvalue(p, encoding, sizeof(encoding));
  else encoding[0]='\0';
  attname[0]='\0';
  debug(6, "Unmime: content-type is '%s'", cont_type);

#ifdef HDRCONTENT
  /* decode & unmime header */
  is_utf8=0;
  canonchrs=canoncharset(charset);
  if (stricmp(canonchrs, "utf-8") || charsetsdir[0] == '\0')
  { if (funix)
      xtable=set_table(charset, extsetname);
    else
      xtable=set_table(charset, intsetname);
  }
  else
  { if ((inttable=findtable(intsetname, charsetsdir)) != NULL)
      is_utf8=1;
  }
  while (*our_header)
  { char *p1, *p2;
    p2=(char *)((char _Huge *)our_header+hstrlen(our_header)+1);
    if (is_utf8)
      decode_utf8_string(our_header);
    else
      for (p=our_header; *p; p=(char *)((char _Huge *)p+1))
        if (*p & 0x80)
          *p=xtable[*p & 0x7f];
    p=p2;
    p1=unmime_header(our_header);
    if (p1==NULL)
    { retcode|=RET_ERR;
      logwrite('?', "Incorrect message %sheader!\n",
               (mtype==MSG_RFC) ? "" : "part ");
      farfree((char *)header);
      return -1;
    }
    if ((char _Huge *)p1+1!=(char _Huge *)p)
    { while (*p)
      { p2=(char *)((char _Huge *)p+hstrlen(p)+1);
        hstrcpy(p1+1, p);
        p=p2;
        p1++;
#if 0
        p1+=strlen(p1);
#else
        while (*p1) p1=(char *)((char _Huge *)p1+1);
#endif
      }
      *(p1+1)='\0';
    }
#if 0
    our_header+=strlen(our_header)+1;
#else
    while (*our_header) our_header=(char *)((char _Huge *)our_header+1);
    our_header++;
#endif
  }
  debug(10, "Unmime: header recoded & unmimed");
#endif

  if (mtype==MSG_RFC)
  { p=getfield(header, "Message-Id");
    if (p) origmsgid=p;
  }

  if (mtype!=MSG_ENTITY)
    inreport=nottext=0;

  if (alternate &&
      stricmp(cont_type, "text") && stricmp(cont_type, "text/plain"))
  { debug(1, "Move %s part of multipart/alternative to /dev/null", cont_type);
devnull:
    if (mtype==MSG_ENTITY)
    { sprintf(str, CRLF "[%s part skipped]" CRLF, cont_type);
      for (p=str; *p; p++)
        fputbyte(*p);
    }
    farfree((char *)header);
    while (fgetbyte()!=-1);
    return was_eof;
  }

  if (kill_vcard && stricmp(cont_type, "text/x-vcard")==0)
  { debug(1, "Move text/x-vcard to /dev/null");
    goto devnull;
  }

  if (strnicmp(cont_type, "multipart", 9)==0)
  {   msg_type newmtype;
      int firstpart;

      new_bound=malloc(80);
      if (new_bound==NULL)
      { logwrite('?', "Not enough memory!\n");
        goto nomime;
      }
      if (nosplit || (mtype==MSG_ENTITY) ||
          ((stricmp(cont_type+9, "/report")==0) && !split_report))
        newmtype=MSG_ENTITY;
      else
        newmtype=MSG_SPLITTED;
      if (!split_report && mtype!=MSG_ENTITY &&
          stricmp(cont_type+9, "/report")==0)
        inreport=1;
      p=getfield(header, "Content-Type");
      strcpy(new_bound, "--");
      getparam(p, "boundary", new_bound+2, 78);
      if (new_bound[2]=='\0')
      { free(new_bound);
        goto nomime;
      }
      delmimehdr(header, 1, mtype);
      if (newmtype==MSG_ENTITY)
      { /* write header */
        if (mtype!=MSG_ENTITY)
        { cur_hdr=pcur_hdr=header;
          imsgbuf=0;
          msgloc=LOC_MEMORY;
        }
        else
        { char _Huge * p;
          for (p=header; ; p++)
          { if (*p==0)
              if (*++p==0)
                break;
            fputbyte(*p);
          }
          fputbyte('\n');
        }
      }
      /* read parts and run unmime for each of them */
      while (myfgets(gotstr, sizeof(gotstr)))
      { if (boundary)
          if (strncmp(gotstr, boundary, strlen(boundary))==0)
            break;
        if (strncmp(gotstr, new_bound, strlen(new_bound))==0)
          break;
        if (newmtype==MSG_ENTITY)
          for (p=gotstr; *p; p++)
            fputbyte(*p);
      }
      if (strncmp(gotstr, new_bound, strlen(new_bound)))
      { /* no boundary found */
        logwrite('?', "No boundary found in multipart!\n");
        r=(newmtype==MSG_SPLITTED) ? -1 : 1;
        goto eomultipart;
      }

      /* copy up_header to header for message parts */
      if (mtype==MSG_ENTITY)
      { char _Huge *oldhdr=header;
        char _Huge *p, _Huge *p1;

        for (p=up_header; *p; p+=hstrlen((char *)p)+1);
        for (p1=header; *p1; p1+=hstrlen((char *)p1)+1);
        header=farmalloc((p-up_header)+(p1-header)+2);
        if (header)
        { p1=header;
          for (p=up_header; *p; p+=hstrlen(p)+1)
          { if (strnicmp((char *)p, "Content-", 8)==0)
              continue;
            hstrcpy((char *)p1, (char *)p);
            p1+=hstrlen(p1)+1;
          }
          for (p=oldhdr; *p; p+=hstrlen(p)+1)
          { hstrcpy((char *)p1, (char *)p);
            p1+=hstrlen(p1)+1;
          }
          *p1='\0';
          if (p1==header) p1[1]='\0';
          farfree((char *)oldhdr);
        }
        else
          header=oldhdr;
      }
        
      r=0;
      if (stricmp(cont_type, "multipart/alternative")==0 && do_alternate)
        firstpart=1;
      else
        firstpart=-1;
      for (;;)
      {
        if (strncmp(gotstr, new_bound, strlen(new_bound)))
        { was_eof=1;
          break;
        }
        if (newmtype==MSG_ENTITY)
          for (p=gotstr; *p; p++)
            fputbyte(*p);
        if (strncmp(gotstr+strlen(new_bound), "--", 2)==0)
        { was_eof=0;
          break;
        }
        if (firstpart==0)
          r=unmime(new_bound, newmtype, 1, header);
        else
        { r=unmime(new_bound, newmtype, 0, header);
          if (firstpart==1) firstpart=0;
        }
        if (r==1)
        { logwrite('!', "End-boundary missed in multipart message!\n");
          if (newmtype==MSG_ENTITY)
            goto eomultipart;
          /* skip all after end-boundary */
          free(new_bound);
          farfree((char *)header);
          if (newsgroups && (mtype==MSG_RFC))
          { free(newsgroups);
            newsgroups=NULL;
          }
          return r;
        }
        if (newmtype==MSG_ENTITY)
          for (p=CRLF; *p; fputbyte(*p++));
        if (r) break;
      }
      /* skip rest of body */
      bound=boundary;
      if (r==0)
      { pstrgetbyte=NULL;
        was_empty=0;
        was_eof=0;
        was_eol=1;
        while ((r=fgetbyte())!=-1)
          if (newmtype==MSG_ENTITY)
            fputbyte(r);
        r=0;
      }
eomultipart:
      free(new_bound);
      if ((newmtype==MSG_ENTITY) && (r!=-1) && (mtype!=MSG_ENTITY))
        if (eomessage())
          r=-1;
      farfree((char *)header);
      if (newsgroups && (mtype==MSG_RFC))
      { free(newsgroups);
        newsgroups=NULL;
      }
      if (r) return r;
      return 0;
  }
  destname[0]='\0';
  longname=NULL;
  if (stricmp(encoding, "base64")==0)
    func_decode=unbase64;
  else if (stricmp(encoding, "quoted-printable")==0)
    func_decode=unqp;
  else if ((stricmp(encoding, "x-uue")==0) ||
           (stricmp(encoding, "x-uucode")==0) ||
           (stricmp(encoding, "x-uuencode")==0))
    func_decode=uudecode;
  else
    func_decode=raw_func;
  if (strnicmp(cont_type, "message", 7)==0 && func_decode!=uudecode)
  { if (stricmp(cont_type, "message/rfc822"))
      goto nomime;
    delmimehdr(header, 1, mtype);
    if (nosplit || (mtype==MSG_ENTITY))
    { /* write header */
      if (mtype!=MSG_ENTITY)
      { cur_hdr=pcur_hdr=header;
        imsgbuf=0;
        msgloc=LOC_MEMORY;
      }
      else
      { char _Huge * p;
        for (p=header; ; p++)
        { if (*p==0)
            if (*++p==0)
              break;
          fputbyte(*p);
        }
        fputbyte('\n');
      }
    }
    p=malloc(strlen((char *)header)+2);
    if (p==NULL)
      r=-1;
    else
    { if (strncmp((char *)header, "From ", 5)==0)
        strcpy(p, (char *)header);
      else
        *p='\0';
      p[strlen(p)+1]='\0'; /* leave only "From " */
      r=unmime(boundary,
               (nosplit || (mtype==MSG_ENTITY)) ? MSG_ENTITY : MSG_SPLITTED, 0, p);
      if (nosplit && (r!=-1) && (mtype!=MSG_ENTITY))
        if (eomessage())
          r=-1;
      free(p);
    }
    if (newsgroups && (mtype==MSG_RFC))
    { free(newsgroups);
      newsgroups=NULL;
    }
    farfree((char *)header);
    return r;
  }
  else if (strnicmp(cont_type, "text", 4) || func_decode==uudecode)
  {
    /* binary file */
    nottext=1;
attach:
    destname[0]='\0';
    longname=NULL;
    p=getfield(header, "Content-Type");
    if (p)
      getparam(p, "name", destname, sizeof(destname));
    if (destname[0]=='\0')
    { p=getfield(header, "Content-Disposition");
      if (p)
      { getparam(p, "filename", destname, sizeof(destname));
#if 0
        if (destname[0]==0)
          getvalue(p, destname, sizeof(destname));
#endif
      }
    }
    if (destname[0]=='\0')
    { /* make filename */
      if (strnicmp(cont_type, "image", 5)==0)
      { if (stricmp(cont_type, "image/gif")==0)
          ext="gif";
        else if (stricmp(cont_type, "image/jpeg")==0)
          ext="jpg";
        else
          ext="img";
      }
      else if (strnicmp(cont_type, "message", 7)==0)
        ext="txt";
      else if (strnicmp(cont_type, "application", 11)==0)
      { if (stricmp(cont_type, "application/postscript")==0)
          ext="ps";
        else
          ext="dat";
      }
      else if (strnicmp(cont_type, "video", 5)==0)
        ext="mpg";
      else if (strnicmp(cont_type, "text", 4)==0)
        ext="txt";
      else if (strnicmp(cont_type, "audio", 5)==0)
        ext="au";
      else
        ext="dat";
      for (r=1; r<10000; r++)
      { sprintf(destname, "%s%u.%s", holdpath, r, ext);
        if (access(destname, 0))
          break;
      }
      sprintf(destname, "%u.%s", r, ext);
      debug(7, "UnMime: create filename %s", destname);
    }
    else
    { debug(7, "UnMime: get filename %s", destname);
      longname=destname;
    }
    xtable=raw_table;
  }
  else
  {
    p=getfield(header, "Content-Disposition");
    if (p)
    { getvalue(p, destname, sizeof(destname));
      if (stricmp(destname, "attachment")==0 && !conf && !keepatt && !inreport)
        goto attach;
      destname[0]='\0';
    }
nomime:
    if (stricmp(cont_type, "text/plain")==0 || stricmp(cont_type, "text")==0)
    { if (stricmp(encoding, "base64") && stricmp(encoding, "quoted-printable"))
        xtable=set_table(charset, funix ? extsetname : intsetname);   /* by default - x-cp866 */
      else
        xtable=set_table(charset, extsetname);  /* by default - koi8 */
    }
    else
      xtable=raw_table;
  }
  if ((keepatt || conf || inreport) && (destname[0] || func_decode==uudecode))
    func_decode=raw_func;
  else if ((!known_charset) || (func_decode == uudecode) || destname[0] ||
           (stricmp(cont_type, "text/plain") && stricmp(cont_type, "text")))
  { /* unknown charset or not text/plain */
    if ((destname[0] || func_decode==uudecode) &&
        !keepatt && !conf && !inreport)
    {
#ifdef __OS2__
      /* save original header for EA */
      char _Huge *p;
      for (p=header; *p; p+=hstrlen(p)+1);
      if (sheader) free(sheader);
      if (origmsgid) p+=strlen(origmsgid);
      if ((sheader=farmalloc(p-header+1))!=NULL)
      { int  wasmsgid=0;
        sheader[0]='\0';
        for (p=header; *p; p+=hstrlen(p)+1)
        { if (strnicmp((char *)p, "Message-Id:", 11)==0)
            wasmsgid=1;
#if 0
          strcat(sheader, (char *)p);
#else
          hstrcpy((char *)((char _Huge *)sheader+hstrlen(sheader)), (char *)p);
#endif
        }
        if (origmsgid && !wasmsgid && (mtype!=MSG_ENTITY))
          strcat(sheader, origmsgid);
      }
#endif
      delmimehdr(header, 0, mtype); /* remove all in fileattaches */
    }
    else
      delmimehdr(header, 1, mtype);
  }
  else
    delmimehdr(header, 0, mtype);
  /* write header */
  if (mtype!=MSG_ENTITY)
  { cur_hdr=pcur_hdr=header;
    imsgbuf=0;
    msgloc=LOC_MEMORY;
  }
  else
  { char _Huge *p;
    for (p=header; ; p++)
    { if (*p==0)
        if (*++p==0)
          break;
      fputbyte(*p);
    }
    fputbyte('\n');
  }
  if ((destname[0] || func_decode==uudecode) &&
      !keepatt && !conf && !inreport && mtype==MSG_ENTITY)
  { /* decode attach */
    save_cur_hdr=cur_hdr;
    save_imsgbuf=imsgbuf;
    save_msgloc=msgloc;
    pcur_hdr=header;
    
    /* copy up_header to header */
    hdrsize=MAXHEADER;
    header=farmalloc(hdrsize);
    if (header==NULL)
    { logwrite('?', "Not enough memory  :-(\n");
      return -1;
    }
    pheader=header;
    if (up_header)
    { for (p=(char *)up_header; *p; p=(char *)((char _Huge *)p+hstrlen(p)+1))
      { if ((strnicmp(p, "Content-", 8)==0) ||
            (strnicmp(p, "Message-Id:", 11)==0))
          continue;
        while (pheader-header+hstrlen(p)+2>hdrsize)
        { oldheader=header;
          if ((header=myrealloc((char *)header, hdrsize, hdrsize+MAXHEADER))==NULL)
          { logwrite('?', "Too large header :-(\n");
            break;
          }
          hdrsize+=MAXHEADER;
          pheader+=(header-oldheader);
        }
        if (header==NULL) break;
        hstrcpy((char *)pheader, p);
        pheader+=hstrlen(pheader)+1;
      }
      if (*p)
      { farfree((char *)header);
        farfree((char *)pcur_hdr);
#ifdef __OS2__
        if (sheader)
        { free(sheader);
          sheader=NULL;
        }
#endif
        return -1;
      }
#ifdef __OS2__
      else
      {
        /* add up_header to sheader */
        char *p, *sheader1;
        for (p=up_header; *p; p+=hstrlen(p)+1);
        if ((sheader1=malloc(p-up_header+1+strlen(sheader)))==NULL)
        { if (sheader) free(sheader);
          sheader=NULL;
        }
        else
        { sheader1[0]='\0';
          for (p=up_header; *p; p+=strlen((char *)p)+1)
            if (strnicmp(p, "Content-", 8))
              strcat(sheader1, p);
          strcat(sheader1, sheader);
          free(sheader);
          sheader=sheader1;
        }
      }
#endif

    }
    for (p=(char *)pcur_hdr; *p; p=(char *)((char _Huge *)p+hstrlen(p)+1))
    { while (pheader-header+hstrlen(p)+2>hdrsize)
      { oldheader=header;
        if ((header=myrealloc((char *)header, hdrsize, hdrsize+MAXHEADER))==NULL)
        { logwrite('?', "Too large header :-(\n");
          break;
        }
        hdrsize+=MAXHEADER;
        pheader+=(header-oldheader);
      }
      if (header==NULL) break;
      hstrcpy((char *)pheader, p);
      pheader+=hstrlen(pheader)+1;
    }
    if (*p)
    { farfree((char *)header);
      farfree((char *)pcur_hdr);
#ifdef __OS2__
      if (sheader)
      { free(sheader);
        sheader=NULL;
      }
#endif
      return -1;
    }
    *pheader='\0';
    farfree((char *)pcur_hdr);
    cur_hdr=pcur_hdr=header;
    imsgbuf=0;
    msgloc=LOC_MEMORY;
  }
  /* write the file */
  was_eof=0;
  was_eol=1;
  was_empty=0;
  pstrgetbyte=NULL;
  bound=boundary;
  if (destname[0] && !keepatt && !conf && !inreport)
  { /* get fileattach pathname */
    strcpy(attname, destname);
    set_path(attname);
    get_uniq(attname);
    
    fatt=fopen(attname, "wb");
    if (fatt==NULL)
    { logwrite('?', "Can't create attached file %s: %s!\n", attname,
               strerror(errno));
      r=-1;
    }
    else
    { r=func_decode(fgetbyte, fputattbyte);
      fclose(fatt);
      if (r==-1)
        unlink(attname);
#ifdef __OS2__
      else
      /* set EA: .TYPE and HEADER */
      { if (sheader)
        { /* change "\r\n" -> "\n" */
          char _Huge *p;
          for (p=sheader; *p; p++)
            if (p[0]=='\r' && p[1]=='\n')
              hstrcpy((char *)p, (char *)p+1);
          easet(attname, "HEADER", sheader);
          free(sheader); 
          sheader=NULL;
        }
        easet(attname, ".TYPE", cont_type);
        if (longname)
          easet(attname, ".LONGNAME", longname);
      }
#endif
    }
  }
  else
  {
    r=func_decode(fgetbyte, is_utf8 ? utf_putbyte : fputbyte);
    if (is_utf8)
      utf_flushputbyte();
  }
#ifdef __OS2__
  if (sheader)
  { free(sheader);
    sheader=NULL;
  }
#endif
  if (r==-1) /* unrecoverable error */
  { farfree((char *)header);
    if (newsgroups && (mtype==MSG_RFC))
    { free(newsgroups);
      newsgroups=NULL;
    }
    retcode|=RET_ERR;
    return -1;
  }
  r=was_eof;
  if (keepatt || conf || inreport)
    attname[0]='\0';
  if (mtype!=MSG_ENTITY)
  { debug(7, "UnMime: call eomessage");
    if (eomessage())
    { r=-1;
      if (destname[0] && !keepatt && !conf && !inreport)
        unlink(attname);
    }
  }
  else if (destname[0] && !keepatt && !conf && !inreport && mtype==MSG_ENTITY)
  { char *s;

    debug(7, "UnMime: call eomessage");
    if (eomessage())
    { r=-1;
      unlink(attname);
    }
    cur_hdr=pcur_hdr=save_cur_hdr;
    imsgbuf=save_imsgbuf;
    msgloc=save_msgloc;
    s=malloc(strlen(destname)+80);
    if (s==NULL)
    { logwrite('?', "Not enough memory :-(\n");
      return -1;
    }
    sprintf(s, "[FileAttach%s%s]\n",
            longname ? " " : "", longname ? longname : "");
    for (p=s; *p; p++)
      fputbyte(*p);
    free(s);
    attname[0]=destname[0]='\0';
    longname=NULL;
  }
  farfree((char *)header);
  if (newsgroups && (mtype==MSG_RFC))
  { free(newsgroups);
    newsgroups=NULL;
  }
  return r;
}

int msg_unmime(long msize)
{ int r;
  char *up_header;

  /* if msgsize=-1 - whole file,
     if msgsize=0  - single message from mailbox
     if msgsize>0  - read only msgsize bytes
  */

  msgsize=msize;
  mbufsize=0;
  if (msgsize>0) mbufsize=msgsize;
  else if (msgsize==-1)
  { if (isfile(fileno(stdin)))
      /* file */
      mbufsize=filelength(fileno(stdin));
    else
      mbufsize=0;
  }
#if 0
  if (maxpart && (mbufsize>maxpart*1024l))
    mbufsize=maxpart*1024l;
#endif
#ifdef __MSDOS__
  /* mbufsize will be needed for buffer in one-message */
  /* so, we decrease unmime buffer and not decrease split size */
  { long freemem=getfreemem();
    debug(6, "msg_unmime: farcoreleft=%ld", freemem);
    if (mbufsize+maxpart*1024l+RESPART>freemem)
      mbufsize=freemem-maxpart*1024-RESPART-0x2000;
    /* if (mbufsize>0xffff) mbufsize=0x8000; */
    if (mbufsize==0) mbufsize=MSGBUFSIZE;
    if (mbufsize>freemem-MINPARTSIZE-0x2000)
      mbufsize=freemem-MINPARTSIZE-0x2000;
    if (mbufsize<=0)
    { mbufsize=(freemem-0x2000)/4;
      if (mbufsize>0xffff) mbufsize=0x8000;
    }
    if (mbufsize>MSGBUFSIZE)
      mbufsize=MSGBUFSIZE; /* do not allocate too large mem buffer */
    if (mbufsize<=0)
      mbufsize=0x8000; /* not enough core */
  }
#else
  if (mbufsize==0) mbufsize=maxpart*1024l;
  if (mbufsize==0) mbufsize=MSGBUFSIZE;
#endif
  debug(6, "msg_unmime: set message buffer to %ld bytes", mbufsize);
  msgbuf=createbuf(mbufsize+=RESPART);
  if (msgbuf==NULL)
  { logwrite('?', "Not enough memory!\n");
    retcode|=RET_ERR;
    return -1;
  }
  if (conf || !bypipe)
    envelope_from[0]='\0';
  gotstr[strlen(gotstr)+1]='\0';
  was_eof=0;
  if ((up_header=malloc(strlen(gotstr)+2))==NULL)
  { freebuf(msgbuf);
    retcode|=RET_ERR;
    logwrite('?', "Not enough memory!\n");
    return -1;
  }
  strcpy(up_header, gotstr);
  up_header[strlen(up_header)+1]='\0';
  if (msgsize==0)
  { msgsize=-1;
    debug(6, "msg_unmime: call unmime");
#ifndef UNIX
    if (uupcver==KENDRA)
      r=unmime(UUPCEXTSEP, MSG_RFC, 0, NULL);
    else
#endif
      r=unmime("From ", MSG_RFC, 0, up_header);
  }
  else
    r=unmime(NULL, MSG_RFC, 0, up_header);
  freebuf(msgbuf);
  free(up_header);
  if (msgloc==LOC_FILE)
  { close(f);
    unlink(namemsg);
  }
  if (r==-1)
  { retcode|=RET_ERR;
    return -1;
  }
  return 0;
}

int myfgetc(void)
{
  if (msgsize==0) return EOF;
  if ((ibufsrc==potoloksrc) || (ibufsrc==BUFSIZE))
  {
    potoloksrc=read(fileno(stdin), bufsrc, BUFSIZE);
    ibufsrc=0;
    if (potoloksrc==0)
    { was_eof=1;
      return EOF;
    }
  }
  if (msgsize>0) msgsize--;
  return bufsrc[ibufsrc++];
}

int myfgets(char *gotstr, int len)
{ /* always return CRLF-terminated strings */
  int i, r;
  static int mywascr=0;

  for (i=0; i<len-2;)
  {
    r=myfgetc();
    if (r==EOF)
    { gotstr[i]=0;
      return i;
    }
    if ((r=='\n') /* && funix */ && !mywascr)
      gotstr[i++]='\r';
    gotstr[i++]=(char)r;
    if (r=='\n')
    { gotstr[i]=0;
      if (msgsize<0)
        if ((strcmp(gotstr, "\x1a\n")==0) || (strcmp(gotstr, "\x1a\r\n")==0))
        { if ((r=myfgetc())==EOF)
          { gotstr[0]='\0'; /* sendmail hack */
            return 0;
          }
          else
            ibufsrc--; /* ungetch */
        }
      return i;
    }
    mywascr=(r=='\r');
  }
  gotstr[i]=0;
  return i;
}

int hgetc(void)
{ int  r;
  if (pcur_hdr)
  {
    if (*pcur_hdr)
      r=*pcur_hdr++;
    else if (*(++pcur_hdr))
      r=*pcur_hdr++;
    else
    { pcur_hdr=NULL;
      r='\n';
    }
    if ((pcur_hdr) && (r=='\r'))
      if (*pcur_hdr=='\n')
        r=*pcur_hdr++;
    return r;
  }
  if (msgloc==LOC_MEMORY)
  { if (imsgbuf==maxmsgbuf) return -1;
    r=getbuflem(msgbuf, imsgbuf++);
    fsize--;
    return r;
  }
  /* temp file */
  if ((ibuf==BUFSIZE) || (ibuf==potolok))
  { potolok=read(f, buffer, BUFSIZE);
    if (potolok==0)
    { waseof=1;
      ibuf=BUFSIZE;
      return -1;
    }
    ibuf=0;
  }
  fsize--;
  r=buffer[ibuf++];
  return r;
}

void hrewind(void)
{
  init_textline();
  if (pcur_hdr)
  { pcur_hdr=cur_hdr;
    return;
  }
  pcur_hdr=cur_hdr;
  fsize=maxmsgbuf;
  if (msgloc==LOC_MEMORY)
  { imsgbuf=0;
    return;
  }
  /* msgloc==LOC_FILE */
  if (lseek(f, 0, SEEK_CUR)>BUFSIZE)
  {
    lseek(f, 0, SEEK_SET);
    ibuf=BUFSIZE;
    return;
  }
  ibuf=0;
  return;
}
