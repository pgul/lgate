/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:24  gul
 * We are under CVS for now
 *
 */
#define VER         "7.01"
#define MAJVER      7u
#define MINVER      1u
#define NAZVA       "LuckyGate" HALF " " VER
#define VERSION     NAZVA "    "__DATE__
#define MYNAME      "Internet->FTN Gate"
#define REL2FIDO
#define SSIZE       80
#define MAXADDR     256
#define MAXDOM      64
#define MAXSTR      2048
#define MAXXC       64 /* только для отлова дупов */
#define MAXSEENBY   240
#define MAXNHEADER  64 /* max число полей заголовка */
#define MINPARTSIZE 0x4000 /* 16384 */
#define MAXHEADER   0x1000 /*  4096 */
#define MAXLINE     1024 /* 1000 by rfc */
#define MAXORIGIN   79
#define CRLF        "\r\n"
#define UUPCEXTSEP  ""
#define TMPNAME     "temp????.msg"
#define TMPZNAME    "temp????.z"
#define TMPUNZNAME  "temp????."
#define TMPOUT      "temp????.txt"
#define TMPIN       "temp????.let"
#define TMPBOXNAME  "tempgate.pst"
#define BADPSTNAME  "badmail.pst"
#define MSGREGEX    "^[0-9]+\\.msg$"
#define EXTSETNAME  "koi8-r"
#define INTSETNAME  "x-cp866"
#if defined(__MSDOS__)
#define BUFSIZE     0x1000 /* 4096 */
#else
#define BUFSIZE     0x4000 /* 16384 */
#define STACK_SIZE (1024*256) /* for threads */
#endif
#define MSGBUFSIZE  0x8000 /* > BUFSIZE! */
#define MAXPACK     20
#define MAX_PATH    80

#define ZAPAS       128    /* насколько в заголовок может быть записано */
                           /* больше, чем длина прочитанной строки */
#define NZAPAS      1      /* запас массива pheader */

#undef  FIDOUNKNWN
#define FSC90
#if 0
#define PRODCODE  0xFE
#else
#define PRODCODE  0xEFF
#endif

#define KENDRA      112
#define SENDMAIL    86

#define BADADDR     1
#define ITWIT       2
#define ITWITTO     3
#define ITWITFROM   4
#define ITWITVIA    5
#define MANYHOPS    6
#define REJ_ATTACH  7
#define REJ_HUGE    8
#define EXTERNAL    9

#define RET_ECHOMAIL 1
#define RET_NETMAIL  2
#define RET_ERR      4

#define RESPART      1024l

#include <libgate.h>

typedef enum {MSG_RFC, MSG_SPLITTED, MSG_ENTITY} msg_type;
typedef struct
  { uword net, node;
  } nodetype;
typedef enum {TO_MASTER, TO_SENDER} errtotype;
typedef enum {EXT_DEFOUT, EXT_DEFAULT, EXT_FREEOUT, EXT_FREE, EXT_DEVNULL,
              EXT_REJECT, EXT_HOLDOUT, EXT_HOLD} externtype;
typedef enum {LOC_MEMORY, LOC_FILE} msgloctype;

extern int  split_report, subj1line;
extern char intsetname[], extsetname[];
extern char raw_table[];
extern char remote[MAXADDR], local[MAXADDR];
extern char dirnews[FNAME_MAX];
extern char rescan[FNAME_MAX];
extern char organization[80], pktout[FNAME_MAX];
extern char tmpdir[FNAME_MAX];
extern char pktpwd[9];
extern char userbox[FNAME_MAX];
extern char badmail[FNAME_MAX], nconf[FNAME_MAX];
extern int  waschaddr;
extern int  use_swap;
extern unsigned pktsize;
extern char packmail, checksb, echolog, forgolded, domainmsgid, gatevia;
typedef enum { ATT_DECODE, ATT_KEEP, ATT_REJECT } keepatttype;
extern keepatttype keepatt;
extern char routeattach;
extern errtotype errorsto;
extern char netmaildir[FNAME_MAX];
extern char spool_dir[FNAME_MAX];
extern char binkout[FNAME_MAX];
extern char tboxes[FNAME_MAX];
#ifndef __MSDOS__
extern char lbso[FNAME_MAX], tlboxes[FNAME_MAX], longboxes[FNAME_MAX];
#endif
extern char rmail[FNAME_MAX], postmast[MAXADDR], localdom[MAXDOM];
extern char frescan[FNAME_MAX];
extern char uncompress[128];
extern char domainid[MAXADDR];
typedef char addrstring[64];
extern wildcard *itwit, *itwitto, *itwitfrom, *itwitvia;
extern int nitwit, nitwitto, nitwitfrom, nitwitvia;
extern char tofield[MAXADDR];
extern unsigned long attr;
extern struct akatype
       { uword zone, net, node, point;
         char domain[MAXDOM];
         char ftndomain[32];
         char uplink;
       } *myaka;
extern int  curaka, naka, nuplinks;
extern ftnaddr *uplink;
extern uword zone, net, node, point;
extern int  maxhops, curhops;
extern long maxpart;
extern unsigned long msgid;
extern unsigned holdsize;
extern char holdpath[FNAME_MAX];
extern int  tz;
extern char namec[FNAME_MAX], named[FNAME_MAX], namex[FNAME_MAX];
extern struct echo_type
       { char *fido;
         char *usenet;
         char aka;
         int  noxc      :1;
         int  checksubj :1;
       } _Huge *echoes;
extern int nechoes, ncaddr, ncdomain, nchecker;
extern struct caddrtype
       { char fido[36], relcom[128];
         uword zone, net, node, point;
       } *caddr;
extern struct cdomaintype
       { char fido[MAXDOM], relcom[MAXDOM];
       } *cdomain;
extern struct checktype
       { char mask[MAXDOM],cmdline[256];
       } *checker;
extern struct ftnchrs_type {
         struct ftnchrs_type *next;
         char *ftnchrs, *rfcchrs;
       } *ftnchrs;
extern int cnews, conf, funix, empty, inconfig, tplout, tabsize;
extern int  f;
extern char newechoflag[FNAME_MAX];
extern char *header;
extern char held_tpl[FNAME_MAX], badaddr_tpl[FNAME_MAX];
extern char addr[MAXADDR];
extern char *buffer;
extern char *newsgroups;
extern char msgname[FNAME_MAX];
extern unsigned ibuf;
extern char str[MAXSTR];
extern int  packnews, myorigin;
extern unsigned naddr;
extern long begdel;
extern char namedel[MAXPACK][FNAME_MAX];
extern char koi8alt_tab[256];
extern int  rcv2via, savehdr;
extern long seekfix, fsize;
extern unsigned ibuffix, potolok;
extern char fromaddr[MAXADDR];
extern char **pheader;
extern int  cheader;
extern int  fix;
extern int  nglobal;
extern int  tossbad, nonet, noecho, uppername;
extern int  bypipe, gulpipe, netmail2pst, fake, holdhuge;
extern char waseof;
extern int  wasfrom,wasmsgid;
extern unsigned long attrib;
extern uword lastzone;
extern int  npath, nseenby;
extern nodetype path[MAX_PATH];
extern struct strseenby { uword net, node;
                          char is;
                        } seenby[MAXSEENBY];
extern int  null, nonews;
extern char origin[MAXORIGIN+3], xorigin[120], tearline[120];
extern char fmsgid[SSIZE];
extern int  uupcver;
extern char *msgbuf;
extern long imsgbuf;
extern long maxmsgbuf;
extern int  notfile;
extern unsigned long pipetype;
extern int  retcode;
extern unsigned ibufsrc, potoloksrc;
extern char *bufsrc;
extern char softCR;
extern msgloctype msgloc;
extern long begsrcpos, omsgsize, msgsize;
extern char gotstr[MAXLINE];
extern long curhdrsize;
extern unsigned curnpheader;
extern long hdrsize;
extern int  seqf;
extern char curtplname[FNAME_MAX];
extern int  nosplit;
extern char xftnfrom[120];
extern ftnaddr xftnaddr;
extern int  shortvia;
extern char ext2pc[256];
extern char cmdline[CMDLINELEN];
extern char *pc2ext;
extern int  msgtz;
extern char envelope_from[MAXADDR];
extern char *myname;
extern char *origmsgid;
typedef enum {REPLY_EMPTY, REPLY_UUCP, REPLY_ADDR} replytype;
extern replytype replyform;
extern char attname[], destname[], *longname;
extern int  known_charset, nottext;
extern int  kill_vcard, do_alternate;
#ifdef msgDIRECT
extern struct packet pkthdr;
extern struct message msghdr;
#endif
#ifndef __MSDOS__
extern void *regbufmsg;
#endif
#ifdef _IOFBF  /* stdio.h included */
extern FILE *fout;
#endif
extern char charsetsdir[FNAME_MAX];
extern char charsetalias[FNAME_MAX];
extern int  putchrs;
extern char freply[SSIZE], freplydomain[MAXADDR];

int  fromuupcspool(void);
int  getfidoaddr(uword *zone, uword *net, uword *node,
                 uword *point, char *addr);
int  transaddr(char *user, uword *zone, uword *net, uword *node,
               uword *point, char *addr);
void parseaddr(char * str, char *addr, char *realname, int chaddr);
void koi8alt(char *string);
int  config(void);
void stripspc(char *string);
int  isbeg(char *s);
int  getletter(void);
int  nextmsg(void);
void writehdr(void);
int  hgets(void);
void hrewind(void);
int  hgetc(void);
int  hread(char *buf, unsigned bufsize);
void renbad(char *fname);
void badlet(void);
int  fidomsgid(char *str, char *s, char *domainid, unsigned long *msgid);
void rcvconv(char *recv);
char *rcvfrom(char *recv);
int  holdmsg(char *realname, char *fromaddr, char *subj);
int  holdatt(char *realname, char *fromaddr, char *subj);
void gofix(void);
void badpst(char *reason);
void badmess(char *reason);
int  params(int argc, char * argv[]);
void copybad(void);
#ifndef __MSDOS__
int GetLbsoBsyName(uword zone, uword net, uword node, uword point, char *domain,
               char *name);
int SetLbsoSem(uword zone, uword net, uword node, uword point, char *domain,
               char *name);
void DelLbsoSem(uword zone, uword net, uword node, uword point, char *domain);
#endif
void voidfunc(void);
int  voidgets(char *str, unsigned size);
int  parsedate(char *str);
void reject(int reason);
void putvia(char *str);
int  readhdr(void);
externtype extcheck(char *to, char *from, char **news
#ifdef DO_PERL
                    , char *subj
#endif
                    );
int  mktempname(char *sample, char *dest);
void chsubstr(char *str, char *from, char *to);
int  one_message(void);
int  isfile(int handle);
int  msg_unmime(long msize);
char *myrealloc(char *oldptr, long oldsize, long newsize);
int  chkhdrsize(char *str);
void altkoi8(char *s);
void getvalue(char *field, char *value, unsigned valsize);
int  hstrcpy(char *dest, char *src);
long hstrlen(char _Huge * str);
int  rnews(void);
void badnews(void);
int  akamatch(uword zone, uword net, uword node);
int  myfgets(char *str, int len);
char *quotemsgid(char *msgid);
char *renamepkt(char *tempname);
