/*
 * $Id$
 *
 * $Log$
 * Revision 2.6  2002/03/21 11:19:15  gul
 * Added support of msgid style <newsgroup|123@domain>
 *
 * Revision 2.5  2002/01/15 18:48:37  gul
 * Remove nkillattfiles=32 limitation
 *
 * Revision 2.4  2001/01/26 14:33:39  gul
 * Version changed to 7.02 in *.h
 *
 * Revision 2.3  2001/01/25 18:41:38  gul
 * myname moved to debug.c
 *
 * Revision 2.2  2001/01/21 10:20:00  gul
 * new cfg param 'fromtop'
 *
 * Revision 2.1  2001/01/15 03:37:09  gul
 * Stack overflow in dos-version fixed.
 * Some cosmetic changes.
 *
 * Revision 2.0  2001/01/10 20:42:17  gul
 * We are under CVS for now
 *
 */
#define VER         "7.02"
#define MAJVER      7u
#define MINVER      2u
#define NAZVA       "LuckyGate" HALF " " VER
#define COPYRIGHT   NAZVA "  " __DATE__
#define FIDO2REL
#define MAXCDOM     16
#define MAXPADDR    16
#define MAXSEND     32
#define MAXREJ      32
#define MAXFREE     16
#define MAXTWIT     16
#define MAXNOTWIT   16
#define MAXAKA      16
#define MAXGROUPS   32
#define MAXUPLINKS  32
#define MAXGATES    32
#define MAXPREFIX   40
#define MAXBEGPREF   8
#define TMPUNZNAME  "temp????." /* Без расширения! */
#define EXTSETNAME  "koi8-r"
#define INTSETNAME  "x-cp866"
#define MAXHEADER   0x8000u
#define MAXFIELDS   (MAXHEADER/32)
#define BUFSIZE     0x4000 /* 16384 */
#define LRDNAME     "lgate.lrd"
#define NOSUBJ      "<None>"
#define MAXAGE      14 /* max age echomail message; if older, date will reset */
#define MAXUNFOLD   200
#define MAX_PATH    80
#define NKILLATTFILES 32
#ifdef __OS2__
#define STACK_SIZE     32768
#endif

#undef  FIDOUNKNWN
#define FSC90
#if 0
#define PRODCODE  0xFE
#else
#define PRODCODE  0xEFF
#endif

#define DEST         1
#define SIZE         2
#define BINARY       3
#define TWITADDR     4
#define NOADDR       5
#define EXTERNAL     6
#define FILEATT      7

#define LRD_CREATE   1
#define LRD_CHECK    2

#define RET_ECHOMAIL 1
#define RET_NETMAIL  2
#define RET_ERR      4

#define KENDRA     112
#define SENDMAIL    86 /* for uupcver */

#define ZAPAS       40

#define nextline pheader[cheader+1]=pheader[cheader]+strlen(pheader[cheader])+1, cheader++;
#define chkkludge(len) if (((len)+pheader[cheader]+ZAPAS>header+MAXHEADER) || (cheader>=MAXFIELDS)) { logwrite('?',"Too many kludges, messages moved to badmail!\n"); goto lbadmsg; }
#define chkkludges chkkludge(strlen(str))

#include <libgate.h>

#ifdef _IOFBF  /* stdio.h included */
typedef struct {
  FILE *file;
  char fname[FNAME_MAX];
  void *buf;
  unsigned long curpos, bufsize, offbody, lines;
  int  waslf;
} VIRT_FILE;
int virt_fprintf(VIRT_FILE *f, char *format, ...);
int virt_fputs(char *str, VIRT_FILE *f);
int virt_putc(char c, VIRT_FILE *f);
VIRT_FILE *virt_fopen(char *fname, char *flags);
int virt_fclose(VIRT_FILE *f);
int virt_rewind(VIRT_FILE *f);
int virt_getc(VIRT_FILE *f);
int virt_fgets(char *str, size_t sizestr, VIRT_FILE *f);

int  rsend(char *to, VIRT_FILE *fout, int type);
#ifndef __MSDOS__ /* OS/2, UNIX */
int  msend(char *cmd, VIRT_FILE *fout);
#endif
#endif
int config(void);
int getfidoaddr(uword *zone, uword *net, uword *node,
                uword *point, char *str);
void genlett(int reason, char *to,
             uword zone, uword net, uword node, uword point,
             int tomaster);
void noaddr(void);
void convrcv(char *via, char *rcv);
int  rclose(void);
int  hgets(char *str, unsigned strsize, int handle);
void int2ext(char * str);
void fido2rfc(char *from, char *msgfrom,
             uword zone, uword net, uword node, uword point,
             char *domain);
void putaddr(char *str, uword zone, uword net, uword node, uword point);
void stripspc(char *str);
int  params(int argc, char * argv[]);
void retoss(void);
void badpkt(void);
void badmsg(char *reason);
int  hread(int handle, void *buffer, unsigned size);
int  hgetc(int h);
void findlet(void);
int  isfield(char *line);
int  checkaddr(char *addr);
int  extcheck(char *addr, int *area);
int  mktempname(char *sample, char *dest);
void chsubstr(char *dest, char *from, char *to);
void closepkt(void);
char *qphdr(char *str);
void parsekludge(char *str, char *klname, char *klopt);
void dateftn2rfc(char *ftndate, char *rfcdate, int tz);
int  adduserline(char *str);
int  moveatt(char *fname, unsigned long attr);
void mkusername(char *str);
int  one_message(char *msgname);
void getaddr(char *str);
char *strreason(int reason, int whatfor);
void delsentfiles(unsigned long attr, char *subj);
int  gettextline_(char *str, unsigned size);
void reset_text_(void);
void set_table(char *charset);

typedef struct
  { uword net, node;
  } nodetype;
typedef struct
  { uword zone, net, node, point;
  } ftnaddress;
typedef struct
  { uword zone, net, node, point;
    char ftndomain[32];
  } ftnaddress5d;
typedef struct
  { uword zone, net, node, point;
    char yes; /* 0 - no-route, 1 - route-to, 2 - to-ifmail */
    char domain[64];
    ftnaddress5d pktfor;
  } gatetype;
typedef struct
  { char fido[64], relcom[64];
  } cdomaintype;
typedef char addrstr[64];
typedef struct
  { char from[64], to[64];
  } aliastype;
typedef struct
  { unsigned echo;
    addrstr moderator;
  } modertype;
typedef struct
  { char mask[64], cmdline[256];
  } checktype;

extern char rmail[FNAME_MAX];
extern char compress[FNAME_MAX], rnews[FNAME_MAX];
extern char netmaildir[FNAME_MAX];
extern char pktin[FNAME_MAX], pktout[FNAME_MAX], binkout[FNAME_MAX];
extern char tboxes[FNAME_MAX];
#ifndef __MSDOS__
extern char lbso[FNAME_MAX], tlboxes[FNAME_MAX], longboxes[FNAME_MAX];
#endif
extern char tmpdir[FNAME_MAX];
extern char pktpwd[9];
extern char msgname[FNAME_MAX];
extern char local[80],remote[80], fidosystem[80];
extern char spool_dir[FNAME_MAX];
extern char charsetname[80];
extern unsigned ncaddr, npaddr, ntwit, nnotwit, nfree, nalias, nmoder, nattfrom;
extern ftnaddress *uplink;
extern unsigned nuplink;
extern uword zone, net, node, point;
extern int  tz, uucode, rcv2via, savehdr, touucp, byuux, deltransfiles;
extern int  xcomment;
extern int  uupcver;
extern char echolog, fscmsgid;
extern unsigned maxsize;
extern unsigned maxline;
extern unsigned maxcnews;
extern char rescan[FNAME_MAX], nconf[FNAME_MAX];
extern unsigned nsend, nrej, ncdomain, nchecker;
extern addrstr *send_to;
extern addrstr *rej;
extern addrstr *sfree;
extern modertype *moderator;
extern aliastype *alias;
extern checktype *checker;
extern char to[128], gw_to[128], from[128];
extern char gatemaster[128];
extern char badmail[FNAME_MAX];
extern char master[80], organization[80];
extern uword mastzone, mastnet, mastnode, mastpoint;
extern char *montable[], *weekday[];
extern struct echotype
       { char _Far *fido;
         char _Far *usenet;
         char group;
       } _Huge *echoes;
extern char _Far *echonames;
extern struct grouptype
       { char newsserv[64];
         char distrib[16];
         char domain[64];
         enum {G_FEED, G_CNEWS, G_DIR} type;
         char sb;
         char aka;
         char extmsgid;
       } *group;
extern unsigned nechoes, ngroups;
extern gatetype *gates;
extern cdomaintype *cdomain;
extern int ngates, curgate;
extern int maxrcv;
extern struct caddrtype
       { uword zone, net, node, point;
         char from[36], to[128];
       } *caddr;
extern struct addrtype
       { uword zone, net, node, point;
         char from[36];
       } *paddr, *twit, *notwit, *attfrom;
extern struct t_addr
       { uword zone, net, node, point;
         char ftndomain[32];
         char domain[64];
       } *myaka;
extern int naka, curaka;
extern char int2ext_tab[128];
extern unsigned ibuf;
extern int nonet, noecho, tossbad, fake;
extern char *buffer;
extern char str[2048];
extern struct lrd_type
       { unsigned long time;
         unsigned num;
       } lastread, new_lrd;
extern int lrd, upaka;
extern unsigned long offs_beg;
extern char packed;
extern int h;
extern char *pheader[MAXFIELDS];
extern int cheader;
extern unsigned long txtsize;
extern char tpl_name[FNAME_MAX], curtplname[FNAME_MAX];
extern int  nglobal, inconfig, tplout;
extern ftnaddress pktdest;
extern int  ourpkt, packmail, gatevia;
extern int  hidetear, hideorigin, fsp1004;
extern char *rsend_stack;
extern unsigned long rsend_tid;
extern int  area;
extern int  seqf;
extern int  hdr8bit;
extern char *header;
extern int  writereason, bangfrom, env_chaddr, fromtop;
extern struct attfiletype
       { char *name;
         unsigned long attr;
       } *killattfiles;
extern int  nkillattfiles;
extern struct ftnchrs_type {
         struct ftnchrs_type *next;
         char *ftnchrs, *rfcchrs;
       } *ftnchrs;
extern unsigned long msgsize;
extern struct packet pkthdr;
extern struct message msghdr;
extern char *myintsetname, *myextsetname;
extern char extsetname[128], intsetname[128];
extern char inb_dir[FNAME_MAX], charsetsdir[FNAME_MAX], charsetalias[FNAME_MAX];
#ifdef _IOFBF  /* stdio.h included */
void putfiles(VIRT_FILE *fout, char *subj, char *bound);
int  writemsghdr(struct message * msghdr,FILE * fout);
#endif
