/*
 * $Id$
 *
 * $Log$
 * Revision 2.6  2001/07/26 12:48:55  gul
 * 7bit- and 8bit-encoded attaches bugfix
 *
 * Revision 2.5  2001/07/20 21:43:26  gul
 * Decode attaches with 8bit encoding
 *
 * Revision 2.4  2001/07/20 21:22:52  gul
 * multipart/mixed decode cleanup
 *
 * Revision 2.3  2001/07/20 14:55:22  gul
 * Decode quoted-printable attaches
 *
 * Revision 2.2  2001/01/26 14:33:38  gul
 * Version changed to 7.02 in *.h
 *
 * Revision 2.1  2001/01/25 18:41:38  gul
 * myname moved to debug.c
 *
 * Revision 2.0  2001/01/10 20:42:16  gul
 * We are under CVS for now
 *
 */
#define VER		"7.02"
#define FORMATVER	"1.0"
#define NAZVA		"LuckyGate" HALF " " VER
#define COPYRIGHT	NAZVA "   " __DATE__
#define MAXSEND		64

#define BUFSIZE		8192
#define MAXPASSWD	33

#define TMPUUE		"temp????.uue"
#define TMPSENT		"att?????.snt"
#define TMPARCNAME	"att?????.arc"
#define SENTBAD		"fail????.snt"
#define BSYNAME		"attuucp.now"

#define RET_SENT	1
#define RET_RCV		2
#define RET_FWD		4
#define RET_WARN	8
#define RET_ERR		16

#define KENDRA		112
#define SENDMAIL	86

#include <libgate.h>

typedef enum { ENC_UUCP, ENC_UUE, ENC_BASE64, ENC_QP, ENC_8BIT, ENC_7BIT, ENC_PGP } enctype;
typedef enum {NO_SEM, FD_SEM, BINK_SEM, LBSO_SEM} semtype;
typedef enum {RESEND, SECURE, UNSECURE} pwdtype;

int  config(void);
int  uucp(char *filename, char *host);
void uudecode(char *filename);
void flushsend(void);
int  params(int argc, char *argv[]);
int  mktempname(char *sample, char *dest);
void checktmp(void);
void mkarcname(char *src, char *arcname, pwdtype passwd);
void topostmast(char *tmp_uue);
int  checkpgpsig(char *fname, char *pgpsig, char *from);
char *getsign(char *fname);
void chsubstr(char *str, char *from, char *to);
void movebad(char *fname, long attrib);
void makename(char *src, char *destname, char *destdir);
int  isfile(int handle);
void getvalue(char *field, char *value, unsigned valsize);
void getparam(char *field, char *param, char *value, unsigned valsize);
int  do_uudecode(char *infile, char *outfile);
int  do_unbase64(char *infile, char *outfile, int decodepart);
int  do_unqp(char *infile, char *outfile, int decodepart);
int  do_un8bit(char *infile, char *outfile, int decodepart);
int  do_un7bit(char *infile, char *outfile, int decodepart);
int  str_unbase64(char *in, char *out);
void str_base64(char *in, char *out, int len);
#ifdef _IOFBF  /* stdio.h included */
int  do_uuencode(char *infile, FILE *fout);
int  do_base64(char *infile, FILE *out);
#endif
typedef enum { ACK_OK, ACK_FAIL } acktype;
void sendack(char *addr, char *msgid, acktype result, char *reason);
void resend(void);
void easet(char *path, const char *name, const char *value);
char *get_ea(char *path, char *name);
int  hgets(char *str, unsigned strsize, int h, char eol);

extern char rmail[FNAME_MAX], netdir[FNAME_MAX];
extern char domain[64];
extern char local[80], remote[80], fidosystem[80];
extern char uupcdir[FNAME_MAX];
extern char filebox[FNAME_MAX];
extern char user[80];
extern char rescan[FNAME_MAX];
extern char newechoflag[FNAME_MAX];
extern int  newecho;
extern char postmaster[80];
extern char pktout[FNAME_MAX];
extern char tmpdir[FNAME_MAX];
extern char incomplete[FNAME_MAX], sentdir[FNAME_MAX];
extern char nconf[FNAME_MAX];
extern char binkout[FNAME_MAX];
extern char tboxes[FNAME_MAX];
#ifndef __MSDOS__
extern char lbso[FNAME_MAX], tlboxes[FNAME_MAX], longboxes[FNAME_MAX];
#endif
extern char unsecure[FNAME_MAX];
extern char badmail[FNAME_MAX];
extern char semdir[FNAME_MAX];
extern char sstr[2048], addrlist[1024];
extern char uuencode_fmt[FNAME_MAX], uudecode_fmt[FNAME_MAX];
extern char pgpenc_fmt[FNAME_MAX], pgpdec_fmt[FNAME_MAX];
extern char pgpcheck_fmt[FNAME_MAX], pgpsign_fmt[FNAME_MAX];
extern char *pgpsig;
extern char confirm[80], msgid[256];
extern char boundary[1024];
extern char precedence[80];
extern int f;
extern int nosend, norcv, bypipe, fake, nocrc;
extern unsigned maxuue;
extern char flo_only;
extern int uupcver;
extern struct hostype
  { ftnaddr addr;
#ifndef __MSDOS__
    char domain[32];
#endif
    char host[80];
    enctype enc;
    char dir[FNAME_MAX];
    char passwd[MAXPASSWD];
    char pgpsig;
    unsigned long confirm, confirm_fail; /* in secs */
    unsigned size;
  } *hosts;
extern struct sendtype
  { char filename[FNAME_MAX];
    unsigned host;
    long attr;
    semtype sem;
  } *tosend;
extern unsigned nsend;
extern ftnaddr my;
extern int  nhosts;
extern int  tz;
extern int  use_swap;
extern int  nglobal, inconfig, tplout;
extern char str[2048];
extern char from[128];
extern int  retcode;
extern int  debuglevel, debuglog;
extern int  curhost;
extern unsigned long fcrc32;
extern char *buffer;
extern unsigned bufsize;
extern unsigned ibuf;
