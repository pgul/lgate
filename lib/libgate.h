/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:22  gul
 * We are under CVS for now
 *
 */
#if defined(__MSDOS__)
#define FNAME_MAX   81
#elif defined(__OS2__)
#define FNAME_MAX   257
#else
#define FNAME_MAX   1025
#endif

#if defined(__MSDOS__)
#define SYSTEM "MSDOS"
#define _Far far
#define _Huge huge
#define HALF "/DOS"
#define EXEEXT ".exe"
#define COMEXT ".com"
#define CMDLINELEN	128
#define GATECFG		"gate.cfg"
#ifdef O_EXCL
extern int share;
#undef O_EXCL
#define O_EXCL (share ? 0x0400 : 0)
#endif
#define METACHARS	"<>|"
#elif defined(__OS2__)
#define SYSTEM "OS/2"
#define HALF "/2"
#define _Far
#define _Huge
#define EXEEXT ".exe"
#define COMEXT ".com"
#define CMDLINELEN	4096
#define GATECFG		"gate.cfg"
#define farmalloc	malloc
#define farfree		free
#define METACHARS	"<>|&"
#else
#define SYSTEM "UNIX"
#define HALF "/Unix"
#define _Far
#define _Huge
#define EXEEXT ""
#define COMEXT ""
#define CMDLINELEN	64536
#define GATECFG		"gate.conf"
#define farmalloc	malloc
#define farfree		free
#define METACHARS	"<>|\"\'\\$*!?[]~`;()&"
#endif

#ifdef HAVE_FTRUNCATE
#define chsize(file,size)	ftruncate(file,size)
#endif

#if !defined(HAVE_SHARE_H) && !defined(HAVE_SOPEN)
#define myfopen(file,mode)	fopen(file,mode)
#elif defined(_IOFBF)
FILE * myfopen(char * fname,char * attr);
#endif

#ifndef HAVE_SETMODE
#define setmode(file,mode)
#endif

#if defined(__EMX__) || defined(UNIX)
#define mkdir(path)	mkdir(path, 0750)
#ifdef __OS2__
#define getcwd		_getcwd2
#endif
#endif

#define addslash(str)  if ((str)[0] && (str)[strlen(str)-1]!=PATHSEP) strcat(str, PATHSTR)
#define removeslash(s) if (s[strlen(s)-1]==PATHSEP && strlen(s)>1+DISKPATH) s[strlen(s)-1]='\0';
#define chorders(n) ((n>>8) | ((n<<8) & 0xff00u))
#define chorderl(n) ((n>>24) | ((n>>8) & 0xff00ul) |  ((n<<8) & 0xff0000ul) | (n<<24))

#if !defined (LOCK_SH)
#define LOCK_SH     0x01
#define LOCK_EX     0x02
#define LOCK_NB     0x04
#define LOCK_UN     0x08
#endif
#if defined(__TURBOC__)
#define flock(h, mode)	(share ? (((mode) & LOCK_UN) ? unlock(h, 0, 0x7fffffffl) : lock(h, 0, 0x7fffffffl)) : 0)
int _Cdecl lock    (int handle, long offset, long length);
int _Cdecl unlock  (int handle, long offset, long length);
#elif defined(__WATCOMC__)
#define flock(h, mode)	(((mode) & LOCK_UN) ? unlock(h, 0, 0x7fffffffl) : lock(h, 0, 0x7fffffffl))
int  lock(int __handle,unsigned long __offset,unsigned long __nbytes);
int  unlock(int __handle,unsigned long __offset,unsigned long __nbytes);
#endif

#include <fidolib.h>

typedef struct
       { char *str;
#ifndef __MSDOS__
         void *regbuf;
#endif
       } wildcard;

void setglobal(char * var,char * value);
void setvar(char * var,char * value);
int  init_tpl(char * fname);
void close_tpl(void);
void closeall(void);
extern int  (*gettextline)(char * str,unsigned size);
extern void (*reset_text)(void);
void setpath(char * fname);
int  configline(char * str,unsigned size);
int  templateline(char * str,unsigned size);
char *getvar(char * var);
int  swap_system(char * cmd);
int  pipe_system0(int * in,int * out,char * cmd,char * argv0);
#define pipe_system(in,out,cmd) pipe_system0(in,out,cmd,NULL);
int  pipe_spawnv(int * in,int * out,char * name, char * args[]);
void expand_path(char * src,char * dest);
#ifndef HAVE_PIPE
int  pipe(int filedes[2]);
#endif
int  isfile(int handle);
int  getmytz(char * str, int * tz);
void debug(int level,char * format,...);
int  saveargs(int argc, char * argv[]);
int  cmpaddr(char * addr,char * mask);
int  wildcmp(char * addr,wildcard * mask);
int  chkregexp(char * str, char * regexp
#ifndef __MSDOS__
               , void **regbuf
#endif
              );
void easet(char *path, const char *name, const char *value);
char *get_ea(char *path, char *name);
int  read_msghdr(int h, struct message * msghdr);
int  write_msghdr(int h, struct message * msghdr);
void msghdr_byteorder(struct message *msg);
void pkthdr_byteorder(struct packet *pkt);
void logwrite(char level,char * format,...);
char *strsysexit(int retcode);
char *strsignal(int signo);
char *chsalias(char *charset);
void addtable(char *charsetname, short int *table);
short int *findtable(char *charset, char *charsetsdir);
void setcharset(char *charsetname, char *fname);
void addmytable(char *charsetname, short int *table, char *charsetsdir);
void addchsalias(char *from, char *to);
char *canoncharset(char *charset);
#ifdef __MSDOS__
long getfreemem(void);
char *createbuf(long size);
void freebuf(char *buf);
char getbuflem(char *buf, long index);
void bufcopy(char *buf, long offs, char *from, int size);
void frombuf(char *dest, char *buf, long offs, int size);
char *bufrealloc(char *buf, long size);
long bufwrite(int h, char *buf, long size);
#ifdef _IOFBF  /* stdio.h included */
int  writebuf(char *buf, long len, FILE *file);
#endif
#else
#define createbuf(l)			malloc(l)
#define freebuf(buf)			free(buf)
#define getbuflem(buf, index)		((char *)(buf))[index]
#define bufcopy(buf, offs, from, size)	memcpy((char *)(buf)+(offs), from, size)
#define frombuf(dest, buf, offs, size)	memcpy(dest, (char *)(buf)+(offs), size)
#define bufrealloc(buf, size)		realloc(buf, size)
#define writebuf(buf, len, file)	((fwrite(buf, len, 1, file) == 1) ? 0 : -1)
#define bufwrite(h, buf, size)          write(h, buf, size)
#endif
#ifdef __WATCOMC__
#define WNOHANG         1
typedef int pid_t;
int kill(pid_t pid, int sig);
int waitpid(pid_t pid, int *status, int options);
#endif
#ifndef HAVE_FILELENGTH
unsigned long filelength(int h);
#endif
#ifndef HAVE_BASENAME
char *basename(char *fname);
#endif
#ifndef HAVE_MKTIME
#include <time.h>
time_t mktime(struct tm * ft);
#endif
#ifndef HAVE_STRUPR
char *strupr(char *str);
char *strlwr(char *str);
#endif
#if defined(HAVE_STRCASECMP) && !defined(HAVE_STRICMP)
#define stricmp(s1, s2)  strcasecmp(s1, s2)
#endif
#if defined(HAVE_STRNCASECMP) && !defined(HAVE_STRNICMP)
#define strnicmp(s1, s2, n)  strncasecmp(s1, s2, n)
#endif
#if !defined(HAVE_STRICMP) && !defined(HAVE_STRCASECMP)
int stricmp(char *s1, char *s2);
#endif
#if !defined(HAVE_STRNICMP) && !defined(HAVE_STRNCASECMP)
int strnicmp(char *s1, char *s2, int n);
#endif
#ifndef HAVE_HTONS
unsigned short htons(unsigned short n);
unsigned short ntohs(unsigned short n);
unsigned long  htonl(unsigned long  n);
unsigned long  ntohl(unsigned long  n);
#endif

extern char *myname;
extern int  use_swap;
extern int  debuglevel, debuglog;
typedef enum {FD_LOG, FE_LOG, SYSLOG_LOG} logtype;
extern logtype logstyle;
extern char logname[];
extern char copyright[];
extern char loglevel[];
extern int  quiet;

#if !defined(HAVE_ENVIRON) && defined(HAVE___ENVIRON)
#define environ __environ
#define HAVE_ENVIRON
#endif

#if !defined(HAVE_FLOCK) && defined(HAVE_LOCKF) && defined(F_LOCK)
#ifndef LOCK_EX
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_UN 8
#define LOCK_NB 4
#endif
#define flock(h,m)	lockf(h,((m)==LOCK_UN)?F_ULOCK:(((m)&LOCK_NB)?F_TLOCK:F_LOCK),0x7fff)
#define HAVE_FLOCK 1
#endif
