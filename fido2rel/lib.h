/*--------------------------------------------------------------------*/
/*      l i b . h                                                     */
/*                                                                    */
/*      Update log:                                                   */
/*                                                                    */
/*      13 May 89    Added PCMAILVER                        ahd       */
/*      Summer 89    Added equali, equalni, compiled,                 */
/*                         compilet                         ahd       */
/*      22 Sep 89    Add boolean typedef                    ahd       */
/*      01 Oct 89    Make logecho boolean                   ahd       */
/*      19 Mar 90    Move FOPEN prototype to here           ahd       */
/*      02 May 1990  Allow set of booleans options via options=       */
/*  8 May  90  Add 'pager' option                                     */
/* 10 May  90  Add 'purge' option                                     */
/*--------------------------------------------------------------------*/

#ifndef __LIB
#define __LIB

/*--------------------------------------------------------------------*/
/*                 Macro for recording when UUPC dies                 */
/*--------------------------------------------------------------------*/

#define panic()  bugout( __LINE__, cfnptr);

#define DCSTATUS    "hostatus"
#define LOGFILE     "uucico.log"
#define PASSWD      "passwd"
#define PATHS       "hostpath"
#define PERMISSIONS "permissn"
#define RMAILLOG    "rmail.log"
#define SYSLOG      "syslog"
#define SYSTEMS     "systems"
#define DIALERS		"dialers"

#define WHITESPACE " \t\n\r"

/*--------------------------------------------------------------------*/
/*    Equality macros                                                 */
/*--------------------------------------------------------------------*/

#define equal(a,b)               (!strcmp(a,b))
#define equali(a,b)              (!stricmp(a,b))                     /*ahd */
#define equalni(a,b,n)           (!strnicmp(a,b,n))                  /*ahd */
#define equaln(a,b,n)            (!strncmp(a,b,n))

#define currentfile()            static char *cfnptr = __FILE__
#define checkref(a)              (checkptr(a, cfnptr ,__LINE__));    /*ahd */

#define nil(type)               ((type *)NULL)

/*--------------------------------------------------------------------*/
/*                  Your basic Boolean logic values                   */
/*--------------------------------------------------------------------*/

#undef FALSE
#undef TRUE
typedef enum { FALSE = 0, TRUE = 1 } boolean;

typedef unsigned short INTEGER;  /* Integers in the config file      */

/*--------------------------------------------------------------------*/
/*                          Global variables                          */
/*--------------------------------------------------------------------*/

extern int debuglevel;
extern boolean logecho;
extern FILE *logfile;

/*--------------------------------------------------------------------*/
/*      Configuration file strings                                    */
/*--------------------------------------------------------------------*/

extern char *name, *mailbox, *homedir;
extern char *maildir, *newsdir, *spooldir, *confdir, *pubdir, *tempdir;
extern char *localdomain;                                      /* ahd   */
extern char *E_indevice, *E_inspeed, *E_inmodem;
/*** Changed by Pavel Gulchouck - confuse with my local variables
extern char *domain, *fdomain, *mailserv;
*/
extern char nodename[];
extern char *postmaster, *anonymous;                            /* ahd   */
extern INTEGER maxhops;
extern INTEGER PacketTimeout;
extern INTEGER MaxErr;
extern INTEGER xfer_bufsize;


/*--------------------------------------------------------------------*/
/*                        Function prototypes                         */
/*--------------------------------------------------------------------*/

void printerr(const char *func, const char *prefix);

extern void checkptr(void *block, char *file, int line);

extern int MKDIR(char *path);
							  /* Make a directory              ahd */

extern int CHDIR(char *path);
							  /* Change to a directory          ahd */

extern int CREAT(char *name,
				 const int mode,
				 const char ftype);                          /* ahd */

extern FILE *FOPEN(char *name,
				   const char *mode,
				   const char ftype);                       /* ahd   */

extern int RENAME(char *oldname, char *newname);

int getargs(char *line,
			char **flds);                                   /* ahd */

void printmsg(int level, char *fmt, ...);

int configure(void);

void bugout( const long lineno, const char *fname);

int real_flush(int);

/*--------------------------------------------------------------------*/
/*                   Compiler specific information                    */
/*--------------------------------------------------------------------*/

/* Ache added */
void dbgputc(const char c);
void dbgputs(char *str);
void show_char(const unsigned char byte);

struct	Table {
	char*	sym;
	char**	loc;
	char	must;
	char	sys;
	char	std;
	char	*suff;
};

void getconfig(FILE* fp, int sysmode, struct Table *table);

#endif


/* arbmath.h */
void mult(unsigned char *number,
      const unsigned range,
      const unsigned digits);

void add(unsigned char *number,
      const unsigned range,
      const unsigned digits);

boolean adiv( unsigned char *number,
             const unsigned divisor,
                   unsigned *remain,
             const unsigned digits);

#define MAX_DIGITS 20         /* Number of digits for arb math */
