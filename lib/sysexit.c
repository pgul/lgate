/*
 * $Id$
 *
 * $Log$
 * Revision 2.2  2002/09/11 14:07:51  gul
 * fix compiler warning
 *
 * Revision 2.1  2002/03/21 11:30:52  gul
 * Added strsignal() check
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "libgate.h"

#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#else
#define EX_OK           0       /* successful termination */

#define EX__BASE        64      /* base value for error messages */

#define EX_USAGE        64      /* command line usage error */
#define EX_DATAERR      65      /* data format error */
#define EX_NOINPUT      66      /* cannot open input */
#define EX_NOUSER       67      /* addressee unknown */
#define EX_NOHOST       68      /* host name unknown */
#define EX_UNAVAILABLE  69      /* service unavailable */
#define EX_SOFTWARE     70      /* internal software error */
#define EX_OSERR        71      /* system error (e.g., can't fork) */
#define EX_OSFILE       72      /* critical OS file missing */
#define EX_CANTCREAT    73      /* can't create (user) output file */
#define EX_IOERR        74      /* input/output error */
#define EX_TEMPFAIL     75      /* temp failure; user is invited to retry */
#define EX_PROTOCOL     76      /* remote error in protocol */
#define EX_NOPERM       77      /* permission denied */
#define EX_CONFIG       78      /* configuration error */

#define EX__MAX         78
#endif

static char *sendmailerr[] = {
"command line usage error",
"data format error",
"cannot open input",
"addressee unknown",
"host name unknown",
"service unavailable",
"internal software error",
"system error",
"critical OS file missing",
"can't create (user) output file",
"input/output error",
"temp failure; user is invited to retry",
"remote error in protocol",
"permission denied",
"configuration error"
};

#if !defined(HAVE_SYS_SIGNAME) && !defined(HAVE_STRSIGNAL)
#define sys_signame _flib_sys_signame /* avoid exists but undeclared */
static char *sys_signame[] = {
"0",
"HUP",
"INT",
"QUIT",
"ILL",
"TRAP",
"ABRT",
"IOT",
"BUS",
"FPE",
"KILL",
"USR1",
"SEGV",
"USR2",
"PIPE",
"ALRM",
"TERM",
"STKFLT",
"CLD",
"CONT",
"STOP",
"TSTP",
"TTIN",
"TTOU",
"URG",
"XCPU",
"XFSZ",
"VTALRM",
"PROF",
"WINCH",
"IO",
"PWR",
"UNUSED"
};
#endif

char *strsysexit(int retcode)
{
  static char unknownerr[128];

  if (retcode>=EX__BASE &&
      retcode<=EX__MAX)
    return sendmailerr[retcode-EX__BASE];
  sprintf(unknownerr, "retcode %u", retcode);
  return unknownerr;
}

#ifndef HAVE_STRSIGNAL
char *strsignal(int signo)
{
  static char sigstr[20];

  if (signo>=0 && signo<sizeof(sys_signame)/sizeof(sys_signame[0]))
  { strcpy(sigstr, "SIG");
    strcpy(sigstr+3, sys_signame[signo]);
    strupr(sigstr);
  }
  else
    sprintf(sigstr, "%u", signo);
  return sigstr;
}
#endif
