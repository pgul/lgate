/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:51:01  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:24  gul
 * We are under CVS for now
 *
 */
#ifndef _UTIME_H
#define _UTIME_H

#ifndef  _TIME_T
#define  _TIME_T
typedef long time_t;
#endif

/* Structure passed to utime containing file times
 */
struct utimbuf
{
        time_t  actime;         /* access time (not used on DOS) */
        time_t  modtime;        /* modification time */
};

int utime(char * path, struct utimbuf * times);

#endif
