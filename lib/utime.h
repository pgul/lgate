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
