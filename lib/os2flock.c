/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:50:59  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#include <fcntl.h>
#include <errno.h>
#define INCL_DOSFILEMGR
#include <os2.h>

int flock(int handle, int mode)
{
	FILELOCK slock, sunlock;
	APIRET r;

	slock.lOffset = sunlock.lOffset = 0;
	if (mode & LOCK_UN) {
		sunlock.lRange = 0x7fffffff;
		slock.lRange = 0;
	} else {
		slock.lRange = 0x7fffffff;
		sunlock.lRange = 0;
	}
	r = DosSetFileLocks(handle, &sunlock, &slock, 
	             (mode & LOCK_NB) ? 0 : 10000, (mode & LOCK_SH) ? 1 : 0);
	if (r) errno = EWOULDBLOCK;
	return r ? -1 : 0;
}
