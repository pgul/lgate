/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#include <stdlib.h>
#include <string.h>
#include <alloc.h>
#include <dos.h>
#include <time.h>
#include "dirent.h"

#ifndef FNAME_MAX
#define FNAME_MAX 128
#endif

/*
#define debug	(void)
#pragma warn -eff
*/

static time_t dos2unix( const struct ftime * ft )
{
   struct date sdate;
   struct time stime;

   stime.ti_hund = 0;
   stime.ti_sec  = ft->ft_tsec * 2;
   stime.ti_min  = ft->ft_min;
   stime.ti_hour = ft->ft_hour;
   sdate.da_day  = ft->ft_day;
   sdate.da_mon  = ft->ft_month;
   sdate.da_year = ft->ft_year + 1980;

   return dostounix(&sdate, &stime);
} /* dos2unix */

DIR *opendir(const char *dirname)
{
   char pathname[FNAME_MAX];
   union REGS inregs, outregs;
   struct SREGS segregs;
   DTA *dtasave;
   DTA *dtaptr;
   char *pathptr;
   DIR *thisDirP = NULL;

/*--------------------------------------------------------------------*/
/*                    Build pathname to be scanned                    */
/*--------------------------------------------------------------------*/

   /* allocate control block */
   thisDirP = malloc(sizeof(DIR));
   strcpy(pathname, dirname);
   if (pathname[strlen(pathname)-1]!='\\')
     strcat(pathname, "\\");
   strcat(pathname, "*.*");

/*--------------------------------------------------------------------*/
/*                     Set disk transfer address                      */
/*--------------------------------------------------------------------*/

   dtasave = (DTA *)getdta();
   dtaptr = (DTA *)&(thisDirP->dirdta);
   setdta((char *)dtaptr);

/*--------------------------------------------------------------------*/
/*                      look for the first file                       */
/*--------------------------------------------------------------------*/

   inregs.h.ah = 0x4e;
   pathptr = (char *)pathname;
   segregs.ds = FP_SEG(pathptr);
   inregs.x.dx = FP_OFF(pathptr);
   inregs.x.cx = 0;   /* attribute */
   intdosx(&inregs, &outregs, &segregs);

   /* bad directory name? */
   if (outregs.x.cflag && outregs.x.ax != 2 && outregs.x.ax != 18) {
      free(thisDirP);
      errno = outregs.x.ax;
      return NULL;
   }

   thisDirP->dirfirst = outregs.x.cflag ? outregs.x.ax : 0;
   if (thisDirP->dirfirst == 2) thisDirP->dirfirst = 18;

   setdta((char far *)dtasave);
   strcpy(thisDirP->dirid, "DIR");

   return thisDirP;

} /*opendir*/

/*--------------------------------------------------------------------*/
/*    r e a d d i r                                                   */
/*                                                                    */
/*    Get next entry in a directory                                   */
/*--------------------------------------------------------------------*/

struct dirent *readdir(DIR *dirp)
{
   int errcode;

/*--------------------------------------------------------------------*/
/*    Debugging code for failures when running on Novell networks     */
/*--------------------------------------------------------------------*/

   if ( dirp == NULL )
      return NULL;

   if (strcmp(dirp->dirid, "DIR"))
      return NULL;

   if (dirp->dirfirst == -1) {
      union REGS inregs, outregs;
      struct SREGS segregs;
      DTA far *dtaptr;
      DTA far *dtasave;

     /* set DTA address to our buffer each time we're called */
      dtasave = (DTA far *)getdta();
      dtaptr = (DTA far *)&(dirp->dirdta);
      setdta((char far *)dtaptr);

      inregs.h.ah = 0x4f;
      segregs.ds = FP_SEG(dtaptr);
      inregs.x.dx = FP_OFF(dtaptr);
      intdosx(&inregs, &outregs, &segregs);
      errcode = outregs.x.cflag ? outregs.x.ax : 0;

      setdta((char far *)dtasave);  /* Restore DTA address     */

   } else {

      errcode = dirp->dirfirst;
      dirp->dirfirst = -1;

   };

   /* no more files in directory? */
   if (errcode == 18)
      return NULL;

   if ( errcode != 0)
   {
      errno = errcode;
      return NULL;
   }

   strcpy(dirp->dirent.d_name, dirp->dirdta.filename);
   strlwr(dirp->dirent.d_name );
   dirp->dirent.d_namlen = (short) strlen(dirp->dirent.d_name);
   dirp->dirent.d_reclen = (short) (sizeof(struct dirent) - (MAXNAMLEN + 1) +
      ((((dirp->dirent.d_namlen + 1) + 3) / 4) * 4));
   dirp->dirent.d_mtime  = dos2unix( & (dirp->dirdta.filetime) );
   dirp->dirent.d_size   = dirp->dirdta.filesize;

   return &(dirp->dirent);

} /*readdir*/

/*--------------------------------------------------------------------*/
/*    c l o s e d i r                                                 */
/*                                                                    */
/*    Close a directory                                               */
/*--------------------------------------------------------------------*/

void closedir(DIR *dirp)
{

   strcpy(dirp->dirid, "CLO");
   free(dirp);

} /*closedir*/
