/*--------------------------------------------------------------------*/
/*    i m p o r t . c                                                 */
/*                                                                    */
/*    File name mapping routines for UUPC/extended                    */
/*--------------------------------------------------------------------*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <process.h>

#ifndef FILENAME_MAX
#if defined (MAXPATH)
#define FILENAME_MAX   (MAXPATH+1)
#elif defined (PATH_MAX)
#define FILENAME_MAX   (PATH_MAX+1)
#else
#define FILENAME_MAX   128
#endif
#endif

#include "lib.h"
#include "import.h"

#define nodename local
extern char local[];

currentfile();

#define MAX_DIGITS 20       /* Number of digits for arb math */

/*--------------------------------------------------------------------*/
/*                    Variables global to package                     */
/*--------------------------------------------------------------------*/

/*** Changed by Pavel Gulchouck for uupc 6.x compatibility
 *** If uupc ver 6.x there are reinitialization at config()
static char charset[] = DOSCHARS;
*/char charset[80] = DOSCHARS5;
int validlen = VALIDLEN_ACHE;

/*--------------------------------------------------------------------*/
/*                    Internal function prototypes                    */
/*--------------------------------------------------------------------*/


#define min(x,y) (((x) < (y)) ? (x) : (y))

/*-------------------------------------------------------------------*/
/*                                                                   */
/*   i m p o r t p a t h                                             */
/*                                                                   */
/*   Convert a canonical name to a format the host can handle        */
/*                                                                   */
/*   These routines convert file name between canonical form, which  */
/*   is defined as a 'unix' style pathname, and the MS-DOS all       */
/*   uppercase "xxxxxxxx.xxx" format.                                */
/*                                                                   */
/*   If the canonical name does not have a path, that is the file is */
/*   destined for the local spool directory, we can assume the UNIX  */
/*   name will normally be in a format like this:                    */
/*                                                                   */
/*                                                                   */
/*       X.hostid#######            (Execute files)                  */
/*       C.hostid#######            (Call files)                     */
/*       D.hostid#######            (Data files)                     */
/*                                                                   */
/*   where "hostid" may be most, but not always all, of the local    */
/*   host or remote host (the file came from or is going to) and     */
/*   "######" can be any character valid for the UNIX file system.   */
/*   Note, however, that the routine has to be generic to allow for  */
/*   other file names to be placed in the spool directory without    */
/*   collisions.                                                     */
/*                                                                   */
/*   Avoiding collisions in the spool directory is important; when   */
/*   receiving files with mixed case names longer than 11            */
/*   characters, sooner or later a file name collision will occur.   */
/*                                                                   */
/*   We can also assume that only UUPC will see these names, which   */
/*   means we can transform the name using any method we choose, so  */
/*   long as the UUPC functions opening the file always call         */
/*   importpath, and that importpath is reducible (that is, two      */
/*   calls to importpath with the same argument always yield the     */
/*   same result).  Note that if end user really wanted the file in  */
/*   the spool directory, all he has to do is rename the file-- far  */
/*   better than losing the data because duplicate file names.       */
/*                                                                   */
/*   For these files, we map the name as follows:                    */
/*                                                                   */
/*   0 - If the name is a valid MS-DOS name, use it without changing */
/*                                                                   */
/*   1 - Begin the output name by inserting up to the first eight    */
/*       characters of the remote host name (followed by a slash) as */
/*       a subdirectory name.                                        */
/*                                                                   */
/*   2 - If the input name begins with an uppercase alphabetic       */
/*       character followed by a period, also insert the alphabetic  */
/*       (followed by a slash) to make this a second subdirectory.   */
/*       Then, move the logical start of the input name past the two */
/*       characters.                                                 */
/*                                                                   */
/*   3 - Determine the number of characters the local host and       */
/*       remote hosts have equal to the next characters of the input */
/*       name, up to a maximum of 8, and zero the lower of the two   */
/*       counts.  Then, step past the number of characters of the    */
/*       larger count.                                               */
/*                                                                   */
/*       For example, if the file name is X.keane22222 and the local */
/*       host name is kendra (2 characters match) and the remote     */
/*       host is keane1 (5 characters match), zero the number of     */
/*       characters matched by kendra, and make the new start of the */
/*       file name five characters further (at the first "2").       */
/*                                                                   */
/*   4 - Convert the remaining string using a base conversion, with  */
/*       the input character size being from ascii "#" to ascii "z"  */
/*       (88 characters) to the allowed set of characters in MS-DOS  */
/*       file names (charset, below, 52 characters).                 */
/*                                                                   */
/*   5 - Prepend to the string to be converted the length of the     */
/*       remote host added to the length of the local host           */
/*       multiplied by 8 (both lengths were computed in step 3,      */
/*       above).  The base conversion is also applied to this        */
/*       "character", we which know will be in the range 1-64.       */
/*                                                                   */
/*   6 - If the string created by steps 4 and 5 exceeds 8            */
/*       characters, insert a period after the eighth character to   */
/*       make it a valid MS-DOS file name.  If the string created by */
/*       steps 4 and 5 exceeds 11 characters, truncate the string by */
/*       using the first eight and last three characters.            */
/*                                                                   */
/*   7 - Append the string created in steps 4 through 6 to the path  */
/*       name created in steps 1 and 2.                              */
/*                                                                   */
/*   If the canonical name has a path, it is destined for an end     */
/*   user, so we should not radically transform it like we do for    */
/*   files in the spool directory.  Thus, if the canonical name has  */
/*   a path, mung the canonical file name as follows:                */
/*                                                                   */
/*   1 - skip any path from the canonical name                       */
/*                                                                   */
/*   2 - copy up to 8 character from the canonical name converting . */
/*       to _ and uppercase to lowercase.                            */
/*                                                                   */
/*   3 - if the name was longer than 8 character copy a . to the     */
/*       host name and then copy the up to three characters from     */
/*       the tail of the canonical name to the host name.            */
/*                                                                   */
/*   Note that this set of rules will cause a collision with names   */
/*   that only differ in case, but leaves the name in a recongizable */
/*   format for the user.                                            */
/*-------------------------------------------------------------------*/


void importpath(char *host, char const *canon, char const *remote)
{
   char *s, *out, c;
   size_t charsetsize = strlen(charset); /* gul */

   out = host;

   if( host == NULL || canon == NULL || remote == NULL )
	panic();

   if ((s = strrchr(canon, '\\')) == (char *)NULL)
   {                          /* File for spooling directory, use
								 internal character set to avoid
								 collisons                           */
	  static size_t range =  UNIX_END_C - UNIX_START_C + 1;
							  /* Determine unique number characters in
								 the UNIX file names we are mapping  */
/*** Changed by Pavel Gulchouck for uupc 6.x compatibility
	  static size_t charsetsize = sizeof charset - 1;
*/

							  /* Number of allowed characters in
								 MS-DOS file names                   */

	  size_t remlen = min(validlen, strlen(remote));
							  /* Length of the remote name passed
								 in, shortened below to number of
								 characters matched in name          */
	  size_t nodelen = min(validlen, strlen(nodename));
							  /* Length of the local host name,
								 shortened below to number of
								 characters matched in name          */
	  unsigned subscript = 0;   /* Value of UNIX character to be
								 converted to MS-DOS character set   */
	  char *next        = host + remlen;
	  char tempname[FILENAME_MAX];
	  unsigned char number[MAX_DIGITS];
							  /* Arbitary length number, for base
								 conversions                        */

/*--------------------------------------------------------------------*/
/*    Put the host name (up to six characters) at the beginning of    */
/*    the MS-DOS file name as a sub-directory name.                   */
/*--------------------------------------------------------------------*/

      strncpy(host, remote, remlen);
	  *next++ = '\\';         /* Add in the sub-directory seperator  */
	  s = (char *) canon;     /* Get the beginnging of the UNIX name */

/*--------------------------------------------------------------------*/
/*             If valid DOS name, use without translation             */
/*--------------------------------------------------------------------*/

      if (ValidDOSName( canon ))
      {
         strcpy( next, canon );
		 goto ret;
	  }

/*--------------------------------------------------------------------*/
/*    Files in the spooling directory generally start with "D.",      */
/*    "C.", or "X."; strip off any upper case letter followed by a    */
/*    period into its own directory.                                  */
/*--------------------------------------------------------------------*/

	  if ((s[0] >= 'A') && (s[0] <= 'Z') && (s[1] == '.'))
	  {
		 *next++ = *s;        /* Copy the input character            */
		 *next++ = '\\';      /* Add the sub-directory indicator too */
         s += 2;              /* Step input string past the copied
                                 data                                */
      }

	  while( remlen > 0 )
      {
         if (equaln(remote,s,remlen))
			break;
         remlen--;
	  }

      while( nodelen > 0 )
      {
         if (equaln(nodename,s,nodelen))
            break;
         nodelen--;
      }

	  if (nodelen > remlen )
      {
         remlen = 0;
         s += nodelen;
      }
      else
      {
         nodelen = 0;
		 s += remlen;
      }

	  *next  = '\0';          /* Terminate first part of host string */

/*--------------------------------------------------------------------*/
/*       Create a binary number which represents our file name        */
/*--------------------------------------------------------------------*/

	  for (subscript = 0; subscript < MAX_DIGITS; subscript++ )
		 number[subscript] = 0;  /* Initialize number to zero        */

	  add(number, nodelen + remlen * validlen, MAX_DIGITS);
								 /* Append host name info to the
									front of the converted string    */

	  while( (*s != '\0') && (*number == '\0'))
	  {
		 mult(number, range, MAX_DIGITS); /* Shift the number over   */
		 add(number, *s++  - UNIX_START_C , MAX_DIGITS);
										  /* Add in new low order    */
	  } /* while */

/*-------------------------------------------------------------------*/
/*   We now have stripped off the leading x. and host name, if any;  */
/*   now, convert the remaining characters in the name by doing a    */
/*   range to charset base conversion.                               */
/*-------------------------------------------------------------------*/

      out = &tempname[FILENAME_MAX];
	  *--out = '\0';          /* Terminate the string we will build  */

/*--------------------------------------------------------------------*/
/*         Here's the loop to actually do the base conversion         */
/*--------------------------------------------------------------------*/

      while(adiv( number, charsetsize, &subscript, MAX_DIGITS))
            *--out = charset[ subscript ];

/*--------------------------------------------------------------------*/
/*    The conversion is done; now squeeze it into an 11 character     */
/*    MS-DOS name with period.                                        */
/*--------------------------------------------------------------------*/

      if (strlen(out) < 9)    /* Need extension inserted?            */
         strcpy( next, out ); /* Length is ok, just copy it          */
      else if (strlen(out) < 12)
                              /* Need to truncate the final name?    */
		 sprintf( next , "%.8s.%s",out,&out[8]);   /* No --> format  */
	  else
	  {                       /* Yes --> Do so                       */
/*
		 printmsg(1,"importpath: Truncated name \"%s\"",out);
*/
		 sprintf( next,"%.8s.%s",out, &tempname[ FILENAME_MAX - 4 ] );
	  }
   }
   else {         /* Not file for spooling directory, convert it  */

	  char *best_period;      /* ptr to last period in canonical fname */
      char *in;
      size_t column;

      s++;                    /* Step past slash in the name (/)     */

/*--------------------------------------------------------------------*/
/*                 If a valid DOS name, use it as-is                  */
/*--------------------------------------------------------------------*/

      if (ValidDOSName( s ))
	  {
         strcpy( host, canon );
		 goto ret;
      }

/*--------------------------------------------------------------------*/
/*                        Copy the input path                         */
/*--------------------------------------------------------------------*/

      out = host;
      in = (char *) canon;
      while ( in < s)
         *out++ = *in++;

/*--------------------------------------------------------------------*/
/*    If the dataset name has a period, use it.  The rule we          */
/*    follow is use the last period in the second through ninth       */
/*    characters, otherwise use the last period in the dataset        */
/*    name with the exception of leading period.                      */
/*                                                                    */
/*    In any case, we only copy up to eight characters for the        */
/*    dataset name and up to three characters for the extension.      */
/*--------------------------------------------------------------------*/

	  best_period = NULL;     /* Assume no prince charming           */
      for ( column = 1; (s[column] != '\0') && (column < 9); column++)
         if ( s[column] == '.')
			best_period = &s[column];

      if ( best_period == NULL )
         best_period = strrchr(s+1 , '.');

      if ( best_period == NULL )
         best_period = &s[ strlen( s ) ];

      column = 0;

	  while ( 1 )
	  {
		 c = s[column++];
		 if ( (strchr( charset, c ) != NULL ) || (s == best_period))
			*out++ = c;
         else
            *out++ = '_';

         if (  s[column] == '\0' )
			break;

         if ((&s[column] == best_period) ||
             (( best_period > s ) && (column > 7)))
         {
/*
            if ((&s[column] != best_period))
               printmsg(1,"importpath: Truncated name \"%s\" to 8 \
characters",
                        s);
*/
            s = best_period;
            column = 0;
		 }
		 else if (( best_period == s ) && (column > 3))
         {
/*
		   printmsg(1,"importpath: Truncated extension \"%s\" to 3 \
characters",
                        s);
*/
            break;
		 }
	  } /* while */
	  *out++ = '\0';

   } /*else */

ret:
	strlwr(host);
} /*importpath*/


/*--------------------------------------------------------------------*/
/*    V a l i d D O S N a m e                                         */
/*                                                                    */
/*    Validate an MS-DOS file name                                    */
/*--------------------------------------------------------------------*/

boolean ValidDOSName( const char *s)
{
   char *ptr;
   size_t len = strlen ( s );
   char tempname[FILENAME_MAX];

   strcpy( tempname, s);

/*--------------------------------------------------------------------*/
/*                 Name must be 12 characters or less                 */
/*--------------------------------------------------------------------*/

   if (len > 12)
	  return FALSE;

/*--------------------------------------------------------------------*/
/*    Simple file name without extension must be eight chracters      */
/*    or less                                                         */
/*--------------------------------------------------------------------*/

   ptr = strrchr(tempname, '.');
   if ((ptr == NULL) && (len > 8))
      return FALSE;

/*--------------------------------------------------------------------*/
/*          Period must be in second through ninth character          */
/*--------------------------------------------------------------------*/

   if ((ptr == tempname) || (ptr > &tempname[8]))
      return FALSE;

/*--------------------------------------------------------------------*/
/*             Extension must be three characters or less             */
/*--------------------------------------------------------------------*/

   if ( strlen( ptr ) > 4 )   /* Three characters plus the period?   */
      return FALSE;           /* No --> Too much                     */

/*--------------------------------------------------------------------*/
/*                          Only one period                           */
/*--------------------------------------------------------------------*/

   if (ptr != strchr(tempname, '.'))
      return FALSE;

/*--------------------------------------------------------------------*/
/*                Must only be valid MS-DOS characters                */
/*--------------------------------------------------------------------*/

   strlwr( tempname );        /* Map into our desired character set  */
   if ( ptr != NULL )
	  *ptr = 'x';             /* We've already accounted for the
								 period, don't let it ruin our day   */

   if (strspn(tempname, charset ) == len)
   {
/*
      printmsg(4,"ValidDOSName: \"%s\" is valid", s);
*/
	  return TRUE;
   }
   else
      return FALSE;

} /* ValidateDOSName */

void bugout(const long lineno,const char * fname)
{ printf("Error in line %ld in file %s!\n",lineno,fname);
  exit(7);
}
