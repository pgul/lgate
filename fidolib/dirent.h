/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#ifndef __DIRENT_DEF_
#define __DIRENT_DEF_
#include <io.h> /* struct ftime */
#include <time.h>

#define MAXNAMLEN   13

struct dirent {
   long  d_size;
   short d_reclen;
   short d_namlen;
   time_t d_mtime;
   char  d_name[MAXNAMLEN];
};

typedef struct {
   char filereserved[21];
   char fileattr;
   struct ftime filetime;
   long filesize;
   char filename[MAXNAMLEN];
} DTA;

typedef struct {
   char dirid[4];
   struct dirent dirent;
   DTA dirdta;
   int dirfirst;
} DIR;

struct dirent *readdir(DIR *dirp);
void closedir(DIR *dirp);
DIR *opendir(const char *dirname);
#endif
