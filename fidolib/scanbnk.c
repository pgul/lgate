/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:20  gul
 * We are under CVS for now
 *
 */
#include <string.h>
#include <stdio.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#else
#include <direct.h>
#endif
#include <ctype.h>
#include "fidolib.h"

void logwrite(char level, char *format, ...);

static void doonelo(char *lopath, char *path, int zone, char attr,
         void (*chklo)(char *lopath, struct stat *ff, ftnaddr *loaddr))
{ struct stat ff;
  ftnaddr to;
  char *p;

#ifndef UNIX
  strlwr(lopath);
#endif
  p=strrchr(lopath, PATHSEP);
  if (p) p++;
  else p=lopath;
  if (strlen(p)!=12) return;
#ifdef UNIX
  if (strcmp(p+10, "lo")) return;
#else
  if (stricmp(p+10, "lo")) return;
#endif
  if (strchr("hfndci", p[9])==NULL)
    return;
  to.point=0;
  to.zone=zone;
  if ((strlen(lopath)>25) &&
      (strncmp(lopath+strlen(lopath)-17, ".pnt" PATHSTR "0000", 9)==0))
  { p=lopath+strlen(lopath)-25;
    sscanf(p,"%04hx%04hx.pnt" PATHSTR "0000%04hx.",
           &to.net,&to.node,&to.point);
  }
  else
  { p=lopath+strlen(lopath)-12;
    sscanf(p,"%04hx%04hx.",&to.net,&to.node);
  }
  if ((p>lopath+2) && (*(p-1)==PATHSEP))
  { for (p-=2; (p>lopath) && isxdigit(*p); p--);
    if ((*p=='.') && (p[4]==PATHSEP))
      sscanf(p+1, "%03hx", &to.zone);
  }
  stat(lopath, &ff);
  if ((ff.st_size==0) && (attr & IGNOREZEROLO))
    return;
  if (attr & SETBSY)
    if (SetBinkSem(&to,path,zone))
    { logwrite('>',"Skipping busy system %u:%u/%u.%u\n",
               to.zone,to.net,to.node,to.point);
      return;
    }
  chklo(lopath, &ff, &to);
  if (attr & SETBSY)
    DelBinkSem(&to,path,zone);
}

void onezone(char *str, char *path, int zone, int attr,
         void (*chklo)(char *lopath, struct stat *ff, ftnaddr *loaddr))
{ DIR *d, *d1;
  struct dirent *df, *df1;
  int r;
  static char lopath[128],lopath1[128];
  
  d=opendir(str);
  if (d==NULL) return;
  while ((df=readdir(d))!=NULL)
  { if (df->d_name[0]=='.') continue;
    if (strlen(df->d_name)!=12) continue;
    if (df->d_name[8]!='.') continue;
    for (r=0; r<8; r++)
      if (!isxdigit(df->d_name[r]))
        break;
    if (r<8) continue;
    strcpy(lopath, str);
    if (lopath[strlen(lopath)-1]!=PATHSEP)
      strcat(lopath, PATHSTR);
    strcat(lopath, df->d_name);
#ifdef UNIX
    if (strcmp(df->d_name+9, "pnt")==0)
#else
    if (stricmp(df->d_name+9, "pnt")==0)
#endif
    { d1=opendir(lopath);
      if (d1==NULL) continue;
      while ((df1=readdir(d1))!=NULL)
      { if (df1->d_name[0]=='.') continue;
        if (strlen(df1->d_name)!=12) continue;
        if (df1->d_name[8]!='.') continue;
        for (r=0; r<8; r++)
          if (!isxdigit(df1->d_name[r]))
            break;
        if (r<8) continue;
        strcpy(lopath1, lopath);
        strcat(lopath1, PATHSTR);
        strcat(lopath1, df1->d_name);
        doonelo(lopath1, path, zone, attr, chklo);
      }
      closedir(d1);
      continue;
    }
    doonelo(lopath, path, zone, attr, chklo);
  }
  closedir(d);
}

void ScanBinkOutbound(char * path, unsigned zone, char attr,
         void (*chklo)(char *lopath, struct stat *ff, ftnaddr *loaddr))
{
  char str[256];
  char *p, *p1;
  DIR  *d;
  struct dirent *df;

  strcpy(str,path);
  if ((str[strlen(str)-1]==PATHSEP) && (strlen(str)>DISKPATH+1))
    str[strlen(str)-1]='\0';
  if (strlen(str)==DISKPATH+1)
  { onezone(str, path, zone, attr, chklo);
    return;
  }
  p=strrchr(str, PATHSEP);
  if (p==NULL) goto onezone;
  p1=strchr(p, '.');
  if (p1==NULL) goto onezone;
  p1++;
  if (*p1=='\0') goto onezone;
  if (!isxdigit(*p1)) goto onezone;
  while (isxdigit(*p1)) p1++;
  if (*p1)
onezone:
    onezone(str, path, zone, attr, chklo);
  if (str[strlen(str)-1]!=PATHSEP)
    strcat(str, PATHSTR);
  strcat(str, "..");
  d=opendir(str);
  if (d==NULL) return;
  while ((df=readdir(d))!=NULL)
  { if (df->d_name[0]=='.') continue;
    p=strchr(df->d_name, '.');
    if (p==NULL) continue;
    if (!isxdigit(*++p)) continue;
    while (isxdigit(*++p));
    if (*p) continue;
    strcpy(str,path);
    if (str[strlen(str)-1]!=PATHSEP)
      strcat(str, PATHSTR);
    strcat(str, ".." PATHSTR);
    strcat(str, df->d_name);
    onezone(str, path, zone, attr, chklo);
  }
  closedir(d);
}
