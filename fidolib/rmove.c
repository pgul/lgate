/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2001/01/25 12:50:31  gul
 * HAVE_STRICMP added
 *
 * Revision 2.0  2001/01/10 20:42:20  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "fidolib.h"

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

int rmove(char *oldname, char *newname)
{
  int  i, arcmail;
  char *p, *p1=NULL;

  if (move(oldname, newname)==0)
    return 0;
  else if (access(newname, 0))
    return 1;
#if 0
  p=malloc(strlen(newname)+4);
  if (p==NULL) return 2;
  strcpy(p, newname);
  newname=p;
#endif
  /* get basename */
  p=strrchr(newname, PATHSEP);
  if (p==NULL) p=newname;
  else p++;
  /* is it arcmail or tic? */
  arcmail=0;
  if (strlen(p)==12 && p[8]=='.')
  { for (i=0; i<8; i++)
      if (!isxdigit(*p))
        break;
    if (i==8)
      if (strnicmp(p+9, "su", 2)==0 ||
          strnicmp(p+9, "mo", 2)==0 ||
          strnicmp(p+9, "tu", 2)==0 ||
          strnicmp(p+9, "we", 2)==0 ||
          strnicmp(p+9, "th", 2)==0 ||
          strnicmp(p+9, "fr", 2)==0 ||
          strnicmp(p+9, "sa", 2)==0 ||
          stricmp(p+9, "pkt")==0 ||
          stricmp(p+10, "ic")==0)
      { arcmail=1;
        p1=p+7;
      }
  }
  if (!arcmail)
  { p=strrchr(p, '.');
    if (p==NULL)
    { p=newname+strlen(newname);
      strcpy(p++, ".");
    }
    else p++;
    /* set p[2] to 'z' (not '0') to avoid first try - increase *p1 */
    if (*p==0)
    { p[0]=p[1]='0';
      p[2]='z';
    }
    else if (p[1]==0)
    { p[1]=0;
      p[2]='z';
    }
    else if (p[2]==0)
      p[2]='z';
    p[3]='\0';
    p1=p+strlen(p)-1;
  }
  /* increase last char if it's digit */
  /* i.e. if exist name.zi6, create name.zi7 but not name.zi0 */
  if (isdigit(*p1))
    for (p1[0]++; isdigit(*p1); p1[0]++)
    { if (move(oldname, newname)==0)
        return 0;
      else if (access(newname, 0))
        return 1;
    }
  /* increase from zero */
  for (i=0, *p1='0'; ;)
  { if (move(oldname, newname)==0)
      return 0;
    else if (access(newname, 0))
      return 1;
    if (*p1=='9') *p1='a';
    else if (*p1!='z') p1[0]++;
    else
    { int j;
      for (j=0; j<i; j++)
      { *(p1--)='0';
        if (*p1=='z')
          continue;
        if (*p1=='9') *p1='a';
        else p1[0]++;
        break;
      }
      if (j<i)
      { p1+=j+1;
        continue;
      }
      if (p1==p)
        return 2;
      i++;
      *(p1--)='0';
      *p1='0';
      p1+=i;
    }
  }
}
