/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 18:37:11  gul
 * Reformat source, translate comments
 *
 * Revision 2.0  2001/01/10 20:42:26  gul
 * We are under CVS for now
 *
 */
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "gate.h"

int uppername;
static char * p,* p1,* p2;
static char s[MAXADDR],s1[MAXADDR];
static int  i,r;
static uword nz,nn,nf,np;
static char c;

/* anything@domain -> domain!anything;
   anything!user%domain -> anything!domain!user
   Then find last of fF.nN.zZ - it's address,
   after last '!' - user
   ? Messages to another gate ?
*/

int transaddr(char *user, uword *zone, uword *net, uword *node,
              uword *point, char *addr)
{
  debug(5, "transaddr(%s)", addr);
  strcpy(s, addr);
  /* all after '@' - to start before '!' */
  s1[0]=0;
  while ((p=strrchr(s, '@'))!=NULL)
  { strcat(s1, p+1);
    *p=0;
    strcat(s1, "!");
  }
  strcat(s1, s);
  strcpy(s, s1);
  /* all after second '%' between '!' - excact after this '!' */
  s1[0]=0;
  do
  {
    p=strchr(s, '!');
    if (p) *p=0;
    do
    {
      p1=strrchr(s, '%');
      if (p1)
      { *p1=0;
        if (strchr(s, '%'))
        { strcat(s1, p1+1);
          strcat(s1, "!");
        }
        else
        { *p1='%';
          p1=NULL;
        }
      }
    }
    while (p1);
    strcat(s1, s);
    if (p)
    { strcat(s1, "!");
      strcpy(s, p+1);
    }
  }
  while (p);
  strcpy(s, s1);

  /* Find last fidonet address */
  p=s;
  p1=NULL; /* pointer to matched addr */
  do
  {
    if (isdigit(*p))
    { /* is it 463/68 or 2.463/68.0 */
      for (i=0; isdigit(p[i]); i++);
      if (p[i]=='.')
      { p[i]=':';
        r=getfidoaddr(&nz, &nn, &nf, &np, p);
        p[i]='.';
      }
      else if ((p[i]=='/') || (p[i]==':'))
        r=getfidoaddr(&nz, &nn, &nf, &np, p);
      else
        r=1;
    }
    else if (tolower(*p)=='p')
    { strcpy(s1, s);
      strlwr(s);
      r=sscanf(p, "p%hu.f%hu.n%hu.z%hu", &np, &nf, &nn, &nz)-4;
      strcpy(s, s1);
    }
    else if (tolower(*p)=='f')
    { strcpy(s1, s);
      strlwr(s);
      np=0;
      r=sscanf(p, "f%hu.n%hu.z%hu", &nf, &nn, &nz)-3;
      strcpy(s, s1);
    }
    else
      r=1;
    if (r==0)
    { p1=p;
      *zone=nz, *net=nn, *node=nf, *point=np;
    }
    p=strpbrk(p, "!%");
    if (p==NULL) break;
    p++;
  }
  while (*p);
  if (p1==NULL)
  { debug(5, "TransAddr: can't convert to FTN-address");
    return 1;
  }
  /* Search username */
  p=strrchr(p1, '!');
  if (p)
  { strncpy(user, p+1, sizeof(msghdr.to)-1);
    user[sizeof(msghdr.to)-1]=0;
  }
  else
  { p=strrchr(s, '%');
    if (p+1!=p1)
      strcpy(user, "SysOp");
    else
    {
      *p=0;
      p=strrchr(s, '!');
      if (p==NULL) p=s;
      else p++;
      strncpy(user, p, sizeof(msghdr.to)-1);
      user[sizeof(msghdr.to)-1]=0;
    }
  }
  if (strchr(user, '%'))
    *(strrchr(user, '%'))='@';
  else
  {
    if (uppername)
      if ((user[0]>='a') && (user[0]<='z'))
        user[0]=toupper(user[0]);
    if (strchr(user,'_'))
      for (p=user; *p; p++)
      { if (*p=='_')
        { *p=' ';
          if (uppername)
            if ((p[1]>='a') && (p[1]<='z'))
              p[1]=toupper(p[1]);
        }
      }
    else
      for (p=user; *p; p++)
        if (*p=='.')
        { *p=' ';
          if (uppername)
            if ((p[1]>='a') && (p[1]<='z'))
              p[1]=toupper(p[1]);
        }
  }
  debug(5, "TransAddr: return user='%s', FTN-addr=%d:%d/%d.%d", user,
        *zone, *net, *node, *point);
  return 0;
}

int getfidoaddr(uword *zone, uword *net, uword *node,
                uword *point, char *addr)
/* return 0 on success */
{ char *p, *p1;
  for (p2=addr; isdigit(*p2) || (*p2==':') || (*p2=='/') || (*p2=='.'); p2++);
  c=*p2;
  *p2=0;
  p=strchr(addr, ':');
  p1=strchr(addr, '.');
  *p2=c;
  *zone=2;
  *point=0;
  debug(9, "GetFidoAddr('%s')", addr);
  if (p)
  { if (p1)
    { if (sscanf(addr, "%hu:%hu/%hu.%hu", zone, net, node, point)!=4)
        return 1;
      else
        return 0;
    }
    else
    { if (sscanf(addr, "%hu:%hu/%hu", zone, net, node)!=3)
        return 1;
      else
        return 0;
    }
  }
  else /* no zone */
  { if (p1)
    { if (sscanf(addr, "%hu/%hu.%hu", net, node, point)!=3)
        return 1;
      else
        return 0;
    }
    else
    { if (sscanf(addr, "%hu/%hu", net, node)!=2)
        return 1;
      else
        return 0;
    }
  }
}
