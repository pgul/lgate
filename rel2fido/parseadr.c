/*
 * $Id$
 *
 * $Log$
 * Revision 2.3  2004/07/07 09:14:54  gul
 * Fixed chaddr
 *
 * Revision 2.2  2004/03/27 12:20:38  gul
 * Unquote realname
 *
 * Revision 2.1  2004/03/27 11:57:40  gul
 * Translate comments
 *
 * Revision 2.0  2001/01/10 20:42:25  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <string.h>
#include "gate.h"

static void parseoneaddr(char *str, char *addr, int maxaddr,
                         char *realname, int chaddr)
{
  char *p, *p1, c;
  int  i, j;
  int  r1, r2, curmatch, curchaddr;

  debug(6, "ParseAddr('%s')", str);
  if (maxaddr<1)
    return;
  realname[SSIZE-1]=0;
  /* split address and real name */
  for(p=str, i=0; *p; p++, i++)
  { if (*p=='(')
    { for (j=0;;)
      { p=strpbrk(p+1, "()");
        if (p==NULL)
          break;
        if (*p=='(')
        { j++;
          continue;
        }
        if (j==0)
          break;
        j--;
      }
      if (p) p++;
      else p=str+strlen(str);
      if (*p==0)
        break;
    }
    if (*p=='<') break;
    if (i<maxaddr)
    { if ((i==0) && ((*p==' ') || (*p=='\t')))
        i--;
      else
        addr[i]=*p;
    }
  }
  if (i<maxaddr)
    addr[i]=0;
  if (*p=='<')
  { /* first format of address */
    p1=p;
    for (i=0; (str[i]==' ') || (str[i]=='\t'); i++);
    if (str[i] != '<')
    {
      for (p1--; (*p1==' ') || (*p=='\t'); p1--);
      /* "Vasya Pupkin"  ->  Vasya Pupkin */
      if (str[i] == '\"' && *p1 == '\"' && p1>str+i)
      { i++;
        p1--;
      }
      p1++;
      c=*p1;
      *p1='\0'; /* todo: make str const */
    }
    strncpy(realname, str+i, SSIZE-1);
    *p1=c;
    for (i=1; (p[i]==' ') || (p[i]=='\t'); i++);
    strncpy(addr, p+i, maxaddr-1);
    p=strchr(p, '>');
    if (p)
    { stripspc(realname);
      if (realname[0] && (strlen(realname)!=SSIZE-1))
        strcat(realname, " ");
      for (i=1; (p[i]==' ') || (p[i]=='\t'); i++);
      strncpy(realname+strlen(realname), p+i,
              SSIZE-strlen(realname)-1);
      p=strchr(addr, '>');
      if (p) *p=0;
    }
  }
  else
  { /* realname is in the parenthesis, the rest is address */
    p=strchr(str, '(');
    if (p==NULL)
      realname[0]=0;
    else
    {
      for (i=1; (p[i]==' ') || (p[i]=='\t'); i++);
      strncpy(realname, p+i, SSIZE-1);
      for (p=realname, i=0; *p; p++)
      { if (*p=='(')
        { i++;
          continue;
        }
        if (*p==')')
        { if (i==0)
          { *p=0;
            break;
          }
          else
            i--;
        }
      }
    }
  }
  p=strchr(addr, '\r');
  if (p) *p=0;
  p=strchr(realname, '\r');
  if (p) *p=0;
  stripspc(realname);
  stripspc(addr);
  if (addr[0]==0)
    strcpy(addr, "uucp");
  debug(6, "ParseAddr: address '%s', realname '%s'", addr, realname);
  if (chaddr==-1)
    return;
  /* process chdomain */
  for (i=0; i<ncdomain; i++)
  { if (strlen(addr)<=strlen(cdomain[i].relcom))
      continue;
    p=addr+strlen(addr)-strlen(cdomain[i].relcom);
    if (stricmp(p, cdomain[i].relcom))
      continue;
    strncpy(p, cdomain[i].fido, maxaddr-strlen(addr)+strlen(cdomain[i].relcom));
    /* added or removed '@' */
    if (strchr(cdomain[i].fido, '@'))
    { p=strrchr(addr, '@');
      for(p1=addr; p1!=p; p1=strchr(p1, '@'))
        *p1='%';
    }
    if (strchr(cdomain[i].relcom, '@'))
      if (strchr(addr, '@')==0)
      { p=strrchr(addr, '%');
        if (p) *p='@';
      }
    break;
  }
  /* process chaddr */
  curmatch=0; /* 1 - nothing, 2 - fido, 3 - zone, 4 - region, 5 - net, 6 - node */
  curchaddr=-1;
  for (i=0; i<ncaddr; i++)
  { if (stricmp(addr, caddr[i].relcom)==0)
    { 
      for (r1=net; r1>=100; r1/=10);
      for (r2=caddr[i].net; r2>=100; r2/=10);
      if ((caddr[i].zone<7 && zone>7) ||
          (caddr[i].zone>7 && zone<7))
      { if (curmatch>0) continue;
        curmatch=1;
      }
      else if (caddr[i].zone!=zone)
      { if (curmatch>1) continue;
        curmatch=2;
      }
      else if (r1!=r2)
      { if (curmatch>2) continue;
        curmatch=3;
      }
      else if (caddr[i].net!=net)
      { if (curmatch>3) continue;
        curmatch=4;
      }
      else if (caddr[i].node!=node)
      { if (curmatch>4) continue;
        curmatch=5;
      }
      else
      { if (curmatch>5) continue;
        curmatch=6;
      }
      curchaddr=i;
    }
  }
  if (curchaddr!=-1)
  { strncpy(addr, caddr[curchaddr].fido, maxaddr);
    realname[0]=0;
    for (p=addr; *p; p++)
      if ((*p==' ') || (*p=='\t')) *p='_';
    sprintf(p, "@p%u.f%u.n%u.z%u.%s",
            caddr[curchaddr].point, caddr[curchaddr].node,
            caddr[curchaddr].net, caddr[curchaddr].zone,
            myaka[curaka].domain);
    if (strchr(myaka[curaka].domain, '@'))
      p[0]='%';
    if (chaddr)
      waschaddr=1;
  }
  debug(6, "ParseAddr: Address after chaddr is %s", addr);
}

void parseaddr(char *str, char *addr, char *realname, int chaddr)
{
  char *p, *p1;
  int j=0, quote=0;

  addr[0]=addr[MAXADDR-1]='\0';
  for (p=str; *p;)
  {
    for(p1=p; *p1; p1++)
    {
      if (*p1==',' && j==0 && quote==0)
        break;
      if (*p1=='(')
        j++;
      else if (*p1==')' && j>0)
        j--;
      else if (*p1=='\\' && p1[1])
        p1++;
      else if (*p1=='\"' && j==0)
        quote^=1;
    }
    if (*p1=='\0') break;
    *p1='\0';
    parseoneaddr(p, addr+strlen(addr), MAXADDR-strlen(addr)-1, realname, chaddr);
    *p1=',';
    p=p1+1;
    if (strlen(addr)+1>=MAXADDR)
      break;
    if (strlen(addr)<MAXADDR-5)
      strcat(addr, ", ");
  }
  parseoneaddr(p, addr+strlen(addr), MAXADDR-strlen(addr)-1, realname, chaddr);
}
