/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:58:33  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "fidolib.h"

int getfaddr(char * addr,ftnaddr * node,unsigned defzone,unsigned defnet)
/* возвращает 0 в случае успеха */
{
  char * p,* p1;
  char def;
  char tmpaddr[30];

  node->point=0;
  strncpy(tmpaddr,addr,sizeof(tmpaddr));
  tmpaddr[sizeof(tmpaddr)-1]=0;
  for (p=tmpaddr;isdigit(*p) || (*p==':') || (*p=='/') || (*p=='.');p++);
  *p=0;
  def=1;
  p=strchr(tmpaddr,':');
  if (p==NULL)
  { if (defzone==0)
      return 1;
    p=tmpaddr;
    node->zone=defzone;
  }
  else
  { *p=0;
    for (p=tmpaddr;*p;p++)
      if (!isdigit(*p))
        return 1;
    node->zone=atoi(tmpaddr);
    p++;
    def=0;
  }
  if (*p=='/')
  { if (def)
    { p++;
      if (strchr(p,'/'))
        return 1;
    }
    else return 1;
  }
  if (strchr(p,':'))
    return 1;
  p1=strchr(p,'/');
  if (p1)
  { *p1=0;
    for (p1=p;*p1;p1++)
      if (!isdigit(*p1))
        return 1;
    node->net=atoi(p);
    p=p1+1;
    def=0;
  }
  else
    if (defnet==0)
      return 1;
    else
      node->net=defnet;
  if (strchr(p,'/'))
    return 1;
  if ((*p=='.') || (*p==0))
    return 1;
  p1=strchr(p,'.');
  if (p1) *p1=0;
  node->node=atoi(p);
  for (;*p;p++)
    if (!isdigit(*p))
      return 1;
  if (!p1)
    return 0;
  p1++;
  node->point=atoi(p1);
  for (;*p1;p1++)
    if (!isdigit(*p1))
      return 1;
  return 0;
}
