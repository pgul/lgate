#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "fidolib.h"

int getfidomask(char * addr,ftnaddr * node,uword defzone)
/* возвращает 0 в случае успеха */
{ char * p,* p1,* p2;
  char c;

  p2=addr;
  while (isdigit(*p2)||(*p2==':')||(*p2=='/')||(*p2=='.')||(*p2=='*'))
    p2++;
  if (p2==addr) return 1;
  c=*p2;
  *p2=0;
  p=strchr(addr,'*');
  if (p)
  { *p2=c;
    p2=p+1;
    c=*p2;
    *p2=0;
  }
  node->zone=defzone;
  node->net=node->node=node->point=(uword)-1;
  p=strchr(addr,':');
  if (p)
  { node->zone=atoi(addr);
    addr=p+1;
  }
  else
  { if (addr[0]=='*')
    { node->zone=(uword)-1;
      *p2=c;
      return 0;
    }
  }
  if (addr[0]=='*')
  { *p2=c;
    return 0;
  }
  p1=strchr(addr, '/');
  if (p1==NULL)
  { /* может быть маска по региону */
    if (strchr(addr,'*')==NULL)
    { *p2=c;
      return 1;
    }
    *p2=c;
    node->net=atoi(addr);
    if (node->net>=100)
      return 1;
    node->node=(uword)-2;
    return 0;
  }
  node->net=atoi(addr);
  addr=p1+1;
  if (addr[0]=='*')
  { *p2=c;
    return 0;
  }
  node->node=atoi(addr);
  p=strchr(addr,'.');
  if (p)
    if (p[1]!='*')
      node->point=atoi(p+1);
  *p2=c;
  return 0;
}
