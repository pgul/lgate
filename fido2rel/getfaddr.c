#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "gate.h"

static char * p, * p1,* p2;
static char c;

int getfidoaddr(uword * zone,uword * net,uword * node,
                uword * point,char * addr)
/* возвращает 0 в случае успеха */
{
  debug(10, "GetFidoAddr: %s", addr);
  for (p2=addr;isdigit(*p2) || (*p2==':') || (*p2=='/') || (*p2=='.');p2++);
  c=*p2;
  *p2=0;
  p=strchr(addr,':');
  p1=strchr(addr,'.');
  *p2=c;
  *zone=myaka[0].zone;
  *point=0;
  if (p)
  { if (p1)
    { if (sscanf(addr,"%hu:%hu/%hu.%hu",zone,net,node,point)!=4)
        return 1;
      else
        return 0;
    }
    else
    { if (sscanf(addr,"%hu:%hu/%hu",zone,net,node)!=3)
        return 1;
      else
        return 0;
    }
  }
  else /* зона не указана */
  { if (p1)
    { if (sscanf(addr,"%hu/%hu.%hu",net,node,point)!=3)
        return 1;
      else
        return 0;
    }
    else
    { if (sscanf(addr,"%hu/%hu",net,node)!=2)
        return 1;
      else
        return 0;
    }
  }
}
