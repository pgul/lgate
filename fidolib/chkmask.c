#include "fidolib.h"

int chkmask(ftnaddr * addr,ftnaddr * mask)
{
  if ((word)mask->zone==-1) return 1;
  if (addr->zone!=mask->zone) return 0;
  if ((word)mask->net==-1) return 1;
  if ((mask->net<100) && ((word)mask->node==-2))
  { /* региональная маска */
    while (addr->net>=100) addr->net/=10;
    if (addr->net==mask->net) return 1;
    return 0;
  }
  if (addr->net!=mask->net) return 0;
  if ((word)mask->node==-1) return 1;
  if (addr->node!=mask->node) return 0;
  if ((word)mask->point==-1) return 1;
  if (addr->point!=mask->point) return 0;
  return 1;
}

int checkmask(uword zone,uword net,uword node,uword point,
              uword mzone,uword mnet,uword mnode,uword mpoint)
{
  if ((word)mzone==-1) return 1;
  if (zone!=mzone) return 0;
  if ((word)mnet==-1) return 1;
  if ((mnet<100) && ((word)mnode==-2))
  { /* региональная маска */
    while (net>=100) net/=10;
    if (net==mnet) return 1;
    return 0;
  }
  if (net!=mnet) return 0;
  if ((word)mnode==-1) return 1;
  if (node!=mnode) return 0;
  if ((word)mpoint==-1) return 1;
  if (point!=mpoint) return 0;
  return 1;
}
