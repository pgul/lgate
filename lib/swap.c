/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#include <string.h>
#include <stdlib.h>
#include "exec.h"
#include "libgate.h"

int swap_system(char * cmd)
{ 
  char * p;

  debug(5, "Swap_System: '%s'", cmd);
  p=strpbrk(cmd," \t");
  if (p)
  {
    *p++='\0';
    while ((*p==' ') || (*p=='\t'))
      p++;
  }
  else
    p="";
  return do_exec(cmd,p,use_swap,-1,environ);
}
