#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include "regex.h"
#include "libgate.h"

#define REG_TYPE REG_ICASE|REG_EXTENDED
#define REG_MODE 0

#define VIAREGEX 0 /* convert wildcard to regex and then check */

static void RegExpErr (int Error, regex_t * RegBuf)
{
  char *string;
  int  i;

  if (Error == 0) return;

  i = regerror (Error, RegBuf, 0, 0);
  string = malloc (i);
  if (string == 0)
  { logwrite ('!', "CmpAddr: not enough memory!\n");
    return;
  }
  regerror (Error, RegBuf, string, i);
  logwrite('!', "Error in regexp: %s!\n", string);
  free (string);
  return;

} /* RegExpErr */

int chkregexp(char * str, char * regexp
#ifndef __MSDOS__
              , void **regbuf
#endif
              )
{
  int r;
  regex_t *rb;
#ifdef __MSDOS__
  regex_t RegBuf;
  rb = &RegBuf;
  {
#else
  if (regbuf && *regbuf)
    rb = (regex_t *)*regbuf;
  else
  { rb = malloc(sizeof(*rb));
    if (rb==NULL)
    { logwrite('!', "Not enough memory for regexp!\n");
      return -1;
    }
    if (regbuf)
      *regbuf=rb;
#endif
    r=regcomp(rb, regexp, REG_TYPE);
    if (r)
    { RegExpErr(r, rb);
#ifndef __MSDOS__
      free(rb);
      if (regbuf) *regbuf=NULL;
#endif
      return -1;
    }
  }
  r = regexec (rb, str, 0, 0, REG_MODE);
  if ((r != REG_NOERROR) && (r != REG_NOMATCH))
  { RegExpErr (r, rb);
#ifdef __MSDOS__
    regfree(rb);
#else
    if (regbuf==NULL)
    { regfree(rb);
      free(rb);
    }
#endif
    return -1;
  }

#ifdef __MSDOS__
  regfree(rb);
#else
  if (regbuf==NULL)
  { regfree(rb);
    free(rb);
  }
#endif
  return (r == REG_NOMATCH) ? 1 : 0;
}

#if !VIAREGEX
static int mstrcmp(char * mask,char * adr)
{
  for (;;mask++,adr++)
  { if (*mask=='*') return 0;
    if ((*mask=='?') && (*adr))
      continue;
    if ((*mask==0) && (*adr==0))
      return 0;
    if (toupper(*mask)!=toupper(*adr))
      return 1;
  }
}
#endif

int wildcmp(char * addr,wildcard * mask)
{
  char *p, *maskstr;
  int  r;
#if VIAREGEX
  char *p1;
#endif

  maskstr=mask->str;
  debug(15, "WildCmp, addr='%s', mask='%s'", addr, maskstr);
  if ((maskstr[0]=='/') && (maskstr[strlen(maskstr)-1]=='/'))
  { debug(21, "WildCmp, it's regexp");
    p=strdup(maskstr+1); /* avoid r/o strings segment */
    if (p==NULL)
    { logwrite('!', "Not enough memory for regex checking!\n");
      return -1;
    }
    p[strlen(p)-1]='\0';
    r=chkregexp(addr, p
#ifndef __MSDOS__
                , &(mask->regbuf)
#endif
                );
    free(p);
    debug(16, "WildCmp, result is %s", r ? "FALSE" : "TRUE");
    return r;
  }

#if VIAREGEX

  /* wildcard to regex */
  p=malloc(strlen(maskstr)*2+3);
  if (p==NULL)
  { logwrite('!', "Not enough memory for regexp checking!\n");
    return -1;
  }
  p1=p;
  *p1++='^';
  for(;*maskstr;maskstr++)
  { switch (*maskstr)
    { case '?': *p1++='.';
                break;
      case '*': *p1++='.';
                *p1++='*';
                break;
      case '\\':
      case '.':
      case '^':
      case '[':
      case ']':
      case '$':
      case '+':
      case '|':
      case '{':
      case '}':
      case '(':
      case ')': *p1++='\\';
      default:  *p1++=*maskstr;
    }
  }
  *p1++='$';
  *p1++='\0';
  debug(21, "CmpAddr, regexp is \"%s\"", p);
  r=chkregexp(addr, p
#ifndef __MSDOS__
                , &(mask->regbuf)
#endif
             );
  free(p);
  debug(16, "CmpAddr, result is %s", r ? "FALSE" : "TRUE");
  return r;

#else /* not VIAREGEX */

  if (*maskstr!='*')
  { if (mstrcmp(maskstr,addr))
    { debug(15, "CmpAddr: FALSE");
      return 1;
    }
    while ((*maskstr!='*') && (*maskstr!=0))
      maskstr++,addr++;
    if (*maskstr==0)
    { debug(15, "CmpAddr: TRUE");
      return 0;
    }
  }
  maskstr++;
  for (;;)
  {
    while (mstrcmp(maskstr,addr))
    { if (*addr==0)
      { debug(15, "CmpAddr: FALSE");
        return 1;
      }
      addr++;
    }
    while ((*maskstr!='*') && (*maskstr!=0))
      maskstr++,addr++;
    if (*maskstr==0)
    { debug(15, "CmpAddr: TRUE");
      return 0;
    }
    maskstr++;
  }

#endif

}

int cmpaddr(char * addr,char * mask)
{
  wildcard w;
  int  r;

  w.str = mask;
#ifndef __MSDOS__
  w.regbuf = NULL;
#endif
  r = wildcmp(addr, &w);
#ifndef __MSDOS__
  if (w.regbuf)
  { regfree((regex_t *)(w.regbuf));
    free(w.regbuf);
  }
#endif
  return r;
}

#ifdef CMP_TEST
#include <stdio.h>
char addr[128],mask[128];

void debug(int level, ...)
{};
void logwrite(char level, ...)
{};

void main(void)
{
  for (;;)
  {
    printf("Enter a mask: ");
    gets(mask);
    if (mask[0]==0)
      return;
    printf("Enter address: ");
    gets(addr);
    if (addr[0]==0)
      return;
    if (cmpaddr(addr,mask))
      puts("No");
    else
      puts("Yes");
  }
}
#endif
