#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "libgate.h"
#include "koi8-u.h"

static struct chsalias_type
 { char *from;
   char *to;
   struct chsalias_type *next;
 } *chsaliases=NULL;

static struct xtable_type
 { char *charset;
   short int *xtable;
   struct xtable_type *next;
 } *table=NULL;

void addtable(char *charsetname, short int *xtable)
{
  struct xtable_type *p;

  charsetname=canoncharset(charsetname);
  if (table==NULL)
  { table=malloc(sizeof(*table)+strlen(charsetname)+1+256*sizeof(*xtable));
    p=table;
  }
  else
  { for (p=table; p; p=p->next)
    { if (stricmp(charsetname, p->charset)==0)
      { memcpy(p->xtable, xtable, 256*sizeof(*xtable));
        return;
      }
      if (p->next == NULL)
        break;
    }
    p->next=malloc(sizeof(*table)+strlen(charsetname)+1+256*sizeof(*xtable));
    p=p->next;
  }
  if (p==NULL)
  { logwrite('?', "Not enough memory for charsets!\n");
    return;
  }
  p->next=NULL;
  p->xtable=(short int *)((char *)p+sizeof(*p));
  memcpy(p->xtable, xtable, 256*sizeof(*xtable));
  p->charset=(char *)(p->xtable+256);
  strcpy(p->charset, charsetname);
}

void addmytable(char *charsetname, short int *table, char *charsetsdir)
{ short int *t;
  short int newtable[256];
  int i, j;

  if (findtable(charsetname, charsetsdir))
    return; /* builtin tables cannot override external */
  if (charsetsdir && charsetsdir[0])
  { addtable(charsetname, table);
    return;
  }
  if ((t=findtable("koi8-u", charsetsdir)) == NULL &&
      (t=findtable("x-koi8-u", charsetsdir)) == NULL &&
      (t=findtable("koi8-r", charsetsdir)) == NULL)
    return; /* don't know how to recode from koi8 to extsetname */
  for (i=0; i<128; i++)
    newtable[i]=i;
  for (; i<256; i++)
    newtable[i]='?';
  for (i=128; i<256; i++)
  { for (j=0; j<256; j++)
      if (table[i] == koi8u_table[j])
      { newtable[i] = t[j];
        break;
      }
    if (j==256)
    { int newc=0;
      if (table[i]==1168) /* ukrainian capital "GHE" with upturn */
        newc=1043;         /* cyrillic capital "GHE" */
      else if (table[i]==1169) /* ukrainian small "GHE" with upturn */
        newc=1075;              /* cyrillic small "GHE" */
      else if (table[i]==1030) /* ukrainian capital "I" */
        newc='I';
      else if (table[i]==1110) /* ukrainian small "I" */
        newc='i';
      if (newc)
        for (j=0; j<256; j++)
          if (newc == koi8u_table[j])
            newtable[i] = t[j];
    }
  }
  addtable(charsetname, newtable);
}

void setcharset(char *charsetname, char *fname)
{ int h,i;
  char newxtable[128];
  short int newtable[256];

  h=myopen(fname, O_BINARY|O_RDONLY);
  if (h==-1)
  { logwrite('!', "Can't open %s: %s!\n", fname, strerror(errno));
    return;
  }
  lseek(h, 128, SEEK_SET);
  read(h, newxtable, 128);
  close(h);
  for (i=0; i<128; i++)
    newtable[i]=i;
  for (; i<256; i++)
    newtable[i]=newxtable[i-128];
  addtable(charsetname, newtable);
}

char *chsalias(char *charset)
{
  struct chsalias_type *p;

  for (p=chsaliases; p; p=p->next)
    if (stricmp(p->from, charset)==0)
      return p->to;
  return charset;
}

void addchsalias(char *from, char *to)
{
  char str[256];
  char *p;
  struct chsalias_type *pa;

  debug(8, "addchsalias %s->%s", from, to);
  if (stricmp(from, to) == 0)
  { debug(2, "Charset alias %s->%s ignored\n", from, to);
    return;
  }
  if (chsalias(from)!=from)
  { debug(4, "charset alias %s already defined to %s, alias to %s ignored",
             from, chsalias(from), to);
    return;
  }
  if (chsalias(to)!=to)
  {
    /* check for alias loop */
    p=to;
    sprintf(str, "%s->%s", from, to);
    while (p!=chsalias(p))
    { p=chsalias(p);
      strcat(str, "->");
      strcat(str, p);
      if (stricmp(from, p)==0)
      { logwrite('!', "Charset alias loop %s; alias %s->%s ignored\n",
                 str, from, to);
        return;
      }
    }
    debug(2, "Charset complicated alias %s", str);
    to=p;
  }
  if (chsaliases == NULL)
  {
    chsaliases = malloc(sizeof(*chsaliases)+strlen(from)+strlen(to)+2);
    pa = chsaliases;
  }
  else
  {
    for (pa=chsaliases; pa->next; pa=pa->next);
    pa->next = malloc(sizeof(*chsaliases)+strlen(from)+strlen(to)+2);
    pa = pa->next;
  }
  if (pa == NULL)
  { logwrite('!', "Not enough memory for charset aliases!\n");
    return;
  }
  pa->next = NULL;
  pa->from = (char *)pa + sizeof(*pa);
  strcpy(pa->from, from);
  pa->to = pa->from + strlen(from)+1;
  strcpy(pa->to, to);
}

char *canoncharset(char *charset)
{
  if (chsalias(charset)==charset &&
      strnicmp(charset, "x-", 2)==0 &&
      chsalias(charset+2)!=charset+2)
    charset+=2;
  while (charset!=chsalias(charset))
    charset=chsalias(charset);
  return charset;
}

short int *findtable(char *charset, char *charsetsdir)
{
  char *p;
  FILE *f;
  int i;
  static short int tmptable[256];
  struct xtable_type *pt;

  debug(15, "findtable(%s)", charset);
  charset=canoncharset(charset);
  debug(15, "findtable: canon charset is %s", charset);
  for (pt=table; pt; pt=pt->next)
  { if (stricmp(charset, pt->charset)==0)
      return pt->xtable;
    if (strnicmp(charset, "x-", 2)==0)
      if (stricmp(charset+2, pt->charset)==0)
        return pt->xtable;
  }
  if (charsetsdir==NULL || charsetsdir[0]=='\0')
    return NULL;
  if (strpbrk(charset, "/\\:"))
    return NULL;
  p=charsetsdir+strlen(charsetsdir);
  strcpy(p, charset);
  if ((f=fopen(charsetsdir, "r")) == NULL)
  { if (strnicmp(charset, "x-", 2)==0)
    { strcpy(p, charset+2);
      if ((f=fopen(charsetsdir, "r")) == NULL)
      { *p='\0';
        return NULL;
      }
    }
    else
    { *p='\0';
      return NULL;
    }
  }
  *p='\0';
  fgets((char *)tmptable, sizeof(tmptable), f); /* magic line */
  for(i=0; i<256; i++)
    if(fscanf(f, "%hi", &(tmptable[i])) != 1)
      break;
  fclose(f);
  if (i!=256)
    return NULL;
  addtable(charset, tmptable);
  return tmptable;
}
