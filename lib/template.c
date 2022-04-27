/*
 * $Id$
 *
 * $Log$
 * Revision 2.6  2011/11/19 08:39:02  gul
 * Fix strcpy(p,p+1) to own mstrcpy(p,p+1) which works correctly in this case
 *
 * Revision 2.5  2011/08/28 20:50:20  gul
 * *** empty log message ***
 *
 * Revision 2.4  2004/07/20 17:51:00  gul
 * \r\n -> \n
 *
 * Revision 2.3  2001/08/08 08:01:22  gul
 * "\r\n" -> "\n" conversion under unix
 *
 * Revision 2.2  2001/01/25 12:40:07  gul
 * Minor changes for fix compile warnings
 *
 * Revision 2.1  2001/01/15 03:37:10  gul
 * Stack overflow in dos-version fixed.
 * Some cosmetic changes.
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#include <ctype.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef INSTALL
#include "install.h"
#else
#include "libgate.h"
#endif

#define MAXSET    64
#define MAXIF     16
#define MAXINCL   5
#define MAXGLOBAL 16

#define boolean   char
#define TRUE      1
#define FALSE     0

#define setcond for (i=0, condition=TRUE; i<=iflevel; condition=ifstack[i++].state && condition);

int mktempname(char *sample, char *dest);

int  nglobal, inconfig, tplout;
char curtplname[FNAME_MAX];
int  (*gettextline)(char *str, unsigned size);
void (*reset_text)(void);
static char *curtplfname;
static boolean condition, intext, washdr, findvars;
static int  iflevel, nsets, cont, sp, curline;
static FILE *htpl;
static char *pvar;
static FILE *fpipe=NULL;
#ifdef __MSDOS__
static char npipe[FNAME_MAX];
#else
static int pidpipe;
#endif
static char cmdline[FNAME_MAX];
#ifndef INSTALL
static struct { boolean state, inelse, wastrue;
              } ifstack[MAXIF];
#endif
static struct { char *var, *value;
              } set[MAXSET], global[MAXGLOBAL];
static FILE *farr[MAXINCL];
static int  curlines[MAXINCL];

static void close_fpipe(void)
{
  if (fpipe==NULL)
    return;
#ifdef __MSDOS__
  fclose(fpipe);
  unlink(npipe);
#else
  { int status;
    waitpid(pidpipe, &status, 0);
  }
  fclose(fpipe);
#endif
  fpipe=NULL;
}

int init_tpl(char *tpl_name)
{
  iflevel=-1;
  condition=TRUE;
  nsets=0;
  cont=0;
  sp=0;
  findvars=TRUE;
  pvar=NULL;
  intext=FALSE;
  washdr=FALSE;
  htpl=NULL;
  close_fpipe();
  debug(4, "Init_tpl(%s)", tpl_name);
  strcpy(curtplname, tpl_name);
  if (tpl_name[0]==0)
    return 1;
  htpl=myfopen(tpl_name, "r");
  if (htpl==NULL)
  {
#ifndef INSTALL
    if (inconfig)
      fprintf(stderr, "Can't open config file %s: %s!\n",
              tpl_name, strerror(errno));
    else
      logwrite('?', "Can't open template file %s: %s! Use default template\n",
               tpl_name, strerror(errno));
#endif
    return -1;
  }
  curtplfname=strrchr(curtplname, PATHSEP);
  if (curtplfname)
    curtplfname++;
  else
    curtplfname=curtplname;
  curline=0;
  return 0;
}

void close_tpl(void)
{ int i;

  close_fpipe();
  for (i=0; i<nsets; i++)
    free(set[i].var);
  nsets=0;
  if (htpl)
    fclose(htpl);
  htpl=NULL;
  debug(4, "Close_tpl()");
}

static int _templateline(char *str, unsigned size)
{
  char *p; 
  int  c=0, i, varlen, incomment, wascont;
#ifdef HAVE_ENVIRON
  char *curvar;
  char *p1=NULL;
  char **pp;
#else
  char var[256];
#endif
#ifdef __MSDOS__
  int saveout;
#endif

  /* read line, substitute [var] */
  p=str;
  incomment=wascont=0;
  for (;;)
  { if (p-str>=size-1)
    { *p=0;
      return (int)(p-str);
    }
    if (pvar)
    { if (*pvar==0)
        pvar=NULL;
      else
        c=*pvar++;
    }
    if (fpipe)
    { if ((c=fgetc(fpipe))==EOF)
        close_fpipe();
      else if (c=='\n')
        c=' ';
    }
    if (pvar==NULL && fpipe==NULL)
      c=getc(htpl);
#ifdef UNIX
    if (c=='\r') continue; /* should be backslash-r if needed */
#endif
    if ((c==';') && (pvar==NULL) && (fpipe==NULL) && inconfig)
    { /* comment */
      incomment=1;
      wascont=0;
      continue;
    }
    if (c==EOF)
    { *p='\0';
      if ((strchr(str, '\n')==NULL) && (p!=str))
      { *p++='\n'; /* last line in file must ends with '\n' */
        *p='\0';
      }
      return (int)(p-str);
    }
    if ((c=='\\') && (pvar==NULL) && (fpipe==NULL)
#ifndef UNIX
        && (!inconfig)
#endif
        )
    { wascont=0;
      if (incomment) continue;
      c=getc(htpl);
      if (c==EOF)
      { *p++='\\';
        *p=0;
        return (int)(p-str);
      }
      switch(tolower(c))
      { case 't': *p++='\t';
                  break;
        case 'n': *p++='\n';
                  break;
        case 'r': *p++='\r';
                  break;
        case 's': *p++=' ';
                  break;
        default:  /* '[', '`', '\\' etc. */
                  *p++=(char)c;
                  break;
      }
      continue;
    }
#ifndef INSTALL
    if (c=='`' && !fpipe && !pvar && inconfig!=2)
    {
      int i=0, hpipe;

      for (i=0; i<sizeof(cmdline)-1; i++)
      {
        c=getc(htpl);
        if (c==EOF || c=='\n')
        { 
          if (tplout)
          { if (inconfig)
              fprintf(stderr, "Unexpected %s in config %s line %d!\n",
                      (c==EOF) ? "EOF" : "EOL", curtplfname, curline);
            else
              logwrite('!', "Unexpected %s in template %s, line %d!\n",
                       (c==EOF) ? "EOF" : "EOL", curtplfname, curline);
          }
          *p=0;
          return (int)(p-str);
        }
        if (c=='`')
        { cmdline[i]='\0';
          break;
        }
        cmdline[i++]=c;
      }
      if (i==sizeof(cmdline)-1)
      { if (tplout)
        { if (inconfig)
            fprintf(stderr, "Too long `...` expr in config %s line %d!\n",
                    curtplfname, curline);
          else
            logwrite('!', "Too long `...` expr in template %s, line %d!\n",
                     curtplfname, curline);
        }
        while (c!='`' && c!='\n' && c!=EOF)
          c=getc(htpl);
        if (c=='`')
          continue;
        *p=0;
        return (int)(p-str);
      }
      cmdline[i++]='\0';
#ifdef __MSDOS__
      mktempname("gate????.tmp", npipe);
      hpipe = open(npipe, O_RDWR|O_CREAT, S_IREAD|S_IWRITE);
      if (hpipe==-1)
      { if (tplout)
        { if (inconfig)
            fprintf(stderr, "Can't create %s: %s!\n", npipe, strerror(errno));
          else
            logwrite('!', "Can't create %s: %s!\n", npipe, strerror(errno));
        }
        continue;
      }
      fflush(stdout);
      saveout=dup(fileno(stdout));
      dup2(hpipe, fileno(stdout));
      close(hpipe);
      i=swap_system(cmdline);
      fflush(stdout);
      hpipe=dup(fileno(stdout));
      dup2(saveout, fileno(stdout));
      close(saveout);
      lseek(hpipe, 0, SEEK_SET);
      fpipe=fdopen(hpipe, "r+");
      if (i<0)
      { 
        close_fpipe();
        if (tplout)
        { if (inconfig)
            fprintf(stderr, "Can't run %s!\n", cmdline);
          else
            logwrite('!', "Can't run %s!\n", cmdline);
        }
        continue;
      }
#else
      pidpipe=pipe_system(NULL, &hpipe, cmdline);
      if (pidpipe<0 || hpipe<0)
      { if (tplout)
        { if (inconfig)
            fprintf(stderr, "Can't run %s: %s!\n", cmdline, strerror(errno));
          else
            logwrite('!', "Can't run %s: %s!\n", cmdline, strerror(errno));
        }
        continue;
      }
      fpipe=fdopen(hpipe, "r");
#endif
      continue;
    }
#endif
    if (c!='[' || pvar || fpipe || (inconfig==2) || (!findvars))
    {
      *p++=(char)c;
      if (c=='\n')
      { if (pvar==NULL)
        { curline++;
          if (wascont)
          { p-=2; /* "%\n" */
            wascont=0;
            continue;
          }
          *p=0;
        }
        return (int)(p-str);
      }
      if ((c=='%') && (pvar==NULL) && (inconfig==0))
        wascont=1;
      else
        wascont=0;
      if (incomment)
        p--;
      continue;
    }
    wascont=0;
    if (incomment) continue;
    /* set */
    varlen=0;
#ifdef HAVE_ENVIRON
    curvar=NULL;
#endif
    for (;;)
    { /* find matched var */
      c=getc(htpl);
      if (c==EOF)
      { if (tplout)
        { if (inconfig)
            fprintf(stderr, "Unexpected EOF in config %s!\n", curtplfname);
          else
            logwrite('!', "Unexpected EOF in template %s!\n", curtplfname);
        }
        *p=0;
        return (int)(p-str);
      }
      if (c=='\n')
      { curline++;
        if (tplout)
        { if (inconfig)
            fprintf(stderr, "Unexpected EOL in config %s line %d!\n",
                    curtplfname, curline);
          else
            logwrite('!', "Unexpected EOL in template %s, line %d!\n",
                     curtplfname, curline);
        }
        *p=0;
        return (int)(p-str);
      }
      if (c==']')
      { /* getvar */
        pvar=NULL;
#ifdef HAVE_ENVIRON
        if (curvar==NULL)
          break;
#else
        var[varlen]='\0';
#endif
        for (i=0; i<nsets; i++)
#ifdef HAVE_ENVIRON
        { if (strlen(set[i].var)!=varlen)
            continue;
          if (strnicmp(set[i].var, curvar, varlen)==0)
            break;
        }
#else
          if (stricmp(set[i].var, var)==0)
            break;
#endif
        if (i<nsets)
        { pvar=set[i].value;
          break;
        }
        for (i=0; i<nglobal; i++)
#ifdef HAVE_ENVIRON
        { if (strlen(global[i].var)!=varlen)
            continue;
          if (strnicmp(global[i].var, curvar, varlen)==0)
            break;
        }
#else
          if (stricmp(global[i].var, var)==0)
            break;
#endif
        if (i<nglobal)
        { pvar=global[i].value;
          break;
        }
#ifdef HAVE_ENVIRON
        for (pp=environ; *pp; pp++)
        { p1=strchr(*pp, '=');
          if (p1==NULL) continue;
          if ((unsigned long)p1-(unsigned long)(*pp)!=varlen)
            continue;
          if (strnicmp(*pp, curvar, varlen)==0)
            break;
        }
        if (pp)
          pvar=p1+1;
#else
        pvar=getenv(var);
#endif
        break;
      }
#ifdef HAVE_ENVIRON
      if ((curvar==NULL) && varlen)
        continue;
      for (i=0; i<nsets; i++)
      { if (strnicmp(set[i].var, curvar, varlen))
          continue;
        if (toupper(set[i].var[varlen])!=toupper(c))
          continue;
        varlen++;
        curvar=set[i].var;
        break;
      }
      if (i!=nsets) continue;
      for (i=0; i<nglobal; i++)
      { if (strnicmp(global[i].var, curvar, varlen))
          continue;
        if (toupper(global[i].var[varlen])!=toupper(c))
          continue;
        varlen++;
        curvar=global[i].var;
        break;
      }
      if (i!=nglobal) continue;
      for (pp=environ; *pp; pp++)
      { p1=strchr(*pp, '=');
        if (p1==NULL) continue;
        if (strnicmp(*pp, curvar, varlen))
          continue;
        if (toupper(pp[0][varlen])==toupper(c))
          break;
      }
      varlen++;
      curvar=*pp;
#else
      if (varlen>=sizeof(var)-1)
        continue;
      var[varlen++]=c;
#endif
    }
  }
}

#ifndef INSTALL
static boolean boolexpr(char *str)
{ char *p, *p1, *p2;
  boolean ret, inquote, relax;

  debug(10, "boolexpr('%s')", str);
  ret=TRUE;
  for (p=str; isspace(*p); p++);
  if (strnicmp(p, "not ", 4)==0)
  { ret=FALSE;
    for (p+=4; isspace(*p); p++);
  }
  inquote=FALSE;
  for (p1=p; *p1; p1++)
  { if (*p1=='\"')
    { if (*(p1-1)=='\\')
        continue;
      inquote =! inquote;
      continue;
    }
    if (!inquote)
      if (strncmp(p1, "==", 2)==0 || strncmp(p1, "=~", 2)==0)
        break;
  }
  if (*p1==0)
  { if (tplout)
      logwrite('!', "Bad @if expression in template %s, line %d: '%s'\n",
               curtplfname, curline, str);
    debug(1, "BoolExpr: incorrect expression, return %s", ret ? "TRUE" : "FALSE");
    return ret;
  }
  relax=(p1[1]=='~');
  *p1=0;
  for (p2=p1-1; isspace(*p2); *p2--=0);
  for (p1+=2; isspace(*p1); p1++);
  for (p2=p1+strlen(p1)-1; isspace(*p2); *p2--=0);
  if (relax ? cmpaddr(p, p1) : stricmp(p, p1))
    ret=!ret;
  debug(10, "BoolExpr: return %s", ret ? "TRUE" : "FALSE");
  return ret;
}
#endif

void setvar(char *var, char *value)
{ int i, j;

  debug(15, "setvar('%s', '%s')", var, value ? value : "NULL");
  /* find var */
  for (i=0; i<nsets; i++)
    if (stricmp(set[i].var, var)==0)
      break;
  if (i<nsets)
  { /* remove var */
    free(set[i].var);
    for (j=i; j<nsets-1; j++)
    { set[j].var=set[j+1].var;
      set[j].value=set[j+1].value;
    }
    nsets--;
  }
  if (value==NULL) value="";
  if (value[0]==0)
    if (getvar(value)==NULL)
      return;
  if (nsets==MAXSET)
  { if (inconfig)
      fputs("Too many variables!\n", stderr);
    else
      logwrite('!', "Too many variables!\n");
    return;
  }
  set[nsets].var=malloc(strlen(var)+strlen(value)+2);
  if (set[nsets].var==NULL)
  { if (inconfig)
      fputs("Not enough memory for variables!\n", stderr);
    else
      logwrite('!', "Not enough memory for variables!\n");
    return;
  }
  strcpy(set[nsets].var, var);
  set[nsets].value=set[nsets].var+strlen(var)+1;
  strcpy(set[nsets].value, value);
  nsets++;
  return;
}

void setglobal(char *var, char *value)
{ int i, j;

  debug(15, "setglobal('%s', '%s')", var, value ? value : "NULL");
  /* find var */
  for (i=0; i<nglobal; i++)
    if (stricmp(global[i].var, var)==0)
      break;
  if (i<nglobal)
  { /* remove var */
    free(global[i].var);
    for (j=i; j<nglobal-1; j++)
    { global[j].var=global[j+1].var;
      global[j].value=global[j+1].value;
    }
    nglobal--;
  }
  if (value==NULL) value="";
  if (value[0]==0)
    if (getvar(value)==NULL)
      return;
  if (nglobal==MAXGLOBAL)
  { if (inconfig)
      fputs("Too many variables!\n", stderr);
    else
      logwrite('!', "Too many variables!\n");
    return;
  }
  global[nglobal].var=malloc(strlen(var)+strlen(value)+2);
  if (global[nglobal].var==NULL)
  { if (inconfig)
      fputs("Not enough memory for variables!\n", stderr);
    else
      logwrite('!', "Not enough memory for variables!\n");
    return;
  }
  strcpy(global[nglobal].var, var);
  global[nglobal].value=global[nglobal].var+strlen(var)+1;
  strcpy(global[nglobal].value, value);
  nglobal++;
  return;
}

char *getvar(char *var)
{ int i;

  debug(15, "getvar('%s')", var);
  for (i=0; i<nsets; i++)
    if (stricmp(var, set[i].var)==0)
    { if (set[i].value[0]==0)
      { debug(15, "getvar: found empty local var, return NULL");
        return NULL;
      }
      debug(15, "getvar: found local var, return '%s'", set[i].value);
      return set[i].value;
    }
  for (i=0; i<nglobal; i++)
    if (stricmp(var, global[i].var)==0)
    { debug(15, "getvar: found global var, return '%s'", global[i].value);
      return global[i].value;
    }
  debug(15, "getvar: can't found, return getenv('%s')='%s'", var, getenv(var) ? getenv(var) : "NULL");
  return getenv(var);
}

#ifndef INSTALL
int templateline(char *str, unsigned size)
{ int r, i;
  char *p, *p1, *p2;

  for (;;)
  {
    if (intext)
    { r=gettextline(str, size);
      if (r) return r;
      intext=FALSE;
    }
    r=_templateline(str, size);
    debug(18, "TemplateLine: read line '%s'", str);
    if (r==0)
      return 0;
    if (cont)
    { if (strchr(str, '\n'))
      { if (cont==2)
        { /* in ctl line */
          cont=0;
          continue;
        }
        cont=0;
        if (condition)
        { debug(18, "TemplateLine: return it");
          return r;
        }
        continue;
      }
      /* line still continue, cont not changed */
      if (cont==2)
        continue;
      if (condition)
      { debug(18, "TemplateLine: return it");
        return r;
      }
      continue;
    }
    for (p=str; (*p==' ') || (*p=='\t'); p++);
    if (strchr(str, '\n')==NULL)
    { if (*p=='@')
        cont=2;
      else
        cont=1;
    }
    if (*p!='@')
    { if (condition)
      { debug(18, "TemplateLine: return it");
        return r;
      }
      else
        continue;
    }
    /* control line (started from '@') */
    mstrcpy(str, p);
    while ((str[1]==' ') || (str[1]=='\t'))
      mstrcpy(str+1, str+2);
    if (strnicmp(str+1, "if ", 3)==0)
    {
      if (iflevel==MAXIF)
      { if (tplout)
          logwrite('!', "Too many nested if in template %s!\n", curtplfname);
        continue;
      }
      iflevel++;
      ifstack[iflevel].inelse=FALSE;
      ifstack[iflevel].state=ifstack[iflevel].wastrue=boolexpr(str+4);
      condition = condition && ifstack[iflevel].state;
      debug(18, "TemplateLine: set condition to %s", condition ? "TRUE" : "FALSE");
      continue;
    }
    if ((strnicmp(str+1, "ifdef ", 6)==0) ||
        (strnicmp(str+1, "ifndef ", 7)==0))
    { char *p, *p1;
      if (iflevel==MAXIF)
      { if (tplout)
          logwrite('!', "Too many nested if in template %s!\n", curtplfname);
        continue;
      }
      for (p1=str+strlen(str)-1; isspace(*p1); *p1--='\0');
      for (p=str+7; isspace(*p); p++);
      if (*p=='\0')
      { logwrite('!', "Bad %s in template %s line %d ignored!\n",
                 str, curtplname, curline);
        continue;
      }
      iflevel++;
      ifstack[iflevel].inelse=FALSE;
      ifstack[iflevel].state=(getvar(p)!=NULL);
      if (tolower(str[3])=='n') /* ifndef */
        ifstack[iflevel].state=!ifstack[iflevel].state;
      ifstack[iflevel].wastrue=ifstack[iflevel].state;
      condition = condition && ifstack[iflevel].state;
      debug(18, "TemplateLine: set condition to %s", condition ? "TRUE" : "FALSE");
      continue;
    }
    if (strnicmp(str+1, "else", 4)==0)
    {
      if ((iflevel==-1) || ifstack[iflevel].inelse)
      { if (tplout)
          logwrite('!', "Misplaces @else in template %s line %d ignored!\n",
                   curtplfname, curline);
        continue;
      }
      ifstack[iflevel].inelse=TRUE;
      ifstack[iflevel].state=!ifstack[iflevel].wastrue;
      setcond;
      debug(18, "TemplateLine: set condition to %s", condition ? "TRUE" : "FALSE");
      continue;
    }
    if (strnicmp(str+1, "elsif ", 6)==0)
    {
      if ((iflevel==-1) || ifstack[iflevel].inelse)
      { if (tplout)
          logwrite('!', "Misplaces @elsif in template %s line %d ignored!\n",
                   curtplfname, curline);
        continue;
      }
      if (!ifstack[iflevel].wastrue)
        ifstack[iflevel].wastrue=ifstack[iflevel].state=boolexpr(str+7);
      else
        ifstack[iflevel].state=FALSE;
      setcond;
      debug(18, "TemplateLine: set condition to %s", condition ? "TRUE" : "FALSE");
      continue;
    }
    if (strnicmp(str+1, "endif", 5)==0)
    {
      if (iflevel==-1)
      { if (tplout)
          logwrite('!', "Misplaced @endif in template %s line %d ignored!\n",
                   curtplfname, curline);
        continue;
      }
      iflevel--;
      setcond;
      debug(18, "TemplateLine: set condition to %s", condition ? "TRUE" : "FALSE");
      continue;
    }
    if (!condition)
      continue;
    p=getvar("module");
    if (stricmp(str+1, "text\n")==0)
    { intext=TRUE;
      if (p && stricmp(p, "rel2fido")==0)
      {
        if (!washdr)
        { reset_text();
          while (gettextline(str, sizeof(str)));
        }
        washdr=FALSE;
      }
      else
        reset_text();
      continue;
    }
    if (p && stricmp(p, "rel2fido")==0 && stricmp(str+1, "header\n")==0)
    { intext=TRUE;
      washdr=TRUE;
      reset_text();
      continue;
    }
    if (strnicmp(str+1, "vars ", 5)==0)
    {
      for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
      for (p=str+5; isspace(*p); p++);
      if (stricmp(p, "yes")==0)
        findvars=TRUE;
      else if (stricmp(p, "no")==0)
        findvars=FALSE;
      else if (tplout)
        logwrite('!', "Incorrect @vars in template %s line %d ignored!\n",
                 curtplfname, curline);
      continue;
    }
    /* now only set leaves */
    if (strnicmp(str+1, "set ", 4)==0)
    {
      p=strchr(str, '\n');
      if (p) *p=0;
      p1=strchr(str+5, '=');
      if (p1==NULL)
      { if (tplout)
          logwrite('!', "Incorrect @set in template %s line %d ignored!\n",
                   curtplfname, curline);
        continue;
      }
      *p1=0;
      for (p=p1-1; isspace(*p); *p--='\0');
      for (p=str+5; isspace(*p); p++);
      /* now p - var name */
      for (p1++; isspace(*p1); p1++);
      if (*p1=='\"')
      { /* remove quote chars */
        for (p2=p1; (p2=strchr(p2+1, '\"'))!=NULL;)
          if (*(p2-1)!='\\')
            *p2--='\0';
        p1++;
      }
      setvar(p, p1);
      continue;
    }
  }
}
#endif /* INSTALL */

void closeall(void)
{ int i;

  for (i=0; i<sp; i++)
    fclose(farr[i]);
  close_tpl();
}

static int unspace(char *str)
{ char *p, *p1;
  int  r=0;

  while ((*str==' ') || (*str=='\t')) mstrcpy(str, str+1);
  for (p=str; *p && (!isspace(*p)) && (*p!='='); p++);
  for (p1=p; isspace(*p1); p1++);
  if (*p1!='=') p++;
  if (p!=p1)
  { mstrcpy(p, p1);
    r+=(int)(p1-p);
  }
  if (*p=='=')
  { p++;
    while (isspace(*p))
    { mstrcpy(p, p+1);
      r++;
    }
  }
  return r;
}

#ifdef UNIX
void setpath(char *fname)
{ char str[FNAME_MAX];
  char *p;

  if (strchr(fname, PATHSEP))
    return;
#if HAVE_GETPWUID && HAVE_GETEUID
  p=getpwuid(geteuid())->pw_dir;
  if (p)
  { debug(6, "Home of effective uid: %s", p);
    strcpy(str, p);
    addslash(str);
    strcat(str, "etc/");
    strcat(str, fname);
    if (access(str, 0)==0)
    { strcpy(fname, str);
      return;
    } else
      debug(6, "Cannot access file %s: %s", str, strerror(errno));
  }
#endif
#if defined(HAVE_GETUID) && defined(HAVE_GETEUID) && defined(HAVE_GETGID) && defined(HAVE_GETEGID)
  if (getuid()==geteuid() && getgid()==getegid())
#endif
  { 
    p=getenv("HOME");
    if (p)
    { strcpy(str, p);
      addslash(str);
      strcat(str, "etc/");
      strcat(str, fname);
      if (access(str, 0)==0)
      { strcpy(fname, str);
        return;
      }
    }
    getcwd(str, sizeof(str));
    addslash(str);
    strcat(str, fname);
    if (access(str, 0)==0)
    { strcpy(fname, str);
      return;
    }
  }
  strcpy(str, SYSCONFDIR "/");
  strcat(str, fname);
  if (access(str, 0)==0)
    strcpy(fname, str);
}
#else
void setpath(char *fname)
{ char *p;
  int  i;

  if (strpbrk(fname, "\\:"))
    return;
  /* if path not specified - to start dir */
  p=strrchr(myname, '\\');
  if (p==NULL) p=myname;
  else p++;
  i=(unsigned)p-(unsigned)myname;
  memmove(fname+i, fname, strlen(fname)+1);
  strncpy(fname, myname, i);
}
#endif

int configline(char *str, unsigned size)
{ int r;
  char *p;
#ifndef INSTALL
  char *p1, *p2;
  int  i;
#endif

  for (;;)
  {
    r=_templateline(str, size);
    if (r==0)
    { if (sp)
      { fclose(htpl);
        htpl=farr[--sp];
        curline=curlines[sp];
        continue;
      }
      return 0;
    }
    if (cont)
    { if (strchr(str, '\n'))
      { if (cont==2)
        { /* in ctl line */
          cont=0;
          continue;
        }
        cont=0;
        if (condition)
          return r;
        continue;
      }
      /* line still continue, cont not changed */
      if (cont==2)
        continue;
      if (condition)
        return r;
      continue;
    }
    if (inconfig)
      while ((str[0]==' ') || (str[0]=='\t'))
      { mstrcpy(str, str+1);
        r--;
      }
    if (strchr(str, '\n')==NULL)
      cont=2;
    if (str[0]=='#')
      continue;
    if (inconfig && strnicmp(str, "application", 11) == 0 && isspace(str[11]))
    { char *p;
      for (p=str+11; isspace(*p); p++);
      if (strnicmp(p, "lgate", 5) || !isspace(p[5]))
        continue; /* not our application */
      for(p+=5; isspace(*p); p++);
      mstrcpy(str, p);
    }
    for (p=str+strlen(str)-1; isspace(*p) && (p>str); *p--=0);
    if (isspace(*p)) *p=0;
    if (str[0]=='\0')
      continue;
#ifndef INSTALL
    if (inconfig==1)
    {
      if (strnicmp(str, "if ", 3)==0)
      {
        if (iflevel==MAXIF)
        { if (tplout)
            fputs("Too many nested if in config!\n", stderr);
          continue;
        }
        iflevel++;
        ifstack[iflevel].inelse=FALSE;
        ifstack[iflevel].state=ifstack[iflevel].wastrue=boolexpr(str+3);
        condition = condition && ifstack[iflevel].state;
        continue;
      }
      if ((strnicmp(str, "ifdef ", 6)==0) ||
          (strnicmp(str, "ifndef ", 7)==0))
      { char *p, *p1;
        if (iflevel==MAXIF)
        { if (tplout)
            logwrite('!', "Too many nested if in config!\n");
          continue;
        }
        for (p1=str+strlen(str)-1; isspace(*p1); *p1--='\0');
        for (p=str+6; isspace(*p); p++);
        if (*p=='\0')
        { logwrite('!', "Bad %s in config %s line %d ignored!\n",
                   str, curtplname, curline);
          continue;
        }
        iflevel++;
        ifstack[iflevel].inelse=FALSE;
        ifstack[iflevel].state=(getvar(p)!=NULL);
        if (tolower(str[2])=='n') /* ifndef */
          ifstack[iflevel].state=!ifstack[iflevel].state;
        ifstack[iflevel].wastrue=ifstack[iflevel].state;
        condition = condition && ifstack[iflevel].state;
        debug(18, "TemplateLine: set condition to %s", condition ? "TRUE" : "FALSE");
        continue;
      }
      if (strnicmp(str, "else", 4)==0)
      {
        if ((iflevel==-1) || ifstack[iflevel].inelse)
        { if (tplout)
            fprintf(stderr, "Misplaces else in config %s line %d ignored!\n",
                    curtplfname, curline);
          continue;
        }
        ifstack[iflevel].inelse=TRUE;
        ifstack[iflevel].state=!ifstack[iflevel].wastrue;
        setcond;
        continue;
      }
      if (strnicmp(str, "elsif ", 6)==0)
      {
        if ((iflevel==-1) || ifstack[iflevel].inelse)
        { if (tplout)
            fprintf(stderr, "Misplaces elsif in config %s line %d ignored!\n",
                    curtplfname, curline);
          continue;
        }
        if (!ifstack[iflevel].wastrue)
          ifstack[iflevel].wastrue=ifstack[iflevel].state=boolexpr(str+6);
        else
          ifstack[iflevel].state=FALSE;
        setcond;
        continue;
      }
      if (strnicmp(str, "endif", 5)==0)
      {
        if (iflevel==-1)
        { if (tplout)
            fprintf(stderr, "Misplaced endif in config %s line %d ignored!\n",
                    curtplfname, curline);
          continue;
        }
        iflevel--;
        setcond;
        continue;
      }
      if (!condition)
        continue;
      if (strnicmp(str, "vars ", 5)==0)
      {
        for (p=str+strlen(str)-1; isspace(*p); *p--='\0');
        for (p=str+5; isspace(*p); p++);
        if (stricmp(p, "yes")==0)
          findvars=TRUE;
        else if (stricmp(p, "no")==0)
          findvars=FALSE;
        else if (tplout)
          logwrite('!', "Incorrect 'vars' in config %s line %d ignored!\n",
                   curtplfname, curline);
        continue;
      }
      if (strnicmp(str, "set ", 4)==0)
      {
        p=strchr(str, '\n');
        if (p) *p=0;
        p1=strchr(str+4, '=');
        if (p1==NULL)
        { if (tplout)
            fprintf(stderr, "Incorrect set in config %s line %d ignored!\n",
                    curtplfname, curline);
          continue;
        }
        *p1=0;
        for (p=p1-1; isspace(*p); *p--='\0');
        for (p=str+4; isspace(*p); p++);
        /* now p - var name */
        for (p1++; isspace(*p1); p1++);
        if (*p1=='\"')
        { /* remove quote chars */
          for (p2=p1; (p2=strchr(p2+1, '\"'))!=NULL;)
            if (*(p2-1)!='\\')
              *p2--='\0';
          p1++;
        }
        setvar(p, p1);
        continue;
      }
    }
#endif
    if ((inconfig==1) ?
        (strnicmp(str, "include", 7)==0) :
        (strnicmp(str, "source", 6)==0))
    { if (sp==MAXINCL)
      { if (tplout)
          fputs("Too many nested include in config!\n", stderr);
        continue;
      }
      for (p=str+7; (*p==' ') || (*p=='\t'); p++);
      mstrcpy(str, p);
      setpath(str);
      strcpy(curtplname, str);
      farr[sp]=htpl;
      curlines[sp]=curline;
      sp++;
      htpl=myfopen(str, "r");
      if (htpl==NULL)
      { sp--;
        if (tplout)
          fprintf(stderr, "Can't open include file %s: %s!\n", str, strerror(errno));
        htpl=farr[sp];
      }
      curtplfname=strrchr(curtplname, PATHSEP);
      if (curtplfname)
        curtplfname++;
      else
        curtplfname=curtplname;
      curline=0;
      continue;
    }
    if (cont)
      cont=1;
    if (inconfig)
      r-=unspace(str);
    return r;
  }
}

char *mstrcpy(char *dest, const char *src)
{
  char *p;

  for (p=dest; (*p++=*src++););
  return dest;
}

