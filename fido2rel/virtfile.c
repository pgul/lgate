/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 18:47:19  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#if defined(HAVE_MALLOC_H)
#include <malloc.h>
#elif defined(HAVE_ALLOC_H)
#include <alloc.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "gate.h"

unsigned long msgsize;
static char *buf=NULL;

int virt_fprintf(VIRT_FILE *f, char *format, ...)
{
  va_list arg;

  va_start(arg, format);
#ifdef HAVE_SNPRINTF
  vsnprintf(buf, BUFSIZE-1,
#else
  vsprintf(buf,
#endif
           format, arg);
  va_end(arg);
  return virt_fputs(buf, f);
}

int virt_fputs(char *str, VIRT_FILE *f)
{ int i=0;

  while (*str)
    if (virt_putc(*str++, f)==EOF)
      return EOF;
    else
      i++;
  return i;
}

int virt_putc(char c, VIRT_FILE *f)
{
  if (f==NULL)
  { errno=EBADF;
    return EOF;
  }
#ifdef __MSDOS__
  if (f->file == NULL)
#else
  if (f->buf == NULL)
#endif
  { errno=EBADF;
    return EOF;
  }
  if (f->offbody && c=='\n')
    f->lines++;
  if (f->offbody==0 && f->waslf)
    if (c=='\n')
      f->offbody=f->curpos;
  f->waslf = (c=='\n');
  msgsize++;
#ifdef __MSDOS__
  f->curpos++;
  return putc(c, f->file);
#else
  if (f->curpos == f->bufsize)
  { void *newbuf;
    if ((newbuf = bufrealloc(f->buf, f->bufsize+=BUFSIZE)) == NULL)
    { errno=ENOMEM;
      freebuf(f->buf);
      f->buf = NULL;
      return EOF;
    }
    f->buf=newbuf;
  }
  bufcopy(f->buf, f->curpos++, &c, 1);
  return 1;
#endif
}

VIRT_FILE *virt_fopen(char *fname, char *flags)
{
  VIRT_FILE *f;

  f = malloc(sizeof(*f));
  if (f==NULL)
  { errno=ENOMEM;
    return NULL;
  }
  if (buf==NULL)
    buf=malloc(BUFSIZE);
  if (buf==NULL)
  { free(f);
    errno=ENOMEM;
    return NULL;
  }
  f->curpos=f->offbody=msgsize=f->lines=f->waslf=0;
#ifdef __MSDOS__
  f->file = fopen(fname, flags);
  if (f->file==NULL)
  { free(f);
    return NULL;
  }
  strncpy(f->fname, fname, sizeof(f->fname));
#else
  f->buf=createbuf(BUFSIZE);
  if (f->buf==NULL)
  { free(f);
    errno=ENOMEM;
    return NULL;
  }
  f->bufsize=BUFSIZE;
#endif
  return f;
}

int virt_fclose(VIRT_FILE *f)
{
  if (f==NULL)
  { errno=EBADF;
    return EOF;
  }
#ifdef __MSDOS__
  if (f->file==NULL)
#else
  if (f->buf==NULL)
#endif
  { errno=EBADF;
    return EOF;
  }
#ifdef __MSDOS__
  fclose(f->file);
  unlink(f->fname);
#else
  free(f->buf);
#endif
  free(f);
  return 0;
}

int virt_rewind(VIRT_FILE *f)
{
  if (f==NULL)
  { errno=EBADF;
    return EOF;
  }
#ifdef __MSDOS__
  if (f->file==NULL)
#else
  if (f->buf==NULL)
#endif
  { errno=EBADF;
    return EOF;
  }
  sprintf(buf, "Content-Length: %lu\nLines: %lu\n",
          msgsize-f->offbody, f->lines);
  msgsize+=strlen(buf);
#ifdef __MSDOS__
  rewind(f->file);
#endif
  f->curpos=0;
  return 0;
}

int virt_getc(VIRT_FILE *f)
{
  if (f==NULL)
  { errno=EBADF;
    return EOF;
  }
#ifdef __MSDOS__
  if (f->file==NULL)
#else
  if (f->buf==NULL)
#endif
  { errno=EBADF;
    return EOF;
  }
  if (f->curpos>=msgsize)
    return EOF;
  if (f->curpos<f->offbody)
#ifdef __MSDOS__
  { f->curpos++;
    return getc(f->file);
  }
#else
    return getbuflem(f->buf, f->curpos++);
#endif
  if (f->curpos<f->offbody+strlen(buf))
    return buf[(int)(f->curpos++-f->offbody)];
#ifdef __MSDOS__
  f->curpos++;
  return getc(f->file);
#else
  return getbuflem(f->buf, f->curpos++-strlen(buf));
#endif
}

int virt_fgets(char *str, size_t sizestr, VIRT_FILE *f)
{ int i=0, c;

  for (i=0; i+1<sizestr;)
  {
    if ((c=virt_getc(f))==EOF)
      break;
    str[i++]=(char)c;
    if (c=='\n') break;
  }
  str[i]='\0';
  return i;
}
