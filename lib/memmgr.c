/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:50:59  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <mem.h>
#include "libgate.h"

#undef NOEMS

#define EMSDEVICE    "EMMXXXX0"
#define PAGESIZE     0x4000l
#define PAGES        4

typedef struct
{  enum { CMM, EMM, XMM } memtype;
   unsigned int frame, bank, page; /* in K */
   long size;
   char far * addr;
} memhdr;

static char cbuf[1024];
static int emsstate[PAGES] = {-1, -1, -1, -1};

long getfreemem(void)
{
  int h;
  long l=0;

#ifndef NOEMS
  h=open(EMSDEVICE,O_BINARY|O_RDONLY);
  if (h!=-1)
  { close(h);
    _AH=0x42;
    geninterrupt(0x67);
    if (_AH==0)
    { h=_BX;
      l=h*PAGESIZE;
    }
  }
  if (l<farcoreleft())
#endif
    return farcoreleft();
  return l;
}

char *createbuf(long size)
{
  int volatile h, i;
  memhdr *hdr;

  hdr=malloc(sizeof(memhdr));
  if (hdr==NULL)
  { debug(4, "Createbuf: no memory for buffer header");
    return NULL;
  }
#ifndef NOEMS
  /* 1. Try EMS */
  h=open(EMSDEVICE,O_BINARY|O_RDONLY);
  if (h!=-1)
  { close(h);
    /* Get seg */
    _AH=0x41;
    geninterrupt(0x67);
    if (_AH==0)
    { h=_BX;
      hdr->frame=h;
      for (i=0; i<PAGES; i++)
        if (emsstate[i]==-1)
          break;
      if (i==PAGES) i=0;
      hdr->page=i;
      hdr->frame+=(unsigned)(i*(PAGESIZE/0x10));
      /* делаем ALLOC */
      _BX=(unsigned)((size-1+PAGESIZE)/PAGESIZE);
      _AH=0x43;
      geninterrupt(0x67);
      if (_AH==0)
      { /* allocated */
        h=_DX;
        (unsigned)hdr->addr=h;
        _DX=h;
        /* Отображаем */
        _BX=0;
        _AL=i;
        _AH=0x44;
        geninterrupt(0x67);
        h=_AH;
        if (h==0)
        { hdr->bank=0;
          hdr->memtype=EMM;
          hdr->size=size;
          emsstate[i]=(unsigned)hdr->addr;
          debug(7, "Createbuf: allocated %ld bytes of EMM (addr=0x%04X)", size, (unsigned)hdr->addr);
          return (char *)hdr;
        }
        _DX=(unsigned)hdr->addr;
        _AH=0x45;
        geninterrupt(0x67); /* free */
      }
    }
    debug(7, "Createbuf: EMM alloc failed");
  }
  else
    debug(7, "No EMM available");
#endif
  hdr->memtype=CMM;
  hdr->addr=farmalloc(size);
  hdr->size=size;
  if (hdr->addr==NULL)
  { free(hdr);
    hdr=NULL;
    debug(4, "Createbuf: allocation %ld bytes failed", size);
  }
  else
    debug(7, "Createbuf: allocated %ld bytes (addr=%lp)", size, hdr->addr);
  return (char *)hdr;
}

static void setbank(memhdr *hdr, int bank)
{
  char volatile page=(char)hdr->page;
  if ((hdr->bank==bank) && (emsstate[page]==(unsigned)hdr->addr))
    return;
  _DX=(unsigned)hdr->addr;
  _BX=bank;
  _AH=0x44;
  _AL=page;
  geninterrupt(0x67);
  hdr->bank=bank;
  emsstate[page]=(unsigned)hdr->addr;
}

void freebuf(char *buf)
{ 
  memhdr *hdr;
  int i;

  hdr=(memhdr*)buf;
  if (hdr==NULL) return;
  if (hdr->memtype==EMM)
  { _DX=(unsigned)(hdr->addr);
    _AH=0x45;
    geninterrupt(0x67);
  }
  else if (hdr->memtype==CMM)
    farfree(hdr->addr);
  for (i=0; i<PAGES; i++)
    if (emsstate[i]==(unsigned)(hdr->addr))
      emsstate[i]=-1;
  free(hdr);
}

char getbuflem(char *buf, long index)
{
  char c;
  frombuf(&c, buf, index, 1);
  return c;
}

void bufcopy(char *buf, long offs, char *from, int size)
{
  memhdr *hdr;

  hdr=(memhdr*)buf;
  if (hdr->memtype==CMM)
  { if (size==1)
      *((char huge *)(hdr->addr)+offs)=*from;
    else
      memcpy((char *)((char huge *)(hdr->addr)+offs), from, size);
    return;
  }
  if (hdr->memtype==EMM)
  { int bank, loffs, lsize;

    while (size>0)
    { bank=(int)(offs/PAGESIZE);
      setbank(hdr, bank);
      loffs=(int)(offs-bank*PAGESIZE);
      lsize=(int)(PAGESIZE-loffs);
      if (lsize>size) lsize=size;
      if (size==1)
      { *(char far *)MK_FP(hdr->frame, loffs)=*from;
        return;
      }
      movedata(FP_SEG(from), FP_OFF(from), hdr->frame, loffs, lsize);
      size-=lsize;
      from+=lsize;
      offs+=lsize;
    }
  }
}

void frombuf(char *dest, char *buf, long offs, int size)
{
  memhdr *hdr;

  hdr=(memhdr*)buf;
  if (hdr->memtype==CMM)
  { if (size==1)
      *dest=*((char huge *)(hdr->addr)+offs);
    else
      memcpy(dest, (char *)((char huge *)(hdr->addr)+offs), size);
    return;
  }
  if (hdr->memtype==EMM)
  { int bank, loffs, lsize;

    while (size>0)
    { bank=(int)(offs/PAGESIZE);
      setbank(hdr, bank);
      loffs=(int)(offs-bank*PAGESIZE);
      lsize=(int)(PAGESIZE-loffs);
      if (lsize>size) lsize=size;
      if (size==1)
      { *dest=*(char far *)MK_FP(hdr->frame, loffs);
        return;
      }
      else
        movedata(hdr->frame, loffs, FP_SEG(dest), FP_OFF(dest), lsize);
      size-=lsize;
      dest+=lsize;
      offs+=lsize;
    }
  }
}

int writebuf(char *buf, long buflen, FILE *fout)
{
  long l;

  for (l=0; l<buflen-sizeof(cbuf); l+=sizeof(cbuf))
  { frombuf(cbuf, buf, l, sizeof(cbuf));
    if (fwrite(cbuf, sizeof(cbuf), 1, fout)!=1)
      return -1;
  }
  frombuf(cbuf, buf, l, (int)(buflen-l));
  if (fwrite(cbuf, (int)(buflen-l), 1, fout)!=1)
    return -1;
  return 0;
}

char *bufrealloc(char *buf, long newsize)
{
  memhdr *hdr;
  char *newbuf;
  int h;
  long l;

  hdr=(memhdr *)buf;

  if (hdr->memtype==CMM)
  { char far *p=farrealloc(hdr->addr, newsize);
    if (p)
    { debug(7, "bufrealloc: reallocated %lp to %lp (%ld bytes)", hdr->addr, p, newsize);
      hdr->addr=p;
      return buf;
    }
hardrealloc:
    newbuf=createbuf(newsize);
    if (newbuf==NULL) return NULL;
    if (newsize>hdr->size) newsize=hdr->size;
    for (l=0; l<newsize; l+=sizeof(cbuf))
    { frombuf(cbuf, buf, l, sizeof(cbuf));
      bufcopy(newbuf, l, cbuf, sizeof(cbuf));
    }
    frombuf(cbuf, buf, l, (int)(newsize-l));
    bufcopy(newbuf, l, cbuf, (int)(newsize-l));
    freebuf(buf);
    return newbuf;
  }
  if (hdr->memtype==EMM)
  {
    if ((newsize-1+PAGESIZE)/PAGESIZE==(hdr->size-1+PAGESIZE)/PAGESIZE)
      return buf;
    h=(int)((newsize-1+PAGESIZE)/PAGESIZE);
    _DX=(unsigned)hdr->addr;
    _BX=h;
    _AX=0x5100;
    geninterrupt(0x67);
    if ((h=_AH)!=0)
    { debug(7, "bufrealloc: can't realloc EMS buf 0x%04X to %ld bytes (EMM status 0x%02X)", (unsigned)hdr->addr, newsize, h);
      goto hardrealloc;
    }
    hdr->size=newsize;
    debug(7, "bufrealloc: EMS buffer 0x%04X reallocated to %ld bytes", (unsigned)hdr->addr, newsize);
    return buf;
  }
  return NULL;
}

long bufwrite(int h, char *buf, long buflen)
{
  long l;

  for (l=0; l<buflen-sizeof(cbuf); l+=sizeof(cbuf))
  { frombuf(cbuf, buf, l, sizeof(cbuf));
    if (write(h, cbuf, sizeof(cbuf))!=sizeof(cbuf))
      return -1;
  }
  frombuf(cbuf, buf, l, (int)(buflen-l));
  if (write(h, cbuf, (int)(buflen-l))!=buflen-l)
    return -1;
  return buflen;
}
