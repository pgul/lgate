/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:15  gul
 * We are under CVS for now
 *
 */
/* base64 encoding
   modified by boris@innonyc.com
   modified by gul@lucky.net
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include "gate.h"

/* ENC is the basic 1-character encoding function to make a char printing */
#define ENC(c) arr_base64[c]
static int  outdec(char * p, FILE * f );
static int  encode(FILE *in, FILE *out);

static char arr_base64[64]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/";

int do_base64(char *infile, FILE *out)
{
  FILE *in;
  int  r;

  r=open(infile, O_BINARY|O_RDONLY);
  if (r==-1)
  { logwrite('?', "Can't open %s: %s!\n", infile, strerror(errno));
    return 3;
  }
  if ((in = fdopen(r, "rb")) == NULL)
  { logwrite('?', "Can't open %s: %s!\n", infile, strerror(errno));
    return 3;
  }

  r=encode(in, out);

  fclose(in);
  return r;
}

/*
 * copy from in to out, encoding as you go along.
 */
static int encode(FILE *in, FILE *out)
{
  char buf[80];
  int  i, n, c;

  for (;;)
  {
    /* 1 (up to) 45 character line */
    n = fread(buf, 1, 45, in);

    for (i=0; i<n-2; i+=3)
      if (outdec(&buf[i], out))
      {
errwrite:
        logwrite('?', "Can't write to file: %s!\n",
                 (errno>=0) ? strerror(errno) : "reason unknown");
        return 7;
      }
    if (n<45)
      break;
    if (putc('\n', out)==EOF)
      goto errwrite;
  }
  if (n)
  { if (i<n)
    { buf[n]=0;
      c = buf[i] >> 2;
      if (putc(ENC(c), out)==EOF) goto errwrite;
      c = ((buf[i] << 4) & 060) | ((buf[i+1] >> 4) & 017);
      if (putc(ENC(c), out)==EOF) goto errwrite;
      i++;
      if (i<n)
      { c = ((buf[i] << 2) & 074) | ((buf[i+1] >> 6) & 03);
        if (putc(ENC(c), out)==EOF) goto errwrite;
      }
      else
        if (putc('=', out)==EOF) goto errwrite;
      if (putc('=', out)==EOF) goto errwrite;
    }
    if (putc('\n', out)==EOF) goto errwrite;
  }
  return 0;
}

void str_base64(char *in, char *out, int len)
{
  for (;len>=3; len-=3, in+=3)
  {
    *out++ = ENC(*in>>2);
    *out++ = ENC(((*in << 4) & 060) | ((in[1] >> 4) & 017));
    *out++ = ENC(((in[1] << 2) & 074) | ((in[2] >> 6) & 03));
    *out++ = ENC(in[2] & 077);
  }
  if (len)
  { *out++ = ENC(*in >> 2);
    if (len>1)
    { *out++ = ENC(((*in << 4) & 060) | ((in[1] >> 4) & 017));
      *out++ = ENC((in[1] << 2) & 074);
    }
    else
    { *out++ = ENC((*in << 4) & 060);
      *out++ = '=';
    }
    *out++ = '=';
  }
  *out++ = '\0';
}


/*
 * output one group of 3 bytes, pointed at by p, on file f.
 */
static int outdec(char *p, FILE *f)
{
  register int c;

  c = *p >> 2;
  if (putc(ENC(c), f)==EOF) return 2;
  c = ((*p << 4) & 060) | ((p[1] >> 4) & 017);
  if (putc(ENC(c), f)==EOF) return 2;
  c = ((p[1] << 2) & 074) | ((p[2] >> 6) & 03);
  if (putc(ENC(c), f)==EOF) return 2;
  c = p[2] & 077;
  if (putc(ENC(c), f)==EOF) return 2;
  return 0;
}
