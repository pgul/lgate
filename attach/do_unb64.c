/* modified by boris@innonyc.com
   modified by gul@lucky.net
*/
/*
 * $Id$
 *
 * $Log$
 * Revision 2.7  2004/07/20 18:29:25  gul
 * \r\n -> \n
 *
 * Revision 2.6  2001/07/26 12:48:55  gul
 * 7bit- and 8bit-encoded attaches bugfix
 *
 * Revision 2.5  2001/07/20 21:43:26  gul
 * Decode attaches with 8bit encoding
 *
 * Revision 2.4  2001/07/20 21:22:52  gul
 * multipart/mixed decode cleanup
 *
 * Revision 2.3  2001/07/20 16:13:26  gul
 * q-p decode bugfix
 *
 * Revision 2.2  2001/07/20 15:06:11  gul
 * error processing cleanup
 *
 * Revision 2.1  2001/07/20 14:55:22  gul
 * Decode quoted-printable attaches
 *
 * Revision 2.0  2001/01/10 20:42:16  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <ctype.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "gate.h"

#include "cunb64.h"

/* single-character decode */
#define DEC(c)		cunbase64[c]

int do_unmime(char *infile, char *outfile, int decodepart, char *encoding, int decode(FILE *, FILE *));
static int decode_b64(FILE *in, FILE *out);
static int decode_qp(FILE *in, FILE *out);
static int decode_8bit(FILE *in, FILE *out);
static char buf[128];

int do_unbase64(char *infile, char *outfile, int decodepart)
{ return do_unmime(infile, outfile, decodepart, "base64", decode_b64);
}

int do_unqp(char *infile, char *outfile, int decodepart)
{ return do_unmime(infile, outfile, decodepart, "quoted-printable", decode_qp);
}

int do_un8bit(char *infile, char *outfile, int decodepart)
{ return do_unmime(infile, outfile, decodepart, "8bit", decode_8bit);
}

int do_un7bit(char *infile, char *outfile, int decodepart)
{ return do_unmime(infile, outfile, decodepart, "7bit", decode_8bit);
}

int do_unmime(char *infile, char *outfile, int decodepart, char *encoding, int decode(FILE *, FILE *))
{
  FILE *in, *out;
  int  i, r, npart;

  if (infile[0] == '\0')
    in = stdin;
  else if ((in = fopen(infile, "r")) == NULL)
  { logwrite('?', "Can't open %s: %s!\n", infile, strerror(errno));
    return 4;
  }

  /* create output file */
  r=open(outfile, O_BINARY|O_RDWR|O_CREAT|O_EXCL, 0666);
  if (r==-1)
  { logwrite('?', "Can't open %s: %s!\n", outfile, strerror(errno));
    if (in!=stdin) fclose(in);
    else if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
    return 3;
  }
  for (i=0; i<5; i++)
    if (flock(r, LOCK_EX|LOCK_NB))
      sleep(1);
    else
      break;
  if (i==5)
  { logwrite('?', "Can't flock %s: %s!\n", outfile, strerror(errno));
    close(r);
    unlink(outfile);
    if (in!=stdin) fclose(in);
    else if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
    return 3;
  }
  out = fdopen(r, "wb");
  if (out == NULL)
  { logwrite('?', "Can't open %s: %s!\n", outfile, strerror(errno));
    flock(r, LOCK_UN);
    close(r);
    unlink(outfile);
    if (in!=stdin) fclose(in);
    else if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
    return 3;
  }
  /* skip header */
  npart=0;
  for (r=0; (i=fgetc(in))!=EOF; r=i)
    if (i=='\n' && r=='\n') break;
  if (i!=EOF && boundary[0])
  { int inparthdr=0, wasenc=0;
    char *p;

    while (fgets(str, sizeof(str), in))
    { if (strcmp(str, "\n")==0)
      { if (inparthdr==2 && !wasenc && encoding[0]!='7')
        /* matched part number but unmatched (missing) encoding */
          inparthdr=1;
        if (inparthdr==2) break;
        inparthdr=0;
        continue;
      }
      if (str[0]=='-' && str[1]=='-' &&
          strncmp(str+2, boundary, strlen(boundary))==0 &&
          str[strlen(boundary)+2]=='\n')
      { inparthdr=1;
        wasenc=0;
        npart++;
        if (npart==decodepart)
          inparthdr=2;
        continue;
      }
      if (!inparthdr) continue;
      if (strncmp(str, "Content-Transfer-Encoding:", 26))
        continue;
      wasenc=1;
      for (p=str+26; isspace(*p); p++);
      if (strnicmp(p, encoding, strlen(encoding)))
      { inparthdr=1;
        continue;
      }
      if (decodepart==0)
        inparthdr=2;
    }
    if (inparthdr!=2) i=EOF;
  }

  /* decode */
  if (i!=EOF)
    r=decode(in, out);
  else
    r=4;

  if (fflush(out)) r=3;
  flock(fileno(out), LOCK_UN);
  if (fclose(out)) r=3;
  if (in!=stdin) fclose(in);
  else if (!isfile(fileno(in)))
    while (fgets(buf, sizeof(buf), in));
  if (r)
  { unlink(outfile);
    if (r==3) /* error write */
      logwrite('?', "Can't write file %s: %s\n", outfile, strerror(errno));
    else if (r<3)
      logwrite('?', "Incorrect %s-coding\n", encoding);
  }
  return r;
}

/*
 * copy from in to out, decoding as you go along.
 */
static int decode_b64(FILE *in, FILE *out)
{
  char c[4];
  int  was_decode=0;
  int  i, n, bound=0;

  for (;;)
  {
    for (n=0; n<4; n++)
    { i=fgetc(in);
      if (i==EOF || i==0x1a)
      { if (was_decode && (n==0))
          return 0;
        else
          return 1; /* nothing to decode */
      }
      if (isspace(i))
      { n--;
        if (i=='\n') bound=1;
        else bound=0;
        continue;
      }
      c[n]=DEC(i);
      if (c[n]>64)
      { if (i=='-' && bound==1 && boundary[0] && was_decode && n==0)
          return 0;
        return 2; /* incorrect character */
      }
      bound=0;
    }
    was_decode=1;
    if ((c[0]==64) || (c[1]==64))
      return 2;
    if (putc((c[0]<<2) | (c[1]>>4), out)==EOF)
    {
errwrite:
      return 3;
    }
    if (c[2]==64)
    { if (c[3]==64)
        break;
      else
        return 2;
    }
    if (putc((c[1]<<4) | (c[2]>>2), out)==EOF)
      goto errwrite;
    if (c[3]==64)
      break;
    if (putc((c[2]<<6) | c[3], out)==EOF)
      goto errwrite;
  }
  /* pad occured */
  for (;;)
  { i=fgetc(in);
    if (i==EOF)
      return 0;
    if (!isspace(i))
    { if (i=='-' && bound==1 && boundary[0])
        return 0;
      else
        return 2;
    }
    if (i=='\n') bound=1;
    else bound=0;
  }
}

int str_unbase64(char *in, char *out)
{
  char c[4];
  int  was_decode=0;
  int  i, n, len=0;

  for (;;)
  {
    for (n=0; n<4; n++)
    { i=*in++;
      if (i=='\0')
      { if (was_decode && (n==0))
          return len;
        else
          return -1; /* nothing to decode */
      }
      if (isspace(i))
      { n--;
        continue;
      }
      c[n]=DEC(i);
      if (c[n]>64)
        return -2; /* incorrect character */
    }
    was_decode=1;
    if ((c[0]==64) || (c[1]==64))
      return -2;
    out[len++]=(c[0]<<2) | (c[1]>>4);
    if (c[2]==64)
    { if (c[3]==64)
        break;
      else
        return -2;
    }
    out[len++]=(c[1]<<4) | (c[2]>>2);
    if (c[3]==64)
      break;
    out[len++]=(c[2]<<6) | c[3];
  }
  /* pad occured */
  for (;;)
  { i=*in++;
    if (i==0)
      return len;
    if (!isspace(i))
      return -2;
  }
}

static int decode_qp(FILE *in, FILE *out)
{
  int c, lastc=0;
  char s[4];
  int bmatch=0;
  char *pbound=NULL;

  s[0]='\0';
  for (;;)
  { if (pbound)
    { 
      if (pbound+4-boundary==bmatch)
      { bmatch=0;
        pbound=NULL;
        c=lastc;
      }
      else if (pbound==boundary-4)
        c='\r';
      else if (pbound==boundary-3)
        c='\n';
      else if (pbound==boundary-2)
        c='-';
      else if (pbound==boundary-1)
        c='-';
      else
        c=*pbound;
      if (pbound) pbound++;
    } else
    { c = fgetc(in);
      if (c=='\r' && bmatch==0)
      { bmatch=1;
        continue;
      }
      if (c=='\n' && bmatch<=1)
      { bmatch=2;
        continue;
      }
      if (c=='-' && (bmatch==2 || bmatch==3))
      { bmatch++;
        continue;
      }
      if (bmatch && boundary[0]=='\0')
      { lastc=c;
        pbound=boundary-4;
        continue;
      }
      if (bmatch==strlen(boundary)+4)
      { if (c=='\r' || c=='-') continue;
        if (c=='\n') /* boundary matched! */
          return 0;
        lastc=c;
        pbound=boundary-4;
        continue;
      }
      if (bmatch>=4)
      { if (c==boundary[bmatch-4])
        { bmatch++;
        } else
        { lastc=c;
          pbound=boundary-4;
        }
        continue;
      }
      if (bmatch)
      { lastc=c;
        pbound=boundary-4;
        continue;
      }
    }
    if (s[0])
    { if (isxdigit(c))
      { if (s[1])
        { if (!isxdigit(s[1])) return 2;
          s[2]=c;
          s[3]='\0';
          if (fputc(strtol(s+1, NULL, 16), out)==EOF) return 3;
          s[0]='\0';
          continue;
        }
        s[1]=c;
        s[2]='\0';
        continue;
      } else if (c=='\n' && s[1]=='\r')
      { s[0]='\0';
        continue;
      } else if (c=='\r' && s[1]=='\0')
      { s[1]=c;
        s[2]='\0';
        continue;
      } else
        return 2;
    }
    if (c==EOF) return 0;
    if (c!='=')
    { if (fputc(c, out)==EOF) return 3;
      continue;
    }
    s[0]=c;
    s[1]='\0';
  }
}

static int decode_8bit(FILE *in, FILE *out)
{
  /* find boundary, convert LF->CRLF */
  int c, lastc=0;
  int bmatch=0;
  char *pbound=NULL;

  for (;;)
  { if (pbound)
    { 
      if (pbound+4-boundary==bmatch)
      { bmatch=0;
        pbound=NULL;
        c=lastc;
      }
      else if (pbound==boundary-4)
        c='\r';
      else if (pbound==boundary-3)
        c='\n';
      else if (pbound==boundary-2)
        c='-';
      else if (pbound==boundary-1)
        c='-';
      else
        c=*pbound;
      if (pbound) pbound++;
    } else
    { c = fgetc(in);
      if (c=='\r' && bmatch==0)
      { bmatch=1;
        continue;
      }
      if (c=='\n' && bmatch<=1)
      { bmatch=2;
        continue;
      }
      if (c=='-' && (bmatch==2 || bmatch==3))
      { bmatch++;
        continue;
      }
      if (bmatch && boundary[0]=='\0')
      { lastc=c;
        pbound=boundary-4;
        continue;
      }
      if (bmatch==strlen(boundary)+4)
      { if (c=='\r' || c=='-') continue;
        if (c=='\n') /* boundary matched! */
          return 0;
        lastc=c;
        pbound=boundary-4;
        continue;
      }
      if (bmatch>=4)
      { if (c==boundary[bmatch-4])
        { bmatch++;
        } else
        { lastc=c;
          pbound=boundary-4;
        }
        continue;
      }
      if (bmatch)
      { lastc=c;
        pbound=boundary-4;
        continue;
      }
    }
    if (c==EOF) return 0;
    if (fputc(c, out)==EOF) return 3;
  }
  return 0;
}
