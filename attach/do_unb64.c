/* modified by boris@innonyc.com
   modified by gul@lucky.net
*/
/*
 * $Id$
 *
 * $Log$
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

int do_unmime(char *infile, char *outfile, int decode(FILE *, FILE *));
static int decode_b64(FILE *in, FILE *out);
static int decode_qp(FILE *in, FILE *out);
static char buf[128];

int do_unbase64(char *infile, char *outfile)
{ return do_unmime(infile, outfile, decode_b64);
}

int do_unqp(char *infile, char *outfile)
{ return do_unmime(infile, outfile, decode_qp);
}

int do_unmime(char *infile, char *outfile, int decode(FILE *, FILE *))
{
  FILE *in, *out;
  int  i, r;

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
  for (r=0; (i=fgetc(in))!=EOF; r=i)
    if (i=='\n' && r=='\n') break;
  if (i!=EOF && boundary[0])
  { int inparthdr=0;
    char *p;

    while (fgets(str, sizeof(str), in))
    { if (strcmp(str, "\n")==0)
      { if (inparthdr==2) break;
        inparthdr=0;
        continue;
      }
      if (str[0]=='-' && str[1]=='-' &&
          strncmp(str+2, boundary, strlen(boundary))==0 &&
          str[strlen(boundary)+2]=='\n')
      { inparthdr=1;
        continue;
      }
      if (!inparthdr) continue;
      if (strncmp(str, "Content-Transfer-Encoding:", 26))
        continue;
      for (p=str+26; isspace(*p); p++);
      if (strnicmp(p, "base64", 6) && strnicmp(p, "quoted-printable", 16))
        continue;
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
      logwrite('?', "Incorrect %s-coding\n", (decode==decode_b64 ? "base64" : "qp"));
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
  int c;
  char s[3];

  for (;;)
  { c = fgetc(in);
gotqpbyte:
    if (c==EOF) return 0;
    if (c=='\n')
    { if (fputc('\r', out)==EOF) return 3;
    } else if (c=='\r')
    { if (fputc(c, out)==EOF) return 3;
      c = fgetc(in);
      if (c != '\n')
        goto gotqpbyte;
    }
    if (c!='=')
    { if (fputc(c, out)==EOF) return 3;
      continue;
    }
    c=fgetc(in);
    if (c==EOF) return 2;
    if (c=='\r')
    { c=fgetc(in);
      if (c!='\n') return 2;
      continue;
    }
    if (c=='\n') continue;
    if (!isxdigit(c)) return 2;
    s[0]=c;
    c=fgetc(in);
    if (c==EOF) return 2;
    if (!isxdigit(c)) return 2;
    s[1]=c;
    s[2]='\0';
    if (fputc(strtol(s, NULL, 16), out)==EOF) return 3;
  }
}
