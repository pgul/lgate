/* uudecode [input]
 *
 * create the specified file, decoding as you go.
 * used with uuencode.
 */
/* modified by boris@innonyc.com
   modefied by gul@lucky.net
*/
/*
 * $Id$
 *
 * $Log$
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

/* single-character decode */
#define DEC(c)		 (((c) - ' ') & 077)
#define index(str,c)	 strchr(str,c)
#define updatesum(sum,c) sum = ((sum >> 1) & 0x7FFF) + ((sum << 15) & 0x8000u) + (char)c;
static int decode( FILE * in, FILE * out, unsigned short *sum);
static int outdec(char * p, FILE * f, int n, unsigned short *sum);

int do_uudecode(char *infile, char *outfile)
{
  FILE *in, *out;
  char buf[80];
  int  r, i;
  unsigned short sum=0, fsum;
  long flen;

  if (infile[0] == '\0')
    in = stdin;
  else if ((in = fopen(infile, "r")) == NULL) 
  { logwrite('?', "Can't open %s: %s!\n", infile, strerror(errno));
    return 4;
  }
  do
  { if (fgets(buf, sizeof buf, in) == NULL)
    { /* No begin line */
      if (in!=stdin) fclose(in);
      return 3;
    }
  } while(strncmp(buf, "begin ", 6) != 0);
  /*
  sscanf(buf, "begin %*o %s", outfile);
  */

  /* create output file */
  r=open(outfile, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
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
    close(r);
    unlink(outfile);
    if (in!=stdin) fclose(in);
    else if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
    flock(r, LOCK_UN);
    return 3;
  }
  r=decode(in, out, &sum);
  fflush(out);
  flock(fileno(out), LOCK_UN);

  if (fgets(buf, sizeof buf, in) == NULL || strcmp(buf, "end\n")) 
  {
    /* No end line */
    if (in!=stdin) fclose(in);
    else if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
    fclose(out);
    return 5;
  }
  /* checksum? */
  while (fgets(buf, sizeof(buf), in))
  { if (strncmp(buf, "sum -r/size ", 12)) continue;
    if (strstr(buf, " entire input file")==NULL) continue;
    if (sscanf(buf+12,"%hu/%lu", &fsum, &flen)!=2) continue;
    if ((fsum!=sum) || (flen!=ftell(out)))
    { logwrite('?', "uucode checksum error!\n");
      fclose(out);
      unlink(outfile);
      if (in!=stdin) fclose(in);
      else if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
      return 6;
    }
    else
    { debug(2, "uucode checksum ok");
      if (!isfile(fileno(in))) while (fgets(buf, sizeof(buf), in));
    }
  }
  fclose(out); 
  if (in!=stdin) fclose(in);
  return r;
}

/*
 * copy from in to out, decoding as you go along.
 */
static int decode(FILE *in, FILE *out, unsigned short *sum)
{
	char buf[80];
	char *bp;
	int n, i, expected;

	for (;;) {
		/* for each input line */
		if (fgets(buf, sizeof buf, in) == NULL) {
			/* Short file */
			return 6;
		}
		if (buf[0] == '\n')
			continue;
		n = DEC(buf[0]);
		if (n <= 0)
			break;

		/* Calculate expected # of chars and pad if necessary */
		expected = ((n+2)/3)<<2;
		if (expected >= sizeof(buf))
		{	debug(7, "Expected=%d, too many", expected);
			return 6;
		}
		for (i = strlen(buf)-1; i <= expected; i++) buf[i] = ' ';

		bp = &buf[1];
		while (n > 0) {
			if (outdec(bp, out, n, sum))
				return 7;
			bp += 4;
			n -= 3;
		}
	}
    return 0;
}

/*
 * output a group of 3 bytes (4 input characters).
 * the input chars are pointed to by p, they are to
 * be output to file f.  n is used to tell us not to
 * output all of them at the end of the file.
 */
static int outdec(char *p, FILE *f, int n, unsigned short *sum)
{
	int c1, c2, c3;
	int r=0;

	c1 = (DEC(*p) << 2) | (DEC(p[1]) >> 4);
	c2 = (DEC(p[1]) << 4) | (DEC(p[2]) >> 2);
	c3 = (DEC(p[2]) << 6) | (DEC(p[3]));
	if (n >= 1)
	{	updatesum(*sum, c1);
		r=putc(c1, f);
	}
	if (n >= 2)
	{	updatesum(*sum, c2);
		r=putc(c2, f);
	}
	if (n >= 3)
	{	updatesum(*sum, c3);
		r=putc(c3, f);
	}
	if (r==EOF)
	{	logwrite('?', "Can't write to file: %s!\n", strerror(errno));
		return 8;
	}
	return 0;
}
