/* uuencode [input] output uuencode-produced-file
 * Encode a file so it can be mailed to a remote system.
 */
/* modified by boris@innonyc.com
   modified by gul@lucky.net
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
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include "gate.h"

/* ENC is the basic 1-character encoding function to make a char printing */
#define ENC(c) ((c) ? ((c) & 077) + ' ': '`')
static int  outdec(char *p, FILE *f);
static int  encode(FILE *in, FILE *out, unsigned short *sum);

int do_uuencode(char *infile, FILE *out)
{
  FILE *in;
  int  r;
  unsigned short sum=0;

  r=open(infile, O_BINARY|O_RDONLY);
  if (r==-1)
  { logwrite('?', "Can't open %s: %s!\n", infile, strerror(errno));
    return 3;
  }
  if ((in = fdopen(r, "rb")) == NULL)
  { logwrite('?', "Can't open %s: %s!\n", infile, strerror(errno));
    return 3;
  }

  fprintf(out, "begin %o %s\n", 0644, basename(infile));

  r=encode(in, out, &sum);

  fprintf(out, "end\n");
  fseek(in, 0, SEEK_END);
  fprintf(out, "sum -r/size %hu/%lu entire input file\n", sum, ftell(in));
  fclose (in);
  return r;
}

/*
 * copy from in to out, encoding as you go along.
 */
static int encode(FILE *in, FILE *out, unsigned short *sum)
{
	char buf[80];
	register int i, n;

	for (;;) {
		/* 1 (up to) 45 character line */
		n = fread(buf, 1, 45, in);
		for (i=0; i<n; i++)
			*sum = ((*sum >> 1) & 0x7FFF) + ((*sum << 15) & 0x8000u) + buf[i];
		if (putc(ENC(n), out)==EOF)
		{
errwrite:
		    logwrite('?', "Can't write to file: %s!\n",
		             (errno>=0) ? strerror(errno) : "reason unknown");
		    return 7;
		}

		for (i=0; i<n; i += 3)
			if (outdec(&buf[i], out))
				goto errwrite;

		if (putc('\n', out)==EOF)
			goto errwrite;
		if (n <= 0)
			break;
	}
	return 0;
}

/*
 * output one group of 3 bytes, pointed at by p, on file f.
 */
static int outdec(char *p, FILE *f)
{
	register int c1, c2, c3, c4;

	c1 = *p >> 2;
	c2 = ((*p << 4) & 060) | ((p[1] >> 4) & 017);
	c3 = ((p[1] << 2) & 074) | ((p[2] >> 6) & 03);
	c4 = p[2] & 077;
	if (putc(ENC(c1), f)==EOF) return 2;
	if (putc(ENC(c2), f)==EOF) return 2;
	if (putc(ENC(c3), f)==EOF) return 2;
	if (putc(ENC(c4), f)==EOF) return 2;
    return 0;
}
