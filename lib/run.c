#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "libgate.h"

int swap_system(char * cmd)
{ debug(7, "system: '%s'", cmd);
  return system(cmd);
}

static int getargs(char *line, char *flds[], int maxfields)
{
   int i = 0;
   char quoted = '\0';

   while ((*line != '\0') && (*line != '\n')) {
	  if (isspace(*line))
		 line++;
	  else {
		 char *out = line;
		 if (maxfields-- <= 0)
			return -1;
		 *flds++ = line;
		 i++;
		 while((quoted || !isspace(*line)) && (*line != '\0'))
		 {
			switch(*line)
			{
			   case '"':
			   case '\'':
				  if (quoted)
				  {
					 if (quoted == *line)
					 {
						quoted = 0;
						line++;
					 }
					 else
						*out++ = *line++;
				  } /* if */
				  else
					 quoted = *line++;
				  break;

			   case '\\':
				  switch(*++line)         /* Unless the following    */
				  {                       /* character is very       */
					 default:             /* special we pass the \   */
								if (!isspace(*line))
						   *out++ = '\\'; /* and following char on   */
					 case '"':
					 case '\'':
					 case '\\':
						*out++ = *line++;
				  }
				  break;

			   default:
				  *out++ = *line++;

			} /*switch*/
		 } /* while */
		 if (isspace(*line))
			line++;
		 *out = '\0';
	  } /* else */
   }

   if (maxfields-- <= 0)
	return -1;
   *flds++ = NULL;
   return i;

} /*getargs*/

int pipe_system0(int *in, int *out, char *cmd, char *argv0)
{ int hpipe[2];
  int newstdin=-1, newstdout=-1, pid;

  debug(7, "pipe_system: '%s'", cmd);
  fflush(stdout);
  fflush(stderr);
  if (in)
  { if (pipe(hpipe))
    { logwrite('?', "Can't create pipe: %s!\n", strerror(errno));
      return -1;
    }
    *in=hpipe[1];
    newstdin=hpipe[0];
  }
  if (out)
  { if (pipe(hpipe))
    { pid=errno;
      if (in)
      { close(*in);
        close(newstdin);
      }
      logwrite('?', "Can't create pipe: %s!\n", strerror(pid));
      return -1;
    }
    *out=hpipe[0];
    newstdout=hpipe[1];
  }
forkagain:
  pid=fork();
  if (pid==-1)
  { if (errno==EINTR || errno==EAGAIN)
      goto forkagain;
    pid=errno;
    if (in)
    { close(*in);
      close(newstdin);
    }
    if (out)
    { close(newstdout);
      close(*out);
    }
    logwrite('?', "Can't fork(): %s!\n", strerror(pid));
    return -1;
  }
  if (pid==0)
  { if (in)
    { close(*in);
      dup2(newstdin, fileno(stdin));
      close(newstdin);
    }
    if (out)
    { close(*out);
      dup2(newstdout, fileno(stdout));
      close(newstdout);
    }
    if (strpbrk(cmd, METACHARS)==0)
    { char *args[256];
      char *p;
      if (getargs(cmd, args, sizeof(args)/sizeof(args[0])) != -1)
      { p=args[0];
        if (argv0) args[0] = argv0;
        execvp(p, args);
        logwrite('?', "Can't exec %s: %s!\n", cmd, strerror(errno));
      }
      goto via_system;
    }
    else
via_system:
    { char *p=getenv("SHELL");
      if (p) p=strchr(p, '=');
      if (p) p++;
      else p="/bin/sh";
      execlp(p, p, "-c", cmd, NULL);
      logwrite('?', "Can't exec %s: %s!\n", strerror(errno));
    }
    exit(123);
  }
  if (out) close(newstdout);
  if (in) close(newstdin);
  debug(5, "pipe_system: \"%s\" pid %d", cmd, pid);
  return pid;
}

int pipe_spawnv(int *in, int *out, char *name, char *args[])
{
  int newstdin=-1, newstdout=-1;
  int pid, i;
  int hpipe[2];

  debug(7, "Pipe_Spawnv: %s", name);
  for (i=0; args[i]; i++)
    debug(7, "Pipe_Spawnv: arg[%d]='%s'", i, args[i]);
  fflush(stdout);
  fflush(stderr);
  if (in)
  { if (pipe(hpipe))
    { logwrite('?', "Can't create pipe: %s!\n", strerror(errno));
      return -1;
    }
    *in=hpipe[1];
    newstdin=hpipe[0];
  }
  if (out)
  { if (pipe(hpipe))
    { pid=errno;
      if (in)
      { close(*in);
        close(newstdin);
      }
      logwrite('?', "Can't create pipe: %s!\n", strerror(pid));
      return -1;
    }
    *out=hpipe[0];
    newstdout=hpipe[1];
  }
forkagain1:
  pid=fork();
  if (pid==-1)
  { if (errno==EINTR || errno==EAGAIN)
      goto forkagain1;
    pid=errno;
    if (in)
    { close(*in);
      close(newstdin);
    }
    if (out)
    { close(newstdout);
      close(*out);
    }
    logwrite('?', "Can't fork(): %s!\n", strerror(pid));
    return -1;
  }
  if (pid==0)
  { if (in)
    { close(*in);
      dup2(newstdin, fileno(stdin));
      close(newstdin);
    }
    if (out)
    { close(*out);
      dup2(newstdout, fileno(stdout));
      close(newstdout);
    }
    execvp(name, args);
    logwrite('?', "Can't exec %s: %s!\n", name, strerror(errno));
    exit(123);
  }
  if (out) close(newstdout);
  if (in) close(newstdin);
  debug(5, "Pipe_Spawnv: %s pid %d", name, pid);
  return pid;
}
