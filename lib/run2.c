#include <stdio.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#define INCL_DOSFILEMGR
#define INCL_DOSQUEUES
#include <os2.h>
#include "libgate.h"

static void restredir(int saved,int to)
{
	if (saved==-1) return;
	dup2(saved,to);
	close(saved);
}

static int redirect(char ** args,int *ind,char * what,int to,int * save)
{
	int h;
	char * p;
	int j;

	p=strstr(args[*ind],what);
	if (p==NULL) return 0;
	if (*save!=-1) return -1;
	*p='\0';
	if (p==args[*ind])
		for (j=*ind;args[j];j++)
			args[j]=args[j+1];
	else
		(*ind)++;
	p+=strlen(what);
	if (*p=='\0')
	{	p=args[*ind];
		if (p==NULL) return -1;
		for (j=*ind;args[j];j++)
			args[j]=args[j+1];
	}
	(*ind)--;
	if (to==-1)
		return 1;
	if ((strcmp(what,">>")==0) || (strcmp(what,">&>")==0)) /* append */
	{	if (access(p,0))
			h=open(p,O_TEXT|O_WRONLY|O_CREAT,S_IREAD|S_IWRITE);
		else {
			h=open(p,O_TEXT|O_APPEND|O_WRONLY);
			if (h!=-1) lseek(h,0,SEEK_END);
		}
	}
	else if (strchr(what,'>'))
	{	if (!access(p,0))
			unlink(p);
		h=open(p,O_TEXT|O_WRONLY|O_CREAT,S_IREAD|S_IWRITE);
	}
	else
		h=open(p,O_TEXT|O_RDONLY);
	if (h==-1) return -1;
        restredir(*save, to);
	*save=dup(to);
	if (*save==-1)
	{	close(h);
		return -1;
	}
	if (dup2(h,to)==-1)
	{	close(*save);
		*save=-1;
		close(h);
		return -1;
	}
	close(h);
	return 1;
}

static char exename[FNAME_MAX];
static char searchbuf[FNAME_MAX];

static int searchfile(char * fname,int needsearch)
{
  if (access(fname,0)==0)
    return 1;
  if (needsearch)
  {
    _searchenv(fname,"PATH",searchbuf);
    if (searchbuf[0]==0) return 0;
    strcpy(fname,searchbuf);
    return 1;
  }
  return (access(fname,0)==0);
}

void expand_path(char *src, char *dest)
{
  /* делаем полный путь по src и добавляем расширение */
  char * p;
  int  needsearch,needext;

  p=strrchr(src,'/');
  if (p==NULL) p=strrchr(src,'\\');
  if (p==NULL) p=strchr(src,':');
  if (p==NULL)
  { p=src;
    needsearch=1;
  }
  else
  { p++;
    needsearch=0;
  }
  if (strchr(p,'.'))
    needext=0;
  else
    needext=1;
  if (needext)
  {
    strcpy(dest,src);
    strcat(dest,".exe");
    if (searchfile(dest,needsearch))
      return;
    strcpy(dest,src);
    strcat(dest,".cmd");
    if (searchfile(dest,needsearch))
      return;
    strcpy(dest,src);
    strcat(dest,".com");
    if (searchfile(dest,needsearch))
      return;
  }
  strcpy(dest,src);
  searchfile(dest,needsearch);
}

int swap_system(char * cmd)
{
	char * args[200];
        int saveerr=-1, saveout=-1, savein=-1;
        char * p;
	int pid;
	int i;
        int rc;

	debug(5, "SwapSystem: '%s'", cmd);
        for (p=cmd,i=0;*p;)
        {
          args[i++]=p;
          p=strpbrk(p," \t");
          if (p==NULL) break;
          *p++='\0';
          while ((*p==' ')||(*p=='\t')) p++;
        }
        args[i]=NULL;
        /* do we need exec via comspec? */
        expand_path(args[0],exename);
        p=strrchr(exename,'.');
        if (p)
          if (stricmp(p,".cmd")==0)
          { for (;i>=0;i--)
              args[i+2]=args[i];
            args[0]=getenv("COMSPEC");
            if (args[0]==NULL) args[0]="cmd.exe";
            strcpy(exename, args[0]);
            args[1]="/c";
            debug(7, "Swap_System: run via comspec");
          }
        /* do redirections */
        for (i=0;args[i];i++)
        { 
          rc=redirect(args,&i,">&>",fileno(stderr),&saveerr);
          if (rc==-1) return -1;
          if (rc) continue;
          rc=redirect(args,&i,">&",fileno(stderr),&saveerr);
          if (rc==-1)
          { restredir(saveerr,fileno(stderr));
            return -1;
          }
          if (rc) continue;
          rc=redirect(args,&i,">>",fileno(stdout),&saveout);
          if (rc==-1)
          { restredir(saveerr,fileno(stderr));
            return -1;
          }
          if (rc) continue;
          rc=redirect(args,&i,">",fileno(stdout),&saveout);
          if (rc==-1)
          { restredir(saveout,fileno(stdout));
            restredir(saveerr,fileno(stderr));
            return -1;
          }
          if (rc) continue;
          rc=redirect(args,&i,"<",fileno(stdin),&savein);
          if (rc==-1)
          { restredir(saveout,fileno(stdout));
            restredir(saveerr,fileno(stderr));
            return -1;
          }
	}
	pid=spawnvp(P_NOWAIT,exename,args);
	if (pid!=-1) {
		waitpid(pid, &rc, 0);
		rc &= 0xffff;
		rc= ((rc << 8) | (rc >> 8)) & 0xffff;
	} else {
		rc=-1;
	}
	restredir(savein,fileno(stdin));
        restredir(saveout,fileno(stdout));
        restredir(saveerr,fileno(stderr));
	debug(5, "Swap_System: retcode %d", rc);
	return rc;
}

#define PIPESIZE    4096

#ifndef HAVE_PIPE
int pipe(int filedes[2])
{
  if (DosCreatePipe((PHFILE)&filedes[0], (PHFILE)&filedes[1], PIPESIZE))
    return -1;
  _hdopen(filedes[1],O_TEXT|O_RDWR);
  _hdopen(filedes[0],O_TEXT|O_RDONLY);
  return 0;
}
#endif

int pipe_system0(int * in,int * out,char * cmd,char * argv0)
{
  char * args[20];
  char * p;
  int  r;

  debug(7, "Pipe_System: %s", cmd);
  for (p=cmd,r=0;*p;)
  {
    args[r++]=p;
    p=strpbrk(p," \t");
    if (p==NULL) break;
    *p++='\0';
    while ((*p==' ')||(*p=='\t')) p++;
  }
  args[r]=NULL;
  p=args[0];
  if (argv0)
    args[0]=argv0;
  return pipe_spawnv(in, out, p, args);
}

int pipe_spawnv(int * in,int * out,char * name, char * args[])
{
  int savein=-1,saveout=-1,saveerr=-1;
  int r,i,rc;
  int hpipe[2];
  char * p;

  debug(7, "Pipe_Spawnv: %s", name);
  for (i=0;args[i];i++)
    debug(7, "Pipe_Spawnv: arg[%d]='%s'", i, args[i]);
  /* do we need exec via comspec? */
  expand_path(name,exename);
  p=strrchr(exename,'.');
  if (p)
    if (stricmp(p,".cmd")==0)
    { for (r=0; args[r]; r++);
      for (;r>=0;r--)
        args[r+2]=args[r]; /* not clean; using args[] after NULL */
      args[0]=getenv("COMSPEC");
      if (args[0]==NULL) args[0]="cmd.exe";
      strcpy(exename, args[0]);
      args[1]="/c";
      debug(7, "Pipe_System: run via comspec");
    }
  /* do redirections */
  for (i=0;args[i];i++)
  { 
    rc=redirect(args,&i,">&>",fileno(stderr),&saveerr);
    if (rc==-1) return -1;
    if (rc) continue;
    rc=redirect(args,&i,">&",fileno(stderr),&saveerr);
    if (rc==-1)
    { restredir(saveerr,fileno(stderr));
      return -1;
    }
    if (rc) continue;
    rc=redirect(args,&i,">>",out ? -1 : fileno(stdout),&saveout);
    if (rc==-1)
    { restredir(saveerr,fileno(stderr));
      return -1;
    }
    if (rc) continue;
    rc=redirect(args,&i,">",out ? -1 : fileno(stdout),&saveout);
    if (rc==-1)
    { restredir(saveout,fileno(stdout));
      restredir(saveerr,fileno(stderr));
      return -1;
    }
    if (rc) continue;
    rc=redirect(args,&i,"<",in ? -1 : fileno(stdin),&savein);
    if (rc==-1)
    { restredir(saveout,fileno(stdout));
      restredir(saveerr,fileno(stderr));
      return -1;
    }
  }
  if (in)
  { 
    if (pipe(hpipe))
    { logwrite('?',"Can't create pipe!\n");
      return -1;
    }
    restredir(savein,fileno(stdin));
    savein=dup(fileno(stdin));
    dup2(hpipe[0],fileno(stdin));
    close(hpipe[0]);
    *in=hpipe[1];
    DosSetFHState(*in,OPEN_FLAGS_NOINHERIT);
  }
  if (out)
  { 
    if (pipe(hpipe))
    { if (in)
      { dup2(savein,fileno(stdin));
        close(savein);
      }
      logwrite('?',"Can't create pipe!\n");
      return -1;
    }
    restredir(saveout,fileno(stdout));
    fflush(stdout);
    saveout=dup(fileno(stdout));
    *out=hpipe[0];
    dup2(hpipe[1],fileno(stdout));
    close(hpipe[1]);
    DosSetFHState(*out,OPEN_FLAGS_NOINHERIT);
  }
  r=spawnvp(P_NOWAIT,exename,args);
  restredir(savein,fileno(stdin));
  restredir(saveout,fileno(stdout));
  restredir(saveerr,fileno(stderr));
  debug(5, "Pipe_Spawnv: %s pid %d", exename, r);
  return r;
}
