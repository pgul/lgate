/*
 * $Id$
 *
 * $Log$
 * Revision 2.3  2004/07/20 18:38:05  gul
 * \r\n -> \n
 *
 * Revision 2.2  2001/01/25 18:41:11  gul
 * fix compiler warnings
 *
 * Revision 2.1  2001/01/24 01:59:18  gul
 * Bugfix: sometimes put msg into pktin dir with 'pkt' extension
 *
 * Revision 2.0  2001/01/10 20:42:24  gul
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
#include <fcntl.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_DIR_H
#include <dir.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef __OS2__
#define INCL_DOSPROCESS
#include <os2.h>
#endif
#include "gate.h"

void importpath(char * host,char const * cannon,char const * remote);

char spool_dir[FNAME_MAX];
extern char str[MAXSTR];
static char tmpname[SSIZE], tmpmask[SSIZE];

#define updatecrc(c,crc) crc=((crc>>1)|(crc<<15))+(int)(unsigned char)(c)

static int rmailfunc(char *addrlist)
{
  char *p, *p1;
  int  r, noaddr=1;

  conf=0;
  cnews=0;
  debug(4, "rmailfunc(\"%s\")", addrlist);
  p=addrlist;
  while (isspace(*p)) p++;
  for (; *p; lseek(fileno(stdin), 0, SEEK_SET))
  {
    for (p1=p; *p1 && !isspace(*p1); p1++);
    if (p1-p>=sizeof(addr))
    { logwrite('?', "Too long address\n");
      return 1;
    }
    strncpy(addr, p, (int)(p1-p));
    addr[(int)(p1-p)]='\0';
    ibufsrc=BUFSIZE;
    msgsize=-1;
    if (!myfgets(gotstr, sizeof(gotstr)))
    { logwrite('?', "Incorrect message\n");
      return 1;
    }
    if (isbeg(gotstr)!=0)
    { logwrite('?', "Incorrect message start\n");
      return 1;
    }
    r=msg_unmime(-1);
    if (r) return r;
    noaddr=0;
    for (p=p1; isspace(*p); p++);
  }
  debug(4, "rmailfunc ok");
  return noaddr;
}

static int rbmail(void)
{
  int hrmail, savein, r;
  long len;
  unsigned short crc, mycrc;
  static char addrlist[1026];
  char *p;

  strcpy(tmpmask, tmpdir);
  strcat(tmpmask, TMPUNZNAME);
  debug(6, "rbmail started");
  while (fgets(str, sizeof(str), stdin))
  {
    p=strchr(str, '\n');
    if (p==NULL)
    { logwrite('!', "Bad rbmail-packet (line too long)!\n");
      return 1;
    }
    *p='\0';
    debug(18, "rbmail: readed control line \"%s\"\n");
    if (sscanf(str, "%ld %hx %s", &len, &crc, addrlist)!=3)
    { logwrite('!', "Bad rbmail-packet (incorrect line format)!\n");
      return 1;
    }
    mktempname(tmpmask, tmpname);
    hrmail=open(tmpname, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
    if (hrmail==-1)
    { logwrite('?',"Can't create %s: %s!\n", tmpname, strerror(errno));
      return 1;
    }
    mycrc=0;
    while (len)
    { int i=sizeof(str);
      if (i>len) i=(int)len;
      if (fread(str, i, 1, stdin)!=1)
      { close(hrmail);
        unlink(tmpname);
        logwrite('!', "Bad rbmail-packet (no message data)!\n");
        return 1;
      }
      if (write(hrmail, str, i)!=i)
      { logwrite('?', "Can't write to file: %s!\n", strerror(errno));
        close(hrmail);
        unlink(tmpname);
        return 1;
      }
      len-=i;
      for (p=str; p-str<i; p++)
        mycrc=updatecrc(*p, mycrc);
    }
    if (mycrc!=crc)
    { logwrite('?', "rbmail crc error: %04x!=%04x\n", mycrc, crc);
      close(hrmail);
      unlink(tmpname);
      return 1;
    }
    savein=dup(fileno(stdin));
    lseek(hrmail, 0, SEEK_SET);
    dup2(hrmail, fileno(stdin));
    close(hrmail);
    r=rmailfunc(addrlist);
    dup2(savein, fileno(stdin));
    close(savein);
    unlink(tmpname);
    if (r) return r;
  }
  debug(6, "rbmail ok");
  return 0;
}

#ifdef __MSDOS__
static int rcbmail(void)
{
  int r, hunc, saveout;
  static char tmprbname[SSIZE];

  strcpy(tmpmask, tmpdir);
  strcat(tmpmask, TMPUNZNAME);
  mktempname(tmpmask, tmprbname);
  sprintf(cmdline, uncompress, "");
  hunc=open(tmprbname, O_BINARY|O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE);
  if (hunc==-1)
  { logwrite('?',"Can't create %s: %s!\n", tmprbname, strerror(errno));
    return 1;
  }
  saveout=dup(fileno(stdout));
  dup2(hunc, fileno(stdout));
  close(hunc);
  debug(4,"rcbmail: run '%s'", cmdline);
  if (!quiet)
  { fputs("Uncompressing batchmail-packet...", stderr);
    fflush(stderr);
  }
  r=swap_system(cmdline);
  if (!quiet)
    fputs("\n", stderr);
  if (r)
  { dup2(saveout,fileno(stdout));
    close(saveout);
    unlink(tmprbname);
    logwrite('!', "Uncompress retcode %d\n", r);
    return 1;
  }
  r=dup(fileno(stdin));
  rewind(stdout);
  dup2(fileno(stdout), fileno(stdin));
  dup2(saveout, fileno(stdout));
  close(saveout);
  saveout=r;
  if (!quiet)
    fputs("\n", stderr);
  r=rbmail();
  debug(4, "rbmail retcode %d", r);
  dup2(saveout, fileno(stdin));
  close(saveout);
  unlink(tmprbname);
  return r;
}
#else
static int rcbmail(void)
{
  int out, savein, r, pid, rgzip;

  sprintf(cmdline, uncompress, "");
  debug(4,"rcbmail: run '%s'", cmdline);
  pid=pipe_system(NULL,&out,cmdline);
  if (pid==-1)
  { logwrite('?',"Can't execute gzip for unpack batchmail-packet!\n");
    return 1;
  }
  setmode(out,O_BINARY);
  savein=dup(fileno(stdin));
  dup2(out, fileno(stdin));
  close(out);
  r=rbmail();
  if (r)
    kill(pid,SIGINT); /* чтобы не ругался "broken pipe" */
  dup2(savein, fileno(stdin));
  close(savein);
  waitpid(pid,&rgzip,0);
  rgzip&=0xffff;
  rgzip=((rgzip>>8) | (rgzip<<8)) & 0xffff;
  if (rgzip)
  { logwrite('?', "gzip retcode %d!\n", rgzip);
    return 1;
  }
  return r;
}
#endif

int fromuupcspool(void)
{
  time_t timer;
  static DIR *dd;
  struct dirent *df;
  char * p;
  FILE * fin;
  int r, lck, savein;
  static char lckname[SSIZE];

  strcpy(lckname, spool_dir);
  strcat(lckname, "locks.lck");
  mkdir(lckname);
  strcat(lckname, PATHSTR);
  strcat(lckname, remote);
  strcat(lckname, ".lck");
  if (access(lckname, 0)==0)
  { if (unlink(lckname))
    { logwrite('!', "System %s locked!\n", remote);
      return 1;
    }
    else
      logwrite('!', "Old lck-flag for %s deleted\n", remote);
  }
  lck=open(lckname, O_BINARY|O_CREAT|O_RDWR|O_EXCL, S_IREAD|S_IWRITE);
  if ((lck==-1) && (errno==EACCES))
  { /* access denied */
    logwrite('!', "System %s locked!\n", remote);
    return 1;
  }
  funix=1;
  if (lck==-1)
    logwrite('!', "Can't create %s: %s!\n", lckname, strerror(errno));
  else
  { time(&timer);
    sprintf(str, "Locked by " NAZVA " PID %u since %s",
            getpid(), ctime(&timer));
    write(lck, str, strlen(str));
    /* flush */
    r=lck;
    lck=dup(r);
    close(r);
  }
  strcpy(str, spool_dir);
  strcpy(named, str);
  strcat(str, remote);
  debug(5, "GetSpool started, spooldir is %s", str);
  strcat(str, "\\c");
  namec[0]=0;
  dd=opendir(str);
  if (dd==NULL)
  { debug(2, "GetSpool: can't opendir %s: %s", str, strerror(errno));
    if (lck!=-1)
    { close(lck);
      unlink(lckname);
    }
    return 0;
  }
  while ((df=readdir(dd))!=NULL)
  { if (df->d_name[0]=='.') continue;
    strcpy(str, spool_dir);
    strcat(str, remote);
    strcat(str, "\\c\\");
    strcat(str, df->d_name);
    fin=myfopen(str, "r");
    if (fin==NULL)
    { logwrite('?', "Can't open %s: %s!\n", str, strerror(errno));
      continue;
    }
    strcpy(namec, str);
    /* там должно быть 2 строки */
    if (!fgets(str, sizeof(str), fin))
    {
badc: fclose(fin);
badc1:strcpy(str, spool_dir);
      strcat(str, "bad.job");
      mkdir(str);
      strcat(str, strrchr(namec,'\\'));
      if (rename(namec, str))
      { logwrite('?',"Can't move %s to %s: %s!\n",namec,str,strerror(errno));
        unlink(namec);
      }
      else
        logwrite('?',"Incorrect spool-file %s, moved to bad.job!\n",namec);
      namec[0]=0;
      continue;
    }
    if (strncmp(str, "S ", 2))
      goto badc;
    /* потом идут имена файлов здесь и там */
    p=strchr(str+2,' ');
    if (p==NULL) goto badc;
    *p=0;
    if (*(p+1)!='D') goto badc;
    strcpy(named, spool_dir);
    importpath(named+strlen(named),str+2,remote);
    if (!fgets(str,sizeof(str),fin))
      goto badc;
    if (strncmp(str, "S ", 2)) /* начинаться должно с "S " */
      goto badc;
    p=strchr(str+2,' ');
    if (p==NULL) goto badc;
    *p=0;
    if (*(p+1)!='X') goto badc;
    strcpy(namex, spool_dir);
    importpath(namex+strlen(namex),str+2,remote);
    if (access(named,0))
    { logwrite('?',"Can't find %s!\n",named);
      goto badc;
    }
    if (access(namex,0))
    { logwrite('?',"Can't find %s!\n",namex);
      goto badc;
    }
    fclose(fin);
    debug(4,"GetSpool: namec=%s, named=%s, namex=%s",namec,named,namex);

    fromaddr[0]=0;
    packnews=0;
    if (fout)
    { if (packmail)
        begdel=ftell(fout);
      else
      { closeout();
        begdel=0;
      }
    }
    else
      begdel=0;

    fin=myfopen(namex,"rb");
    if (fin==NULL)
    { logwrite('?',"Can't open %s: %s!\n",namex,strerror(errno));
      if (lck!=-1)
      { close(lck);
        unlink(lckname);
      }
      return 2;
    }
    while (fgets(str,sizeof(str),fin))
      if (strncmp(str,"C ",2)==0)
        break;
    if (feof(fin))
      goto badc;
    fclose(fin);
    p=strchr(str, '\n');
    if (p) *p='\0';
    r=open(named, O_BINARY|O_RDONLY);
    if (r==-1)
    { logwrite('?', "Can't open %s: %s!\n", named, strerror(errno));
      goto badc1;
    }
    savein=dup(fileno(stdin));
    dup2(r, fileno(stdin));
    close(r); 
    if (strncmp(str+2, "rmail ", 6)==0)
    { char *addrlist;
      if (nonet) continue;
      addrlist=strdup(str+8);
      if (addrlist==NULL)
      { logwrite('?',"Not enough memory!\n");
        r=-1;
      }
      else
      { if (conf)
        { closeout();
          begdel=packnews=0;
        }
        r=rmailfunc(addrlist);
      }
    }
    else if (strcmp(str+2, "rbmail")==0)
    { if (nonet) continue;
      if (conf) 
      { closeout();
        begdel=packnews=0;
      }
      r=rbmail();
    }
    else if (strcmp(str+2, "rcbmail")==0 ||
             strcmp(str+2, "rzbmail")==0)
    { if (nonet) continue;
      if (conf) 
      { closeout();
        begdel=packnews=0;
      }
      r=rcbmail();
    }
    else if (strcmp(str+2, "rnews")==0)
    { if (noecho) continue;
      if (!conf)
      { closeout();
        begdel=packnews=0;
      }
      r=rnews();
    }
    else
    { logwrite('?', "Unknown command '%s' in spool-file!\n", str);
      dup2(savein, fileno(stdin));
      close(savein);
      goto badc1;
    }
    dup2(savein, fileno(stdin));
    close(savein);
    if (r==0)
    { unlink(named);
      unlink(namex);
      unlink(namec);
    }
    else
    { badnews();
      /* goto badc; */
      continue;
    }
  }
  debug(4,"GetSpool: no more jobs in spool");
  closedir(dd);
  if (lck!=-1)
  { close(lck);
    unlink(lckname);
  }
  if (!conf) closeout();
  return 0;
}
