/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:15  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <time.h>
#include <errno.h>
#ifdef HAVE_SHARE_H
#include <share.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef __OS2__
#define INCL_DOSFILEMGR
#include <os2.h>
#endif
#include <fidolib.h>
#include "gate.h"

static struct message msghdr;
struct hostype * hosts;
int nhosts;
int retcode;
char newechoflag[FNAME_MAX];
int newecho;
char flo_only;
static int r,i,waserr;
static char s[80];
char str[2048];
static unsigned long attrib;
char netdir[FNAME_MAX],rescan[FNAME_MAX];
static unsigned pp,zz,resc;
static char * p,* p1;
int f;
static DIR * d;
static struct dirent * df;
static struct stat statbuf;
static char empty,cont,notsend;
static int hbsy;
static int leavesem;
int curhost=-1;

struct sendtype * tosend;
unsigned nsend;

static int sendfile(char * str, int i, unsigned long attrib, semtype sem)
{ int r;

  stat(str, &statbuf);
  if (hosts[i].enc==ENC_UUCP)
  {
    if (sem==FD_SEM)
    { if (SetFDSem(&hosts[i].addr,semdir))
      { logwrite('!',"Can't send file %s to %s: system busy\n",
                 str,hosts[i].host);
        return 0;
      }
      debug(5, "Main: set semaphore for %d:%d/%d.%d",
            hosts[i].addr.zone,hosts[i].addr.net,hosts[i].addr.node,hosts[i].addr.point);
    }
    debug(4, "Main: sending %s to %s via uucp", str, hosts[i].host);
    r=uucp(str,hosts[i].host);
    if (sem==FD_SEM)
      if (DelFDSem(&hosts[i].addr,semdir))
        logwrite('!',"Cant unlink semaphore: %s", strerror(errno));
    if (r)
    { logwrite('?',"Error! Can't send file %s to %s!\n",str,hosts[i].host);
      waserr=1;
      movebad(str,attrib);
      retcode|=RET_ERR;
      return 1;
    }
    logwrite('$',"File %s size %lu sent to %s\n",str,statbuf.st_size,hosts[i].host);
    retcode|=RET_SENT;
    if (attrib & msgKFS)
    { logwrite('$',"Deleting sent file %s\n",str);
      unlink(str);
    }
    else if (attrib & msgTFS)
    { logwrite('$',"Truncating sent file %s\n",str);
      r=myopen(str,O_RDWR|O_EXCL);
      if (r!=-1)
      { chsize(r,0);
        close(r);
      }
      else
      { debug(1, "Main: can't open %s: %s", str, strerror(errno));
        printf("Can't truncate file!\n");
        logwrite('!',"Can't truncate file!\n");
        retcode|=RET_WARN;
      }
    }
    debug(4, "Main: file %s sent", str);
  }
  else
  { /* uue */
    if ((statbuf.st_size>maxuue*1024l) && (maxuue) && (hosts[i].size==0))
    { logwrite('!',"File %s too large for uuencode (%lu bytes), not sent to %s.\n",
               str,statbuf.st_size,hosts[i].host);
      movebad(str,attrib);
      retcode|=RET_WARN;
      return 0;
    }
    if (sem==FD_SEM)
    { for (r=0;r<nsend;r++)
        if ((tosend[r].host==i) && (tosend[r].sem==FD_SEM))
          break;
      if (r==nsend)
      {
        if (SetFDSem(&hosts[i].addr,semdir))
        { logwrite('!',"Can't send file %s to %s: system busy\n",
                   str,hosts[i].host);
          return 0;
        }
        debug(5, "Main: set semaphore for %d:%d/%d.%d",
              hosts[i].addr.zone,hosts[i].addr.net,hosts[i].addr.node,hosts[i].addr.point);
      }
    }
    debug(4, "Main: send %s to %s via uucode", str, hosts[i].host);
    strcpy(tosend[nsend].filename,str);
    tosend[nsend].host=i;
    tosend[nsend].attr=attrib;
    tosend[nsend].sem=sem;
    nsend++;
    if (nsend==MAXSEND)
    { debug(5, "Main: call FlushSend");
      flushsend();
    }
  }
  return 0;
}

static void checkbox(char *boxname, int i)
{
  DIR *d;
  struct dirent *df;
  struct stat st;

  debug(4, "Checkbox: %s", boxname);
  d=opendir(boxname);
  if (d==NULL) return;
  while ((df=readdir(d))!=NULL)
  {
    strcpy(str,boxname);
    addslash(str);
    strcat(str,df->d_name);
    if (stat(str,&st))
      continue;
    if (!(st.st_mode & S_IFREG))
      continue;
    debug(6, "Checkbox: found %s", str);
    sendfile(str, i, msgKFS, NO_SEM);
  }
  closedir(d);
}

static char dhex(int i)
{ return (i>9) ? 'a'+i-10 : '0'+i;
}

int main(int argc, char * argv[])
{
  bufsize=BUFSIZE;
  buffer=malloc(BUFSIZE);
  if (buffer==NULL)
  { fprintf(stderr, "Not enough memory!\n");
    return RET_ERR;
  }
  retcode=0;
  strcpy(copyright, NAZVA);
  strcat(copyright, " (AttUucp)");
  if (params(argc, argv))
    return retcode;
  if (fake)
    return saveargs(argc, argv);
  debug(1, "Attuucp Started");
#ifdef __MSDOS__
  debug(7, "Main: farcoreleft()=%ld", farcoreleft());
#endif
  if ((!nosend) && (!bypipe))
  {
    tosend=malloc(MAXSEND*sizeof(tosend[0]));
    if (tosend==NULL)
    { fputs("Not enough memory!\n",stderr);
      return RET_ERR;
    }
  }
  else
    tosend=NULL;
  r=config();
  if (r) return r;
  tzset();
  resc=0;
  if (semdir[0])
    strcpy(str,semdir);
  else
    strcpy(str,tmpdir);
  addslash(str);
  strcat(str,BSYNAME);
  debug(6, "Main: semaphore name is %s", str);
  {
    int i;
#ifdef UNIX
    int wasold=0;
    char buf[32];
#endif
    for (i=0; ; i++)
    {
#ifndef UNIX
#ifdef __MSDOS__
      if (!share)
        hbsy=open(str,O_BINARY|O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE);
      else
#endif
        hbsy=sopen(str,O_BINARY|O_CREAT|O_RDWR|O_EXCL,SH_DENYWR,S_IREAD|S_IWRITE);
      { if (hbsy==-1)
        { if (unlink(str)==0)
          { logwrite('!', "Old flag %s deleted\n", str);
#ifdef __MSDOS__
            if (!share)
              hbsy=open(str,O_BINARY|O_CREAT|O_RDWR|O_EXCL,S_IREAD|S_IWRITE);
            else
#endif
              hbsy=sopen(str,O_BINARY|O_CREAT|O_RDWR|O_EXCL,SH_DENYWR,S_IREAD|S_IWRITE);
          }
        }
      }
      if (hbsy!=-1)
        break;
      if (i==0)
      {
#ifdef __MSDOS__
        if (!share)
          hbsy=open(str,O_BINARY|O_RDONLY);
        else
#endif
          hbsy=sopen(str,O_BINARY|O_RDONLY,SH_DENYNO,S_IREAD|S_IWRITE);
        if (hbsy==-1)
          logwrite('?',"Can't create %s!\n",str);
        else
        { r=read(hbsy,str,sizeof(str)-1);
          str[r]='\0';
          close(hbsy);
          logwrite('!', "Another copy of attuucp running %s",str);
        }
        /* return RET_ERR;
        */
      }
      else if (i==30 || (errno!=EEXIST && errno!=EACCES && errno!=EAGAIN))
        break;
      sleep(1);
#else /* UNIX */
      hbsy=open(str,O_CREAT|O_RDWR|O_EXCL,0644);
      if (hbsy==-1)
      { hbsy=open(str,O_RDWR);
        if (hbsy==-1)
          debug(1, "Can't open %s: %s!\n", str, strerror(errno));
        else
        { wasold=1;
          r=read(hbsy, buf, sizeof(buf));
          buf[sizeof(buf)-1]='\0';
          lseek(hbsy, 0, SEEK_SET);
        }
      }
      if (hbsy==-1)
      { if (i==30 || (errno!=EACCES && errno!=EEXIST && errno!=EAGAIN))
          break;
        sleep(1);
        continue;
      }
#ifdef HAVE_FLOCK
      if (flock(hbsy, LOCK_EX|LOCK_NB))
      { if (errno!=EAGAIN)
        { close(hbsy);
          hbsy=-1;
          break;
        }
        else if (i==0)
          debug(1, "Another copy of attuucp running%s%s",
                   (wasold && r>0) ? " " : "\n",
                   (wasold && r>0) ? buf : "");
        close(hbsy);
        hbsy=-1;
        sleep(1);
        continue;
      }
      else
        break;
#else /* no flock() */
      if (wasold)
      { int pid=1;
        if (r>0)
        { char *p=strstr(buf, "PID ");
          if (p) pid=atoi(p+4);
          if (kill(pid, 0))
            pid=0; /* no corresponding process */
        }
        if (pid)
        { close(hbsy);
          hbsy=-1;
          if (i==0)
            debug(1, "Another copy of attuucp running%s%s",
                  (r>0) ? " " : "\n",
                  (r>0) ? buf : "");
          sleep(1);
          continue;
        }
      }
#endif
      if (wasold && hbsy!=-1)
        logwrite('!', "Old semaphore deleted%s%s%s",
                 (r>0) ? " " : "\n",
                 (r>0) ? buf : "");
      if (hbsy!=-1)
      { close(hbsy);
        hbsy=-1;
        wasold=0;
      }
#endif
    }
  }
  if (hbsy!=-1)
  { time_t t;
    /* put our attributes */
    debug(6, "Main: attuucp semaphore created");
    t=time(0);
    strcpy(str,ctime(&t));
    p=strchr(str,'\n');
    if (p) *p='\0';
    sprintf(str+strlen(str),", PID %u\n",(unsigned)getpid());
    write(hbsy,str,strlen(str));
    chsize(hbsy, strlen(str));
    /* flush */
    if ((r=dup(hbsy))!=-1)
    { close(hbsy);
      hbsy=r;
    }
#ifdef __OS2__
    DosSetFHState(hbsy, OPEN_FLAGS_NOINHERIT);
#endif
  }
  else
  { logwrite(bypipe ? '!' : '?', "Can't create attuucp semaphore: %s!",
             strerror(errno));
    if (!bypipe)
      return RET_ERR;
  }
  newecho=0;
  nsend=0;
  if ((!nosend) && (!bypipe))
  {
    debug(4, "Checking netmail (*.msg)");
    d=opendir(netdir);
    if (d==NULL)
      logwrite('!', "Can't find netmail directory!\n");
    else
    { while ((df=readdir(d))!=NULL)
      {
        debug(9, "Main: found %s", df->d_name);
        if (strlen(df->d_name)<4) continue;
        if (stricmp(df->d_name+strlen(df->d_name)-4, ".msg")) continue;
        strcpy(str, netdir);
        addslash(str);
        strcat(str, df->d_name);
        if (access(str, 2)) /* W_OK */
        { debug(9, "Main: have no write permissions for %s", df->d_name);
          continue;
        }
        waserr=0;
        f=myopen(str,O_BINARY|O_RDWR|O_EXCL);
        if (f==-1)
        { debug(1, "Main: can't open: %s, skipped", strerror(errno));
          continue;
        }
        read_msghdr(f, &msghdr);
        if (msghdr.attr & (msgSENT | msgORPHAN | msgFREQ))
        { close(f);
          debug(9, "Main: Message sent, orphan or freq, skipped");
          continue;
        }
        if (!(msghdr.attr & msgFILEATT))
        { close(f);
          debug(9, "Main: it's not fileattach, skipped");
          continue;
        }
        if (flo_only)
          if (msghdr.attr & (msgHOLD | msgCRASH))
          { close(f);
            debug(9, "Main: message hold or crash (flo-only=yes), skipped");
            continue;
          }
        if (((msghdr.attr & msgFORWD) && (msghdr.attr & msgLOCAL)) ||
            ((!(msghdr.attr & msgLOCAL)) && !(msghdr.attr & msgFORWD)))
        { close(f);
          debug(9, "Main: message (TRS & LOC) or (!TRS & !LOC), skipped");
          continue;
        }
        for (i=0;i<nhosts;i++)
          if ((msghdr.dest_net==hosts[i].addr.net) &&
              (msghdr.dest_node==hosts[i].addr.node))
            break;
        if (i==nhosts)
        { close(f);
          debug(9, "Main: message to %d/%d, not for us, skipped",
                msghdr.dest_net, msghdr.dest_node);
          continue;
        }
        /* read the message, look for point number */
        empty=1;
        notsend=0;
        cont=0;
        ibuf=0;
        attrib=msghdr.attr;
        zz=0;
        pp=0;
        while (hgets(str,sizeof(str),f,'\r'))
        {
          if (!cont)
          { if (str[0]=='\n')
              strcpy(str,str+1);
            if ((str[0]!='\r') && (str[0]!='\1') && (str[0]))
              empty=0;
          }
          if (cont)
          { if (strchr(str,'\r'))
              cont=0;
            continue;
          }
          if (strchr(str,'\r')==NULL)
            cont=1;
          if (str[0]!=1)
            continue;
          debug(11, "Main: read kludge '%s'", str+1);
          if (strncmp(str+1,"INTL ",5)==0)
          { /* Check dest zone */
            zz=atoi(str+5);
            continue;
          }
          if (strncmp(str+1,"TOPT ",5)==0)
          { pp=atoi(str+5);
            continue;
          }
          if (strncmp(str+1,"FLAGS ",6)==0)
          {
            for (p=str+6;(*p!='\r') && (*p!=0);p+=3)
            { while (*p==' ') p++;
              if (strncmp(p,"DIR",3)==0)
              { notsend|=flo_only;
                continue;
              }
              if (strncmp(p,"LOK",3)==0)
              { notsend=1;
                break;
              }
              if (strncmp(p,"IMM",3)==0)
              { notsend|=flo_only;
                continue;
              }
              if (strncmp(p,"KFS",3)==0)
              { attrib|=msgKFS;
                continue;
              }
              if (strncmp(p,"TFS",3)==0)
              { attrib|=msgTFS;
                continue;
              }
            }
          }
          if (notsend) break;
        }
        if (notsend)
        { close(f);
          debug(9, "Main: not my flags, skipped");
          continue;
        }
        if ((hosts[i].addr.point!=pp) || ((hosts[i].addr.zone!=zz) && (zz!=0)))
        { for (i++; i<nhosts; i++)
            if (((hosts[i].addr.zone==zz) || (zz==0)) &&
                 (hosts[i].addr.net==msghdr.dest_net) &&
                 (hosts[i].addr.node==msghdr.dest_node) &&
                 (hosts[i].addr.point==pp))
              break;
          if (i==nhosts)
          { close(f);
            debug(9, "Main: message to %d:%d/%d.%d, not for me, skipped",
                  zz, msghdr.dest_net, msghdr.dest_node, pp);
            continue;
          }
        }
        debug(9, "Main: our message");
        /* need to resend */
        resc=1;
        for(p=msghdr.subj; p; p=strpbrk(p, " \t"))
        {
          while ((*p==' ')||(*p=='\t'))
            p++;
          if (*p==0) break;
          strcpy(str, p);
          p1=strpbrk(str," \t");
          if (p1) *p1=0;
          debug(8, "Main: attached file %s", str);
          if (access(str,0))
          { printf("Error! Can't find file %s!\n", str);
            logwrite('!', "Error! Can't find file %s!\n",str);
            retcode|=RET_WARN;
            continue;
          }
          if (sendfile(str, i, attrib, semdir[0] ? FD_SEM : NO_SEM))
            break;
        }
        close(f);
        strcpy(str, netdir);
        addslash(str);
        strcat(str, df->d_name);
        if (waserr) continue;
        if ((attrib & msgKILLSENT) && empty)
        { debug(9, "Main: killing %d", str);
          unlink(str);
        }
        else
        { f=myopen(str, O_BINARY|O_RDWR|O_EXCL);
          if (f==-1)
          { debug(1, "Can't open %s: %s", str, strerror(errno));
            strcpy(s, str);
            p=strrchr(s, PATHSEP);
            if (p==NULL) p=s+strlen(s);
            p=strchr(p,'.');
            if (p==NULL) p=s+strlen(s);
            strcpy(p, ".bad");
            rename(str, s);
            continue;
          }
          if (empty)
          { debug(9, "Main: set SENT attribute to %s", str);
            msghdr.attr|=msgSENT;
          }
          else
          { debug(9, "Main: clear ATT attribute at %s", str);
            msghdr.attr&=~msgFILEATT;
          }
          write_msghdr(f, &msghdr);
        }
      }
      closedir(d);
    }
    /* check for bink outbound */
    if (binkout[0])
    {
      debug(4, "Checking bink outbound");
      for (curhost=0; curhost<nhosts; curhost++)
      { char loname[9];
        debug(10, "Main: check attaches for %u:%u/%u.%u",
              hosts[curhost].addr.zone, hosts[curhost].addr.net,
              hosts[curhost].addr.node, hosts[curhost].addr.point);
        p=GetBinkBsyName(&hosts[curhost].addr, binkout, my.zone);
        if (p==NULL) continue;
        strcpy(s,p);
        p=strrchr(s, '.');
        if (p) *p='\0';
        p=strrchr(s, PATHSEP);
        if (p)
        { *p++='\0';
          strcpy(loname, p);
        }
        else
          loname[0]='\0';
        debug(8, "Main: check *.?lo", s);
        d=opendir(s);
        if (d==NULL)
          logwrite('!', "Can't find dir %s!\n", s);
        else
        { while ((df=readdir(d))!=NULL)
          {
            if (strlen(df->d_name)!=12) continue;
            if (strnicmp(df->d_name, loname, 8)) continue;
            if (stricmp(df->d_name+10, "lo")) continue;
            if (df->d_name[8]!='.') continue;
            if (flo_only && stricmp(df->d_name+8, ".flo")) continue;
            debug(6, "Main: found %s" PATHSTR "%s", s, df->d_name);

            for (r=0;r<nsend;r++)
              if ((tosend[r].host==curhost) && (tosend[r].sem==BINK_SEM))
                break;
            if (r==nsend)
            { if (SetBinkSem(&hosts[curhost].addr,binkout,my.zone))
              { debug(6, "Can't set semaphore, lo-file skipped");
                break;
              }
              debug(8, "Main: set semaphore for %u:%u/%u.%u",
                    hosts[curhost].addr.zone, hosts[curhost].addr.net,
                    hosts[curhost].addr.node, hosts[curhost].addr.point);
              leavesem=0;
            }
            else
              leavesem=1;
            strcat(s, PATHSTR);
            strcat(s, df->d_name);
            f=myopen(s, O_TEXT|O_RDONLY);
            if (f==-1)
            { logwrite('?', "Can't open %s: %s!\n",s,strerror(errno));
              if (!leavesem)
              { debug(8, "Main: delete semaphore for %u:%u/%u.%u",
                      hosts[curhost].addr.zone, hosts[curhost].addr.net,
                      hosts[curhost].addr.node, hosts[curhost].addr.point);
                if (DelBinkSem(&hosts[i].addr, binkout,my.zone))
                  logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
              }
              retcode|=RET_WARN;
              *strrchr(s, PATHSEP)='\0';
              continue;
            }
            if (lseek(f, 0, SEEK_END)==0)
            { close(f);
              unlink(s);
              debug(6, "Main: zero-length LO-file deleted");
              if (!leavesem)
              { debug(8, "Main: delete semaphore for %u:%u/%u.%u",
                      hosts[curhost].addr.zone, hosts[curhost].addr.net,
                      hosts[curhost].addr.node, hosts[curhost].addr.point);
                if (DelBinkSem(&hosts[curhost].addr,binkout, my.zone))
                  logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
              }
              *strrchr(s, PATHSEP)='\0';
              continue;
            }
            lseek(f, 0, SEEK_SET);
            ibuf=0;
            while (hgets(str, sizeof(str), f, '\n'))
            { p=strchr(str, '\n');
              if (p) *p=0;
              p=str;
              if ((*p=='#') || (*p=='^'))
                p++;
              debug(8, "Main: attached file %s", p);
              if (access(p,0))
              { logwrite('?', "Can't find attached to %u:%u/%u.%u file %s!\n",
                   hosts[curhost].addr.zone, hosts[curhost].addr.net,
                   hosts[curhost].addr.node, hosts[curhost].addr.point, p);
                retcode|=RET_WARN;
                continue;
              }

              switch (str[0])
              { case '^': attrib=msgKFS;
                          break;
                case '#': attrib=msgTFS;
                          break;
                default:  attrib=0;
              }
              if (sendfile(p, curhost, attrib, BINK_SEM))
                break;
            }
            close(f);
            unlink(s);
            debug(6, "Main: delete %s", s);
            *strrchr(s, PATHSEP)='\0';
            /* remove semaphore if no files to send */
            /* (uucp or just FlushSend) */
            for (r=0; r<nsend; r++)
              if ((tosend[r].host==curhost) && (tosend[r].sem==BINK_SEM))
                break;
            if (r==nsend)
            { debug(8, "Main: delete semaphore for %u:%u/%u.%u", 
                    hosts[curhost].addr.zone, hosts[curhost].addr.net,
                    hosts[curhost].addr.node, hosts[curhost].addr.point);
              if (DelBinkSem(&hosts[curhost].addr, binkout, my.zone))
                logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
            }
          }
          closedir(d);
        }
        debug(8, "Main: check *.?ut", s);
        d=opendir(s);
        while (d && ((df=readdir(d))!=NULL))
        {
          if (strlen(df->d_name)!=12) continue;
          if (strnicmp(df->d_name, loname, 8)) continue;
          if (stricmp(df->d_name+10, "ut")) continue;
          if (df->d_name[8]!='.') continue;
          if (flo_only && stricmp(df->d_name+8, ".out")) continue;
          debug(6, "Main: found %s", df->d_name);
          for (r=0;r<nsend;r++)
            if ((tosend[r].host==curhost) && (tosend[r].sem==BINK_SEM))
              break;
          if (r==nsend)
          { if (SetBinkSem(&hosts[curhost].addr,binkout,my.zone))
            { debug(6, "Can't set semaphore, ut-file skipped");
              break;
            }
            debug(8, "Main: set semaphore for %u:%u/%u.%u",
                  hosts[curhost].addr.zone, hosts[curhost].addr.net,
                  hosts[curhost].addr.node, hosts[curhost].addr.point);
            leavesem=0;
          }
          else
            leavesem=1;
          strcat(s, PATHSTR);
          strcpy(str, s);
          strcat(str, df->d_name);
          { unsigned long i;
            for (i=time(NULL);; i++)
            { sprintf(strrchr(s, PATHSEP), PATHSTR "%08lx.pkt", i);
              if (access(s, 0)) break;
            }
          }
          if (rename(str, s))
          { logwrite('!', "Can't send %s to %u:%u/%u.%u!\n", str,
                 hosts[curhost].addr.zone, hosts[curhost].addr.net,
                 hosts[curhost].addr.node, hosts[curhost].addr.point);
            retcode|=RET_ERR;
            if (!leavesem)
            { debug(8, "Main: delete semaphore for %u:%u/%u.%u",
                    hosts[curhost].addr.zone, hosts[curhost].addr.net,
                    hosts[curhost].addr.node, hosts[curhost].addr.point);
              if (DelBinkSem(&hosts[curhost].addr, binkout, my.zone))
                logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
            }
            strcpy(s, str);
            *strrchr(s, PATHSEP)='\0';
            continue;
          }
          debug(6, "Main: %s renamed to %s", str, s);
          if (sendfile(s, curhost, msgKFS, BINK_SEM))
            break;
          strcpy(s, str);
          *strrchr(s, PATHSEP)='\0';
          /* remove semaphore if no files to send */
          /* (uucp or just FlushSend) */
          for (r=0;r<nsend;r++)
            if ((tosend[r].host==curhost) && (tosend[r].sem==BINK_SEM))
              break;
          if (r==nsend)
          { debug(8, "Main: delete semaphore for %u:%u/%u.%u", 
                  hosts[curhost].addr.zone, hosts[curhost].addr.net,
                  hosts[curhost].addr.node, hosts[curhost].addr.point);
            if (DelBinkSem(&hosts[curhost].addr, binkout, my.zone))
              logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
          }
        }
        if (d) closedir(d);
      }
      curhost=-1;
    }
#ifndef __MSDOS__
    /* look into LongBSO */
    if (lbso[0])
    {
      debug(4, "Checking LBSO");
      for (curhost=0; curhost<nhosts; curhost++)
      { char loname[9];
        debug(10, "Main: check attaches for %u:%u/%u.%u",
              hosts[curhost].addr.zone, hosts[curhost].addr.net,
              hosts[curhost].addr.node, hosts[curhost].addr.point);
        p=GetLBSOBsyName(&hosts[curhost].addr, hosts[curhost].domain, lbso);
        if (p==NULL) continue;
        strcpy(s, p);
        p=strrchr(s, '.');
        if (p) p[1]='\0';
        p=strrchr(s, PATHSEP);
        if (p)
        { *p++='\0';
          strcpy(loname, p);
        }
        else
          loname[0]='\0';
        debug(8, "Main: check *.List", s);
        d=opendir(s);
        if (d==NULL)
          logwrite('!', "Can't find dir %s!\n", s);
        else
        { while ((df=readdir(d))!=NULL)
          {
            if (strnicmp(df->d_name, loname, strlen(loname))) continue;
            if (stricmp(df->d_name+strlen(df->d_name)-5, ".list")) continue;
            if (flo_only && stricmp(df->d_name+strlen(loname), "normal.list"))
              continue;
            debug(6, "Main: found %s" PATHSTR "%s", s, df->d_name);

            for (r=0;r<nsend;r++)
              if ((tosend[r].host==curhost) && (tosend[r].sem==LBSO_SEM))
                break;
            if (r==nsend)
            { if (SetLBSOSem(&hosts[curhost].addr, hosts[curhost].domain, lbso))
              { debug(6, "Can't set semaphore, list-file skipped");
                break;
              }
              debug(8, "Main: set semaphore for %u:%u/%u.%u",
                    hosts[curhost].addr.zone, hosts[curhost].addr.net,
                    hosts[curhost].addr.node, hosts[curhost].addr.point);
              leavesem=0;
            }
            else
              leavesem=1;
            strcat(s, PATHSTR);
            strcat(s, df->d_name);
            f=myopen(s, O_TEXT|O_RDONLY);
            if (f==-1)
            { logwrite('?', "Can't open %s: %s!\n", s, strerror(errno));
              if (!leavesem)
              { debug(8, "Main: delete semaphore for %u:%u/%u.%u",
                      hosts[curhost].addr.zone,hosts[curhost].addr.net,
                      hosts[curhost].addr.node,hosts[curhost].addr.point);
                if (DelLBSOSem(&hosts[i].addr,hosts[i].domain,lbso))
                  logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
              }
              retcode|=RET_WARN;
              *strrchr(s, PATHSEP)='\0';
              continue;
            }
            if (lseek(f, 0, SEEK_END)==0)
            { close(f);
              unlink(s);
              debug(6, "Main: zero-length list-file deleted");
              if (!leavesem)
              { debug(8, "Main: delete semaphore for %u:%u/%u.%u",
                      hosts[curhost].addr.zone, hosts[curhost].addr.net,
                      hosts[curhost].addr.node, hosts[curhost].addr.point);
                if (DelLBSOSem(&hosts[curhost].addr, hosts[curhost].domain, lbso))
                  logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
              }
              *strrchr(s, PATHSEP)='\0';
              continue;
            }
            lseek(f, 0, SEEK_SET);
            ibuf=0;
            while (hgets(str, sizeof(str), f, '\n'))
            { p=strchr(str, '\n');
              if (p) *p=0;
              p=str;
              if ((*p=='#') || (*p=='^'))
                p++;
              else if (*p=='~')
              { debug(5, "Main: file %s already sent (prefix '~' in List-file)\n", p+1);
                continue;
              }
              debug(8, "Main: attached file %s", p);
              if (access(p, 0))
              { logwrite('?', "Can't find attached to %u:%u/%u.%u file %s!\n",
                   hosts[curhost].addr.zone, hosts[curhost].addr.net,
                   hosts[curhost].addr.node, hosts[curhost].addr.point,p);
                retcode|=RET_WARN;
                continue;
              }

              switch (str[0])
              { case '^': attrib=msgKFS;
                          break;
                case '#': attrib=msgTFS;
                          break;
                default:  attrib=0;
              }
              if (sendfile(p, curhost, attrib, LBSO_SEM))
                break;
            }
            close(f);
            unlink(s);
            debug(6, "Main: delete %s", s);
            *strrchr(s, PATHSEP)='\0';
            /* remove semaphore if no files to send */
            /* (uucp or just FlushSend) */
            for (r=0;r<nsend;r++)
              if ((tosend[r].host==curhost) && (tosend[r].sem==LBSO_SEM))
                break;
            if (r==nsend)
            { debug(8, "Main: delete semaphore for %u:%u/%u.%u", 
                    hosts[curhost].addr.zone, hosts[curhost].addr.net,
                    hosts[curhost].addr.node, hosts[curhost].addr.point);
              if (DelLBSOSem(&hosts[curhost].addr,hosts[curhost].domain,lbso))
                logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
            }
          }
          closedir(d);
        }
        debug(8, "Main: check *.Mail", s);
        d=opendir(s);
        while (d && ((df=readdir(d))!=NULL))
        {
          if (strnicmp(df->d_name, loname, strlen(loname))) continue;
          if (stricmp(df->d_name+strlen(df->d_name)-5, ".mail")) continue;
          if (flo_only && stricmp(df->d_name+strlen(loname), "normal.mail"))
            continue;
          debug(6, "Main: found %s", df->d_name);
          for (r=0;r<nsend;r++)
            if ((tosend[r].host==curhost) && (tosend[r].sem==LBSO_SEM))
              break;
          if (r==nsend)
          { if (SetLBSOSem(&hosts[curhost].addr, hosts[curhost].domain, lbso))
            { debug(6, "Can't set semaphore, mail-file skipped");
              break;
            }
            debug(8, "Main: set semaphore for %u:%u/%u.%u",
                  hosts[curhost].addr.zone, hosts[curhost].addr.net,
                  hosts[curhost].addr.node, hosts[curhost].addr.point);
            leavesem=0;
          }
          else
            leavesem=1;
          strcat(s, PATHSTR);
          strcpy(str, s);
          strcat(str, df->d_name);
          { unsigned long i;
            for (i=time(NULL);; i++)
            { sprintf(strrchr(s, PATHSEP), PATHSTR "%08lx.pkt", i);
              if (access(s,0)) break;
            }
          }
          if (rename(str, s))
          { logwrite('!', "Can't send %s to %u:%u/%u.%u!\n", str,
                 hosts[curhost].addr.zone, hosts[curhost].addr.net,
                 hosts[curhost].addr.node, hosts[curhost].addr.point);
            retcode|=RET_ERR;
            if (!leavesem)
            { debug(8, "Main: delete semaphore for %u:%u/%u.%u",
                    hosts[curhost].addr.zone, hosts[curhost].addr.net,
                    hosts[curhost].addr.node, hosts[curhost].addr.point);
              if (DelLBSOSem(&hosts[curhost].addr, hosts[curhost].domain, lbso))
                logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
            }
            strcpy(s, str);
            *strrchr(s, PATHSEP)='\0';
            continue;
          }
          debug(6, "Main: %s renamed to %s", str, s);
          if (sendfile(s, curhost, msgKFS, LBSO_SEM))
            break;
          strcpy(s, str);
          *strrchr(s, PATHSEP)='\0';
          /* remove semaphore if no files to send */
          /* (uucp or just FlushSend) */
          for (r=0;r<nsend;r++)
            if ((tosend[r].host==curhost) && (tosend[r].sem==LBSO_SEM))
              break;
          if (r==nsend)
          { debug(8, "Main: delete semaphore for %u:%u/%u.%u", 
                  hosts[curhost].addr.zone, hosts[curhost].addr.net,
                  hosts[curhost].addr.node, hosts[curhost].addr.point);
            if (DelLBSOSem(&hosts[curhost].addr, hosts[curhost].domain, lbso))
              logwrite('!', "Can't unlink semaphore: %s!\n", strerror(errno));
          }
        }
        if (d) closedir(d);
      }
      curhost=-1;
    }
#endif
    /* смотрим по каталогам */
    debug(4, "Main: check fileboxes");
    for(i=0;i<nhosts;i++)
    { if (hosts[i].dir[0])
        checkbox(hosts[i].dir, i);
      if (tboxes[0] &&
          hosts[i].addr.zone<0x400u && hosts[i].addr.net<0x8000u &&
          hosts[i].addr.net<0x8000u && hosts[i].addr.point<0x400u)
      { sprintf(s, "%s%c%c%c%c%c%c%c%c.%c%c", tboxes,
                dhex(hosts[i].addr.zone/32),  dhex(hosts[i].addr.zone%32),
                dhex(hosts[i].addr.net/1024), dhex((hosts[i].addr.net/32)%32), dhex(hosts[i].addr.net%32),
                dhex(hosts[i].addr.node/1024),dhex((hosts[i].addr.node/32)%32),dhex(hosts[i].addr.node%32),
                dhex(hosts[i].addr.point/32), dhex(hosts[i].addr.point%32));
        checkbox(s, i);
        if (!flo_only)
        { strcat(s, "h");
          checkbox(s, i);
        }
      }
#ifndef __MSDOS__
      if (tlboxes[0])
      { sprintf(s, "%s%hu.%hu.%hu.%hu", tlboxes,
                hosts[i].addr.zone, hosts[i].addr.net,
                hosts[i].addr.node, hosts[i].addr.point);
        checkbox(s, i);
        if (!flo_only)
        { strcat(s, ".h");
          checkbox(s, i);
        }
      }
      if (longboxes[0])
      { if (flo_only)
        { sprintf(s, "%s%s.%hu.%hu.%hu.%hu.%s", longboxes, hosts[i].domain,
                  hosts[i].addr.zone, hosts[i].addr.net,
                  hosts[i].addr.node, hosts[i].addr.point,
                  "normal");
          checkbox(s, i);
        }
        else
        { char *flavours[]={ "immediate", "crash", "direct", "normal", "hold" };
          int j;
          for (j=0; j<sizeof(flavours)/sizeof(flavours[0]); j++)
          { sprintf(s, "%s%s.%hu.%hu.%hu.%hu.%s", longboxes, hosts[i].domain,
                    hosts[i].addr.zone, hosts[i].addr.net,
                    hosts[i].addr.node, hosts[i].addr.point,
                    flavours[j]);
            checkbox(s, i);
          }
        }
      }
#endif
    }
    debug(5, "Main: call FlushSend");
    flushsend();
  }
  if (tosend)
    free(tosend);
  if (bypipe)
  { debug(3, "Main: call uudecode stdin");
    uudecode(NULL);
  }
  else if ((!norcv) && (filebox[0]!='\0'))
  { if (stat(filebox, &statbuf)==0)
    { if (statbuf.st_size>0)
      { debug(3, "Main: call uudecode %s", filebox);
        uudecode(filebox);
      }
      else
        debug(5, "Main: %s is zero-length, nothing to decode", filebox);
    }
    else
      debug(5, "Main: %s not exists, nothing to decode", filebox);
  }
  if ((!norcv) && (hbsy!=-1))
  { debug(3, "Main: call CheckTmp");
    checktmp();
  }
  if ((!nosend) && (hbsy!=-1))
  { debug(2, "Main: call resend");
    resend();
  }
  if (resc && rescan[0])
    touch(rescan);
  if (newecho && newechoflag[0])
    touch(newechoflag);
  if (hbsy!=-1)
  {
#ifdef UNIX
#ifdef HAVE_FLOCK
    flock(hbsy, LOCK_UN);
#endif
#endif
    close(hbsy);
    if (semdir[0])
      strcpy(str, semdir);
    else
      strcpy(str, tmpdir);
    addslash(str);
    strcat(str, BSYNAME);
    for (i=0; i<10; i++)
    { if (unlink(str)==0)
        break;
      if (errno==EACCES || errno==EAGAIN)
        sleep(1);
      else
        i=10; /* no more attempts */
    }
    if (i>=10)
      logwrite('!', "Can't unlink busy-flag %s: %s!\n", str, strerror(errno));
    else
      debug(6, "Main: busy-flag %s deleted", str);
  }
  debug(1, "Attuucp exiting");
  return 0;
}
