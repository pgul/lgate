/*
 * $Id$
 *
 * $Log$
 * Revision 2.4  2004/03/27 09:45:31  gul
 * Bugfix
 *
 * Revision 2.3  2001/01/26 17:24:35  gul
 * translate comments
 *
 * Revision 2.2  2001/01/25 18:41:39  gul
 * myname moved to debug.c
 *
 * Revision 2.1  2001/01/20 01:47:41  gul
 * fromname-field in forward.cfg is wildcard now
 *
 * Revision 2.0  2001/01/10 20:42:20  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef __OS2__
#define INCL_DOSPROCESS
#include <os2.h>
#endif
#include <libgate.h>

#ifndef W_OK
#define W_OK 2
#endif
#ifndef O_DENYALL
#define O_DENYALL  0
#define O_DENYNONE 0
#endif

#define MAXFORW 64
#define BUFSIZE 8192

struct message msghdr;
struct
  { uword fromzone, fromnet, fromnode, frompoint;
    uword destzone, destnet, destnode, destpoint;
    char fromname[sizeof(msghdr.to)+1];
    char destname[128];
  } forw[MAXFORW];
int nforw;
int r, i, firstline;
char str[512], s[80], flags[80];
char fromname[sizeof(msghdr.to)];
unsigned long attrib, attror, attrand, attrxor;
unsigned long *a;
char netdir[80], rescan[80];
unsigned ibuf;
char buffer[BUFSIZE];
uword pp, zz, resc;
char *p, *p1;
int f;
FILE *fout;
DIR *d;
struct dirent *df;

int getfidoaddr(char *s, uword *zone, uword *net, uword *node, uword *point)
{
  char c, *p;

  for (p=s; isdigit(*p) || (*p==':') || (*p=='/') || (*p=='.'); p++);
  c=*p;
  *p=0;
  p=strchr(s, ':');
  if (p==NULL)
  { s[strlen(s)]=c;
    return 1;
  }
  if (!isdigit(*s))
  { s[strlen(s)]=c;
    return 1;
  }
  if (!isdigit(p[1]))
  { s[strlen(s)]=c;
    return 1;
  }
  *zone=atoi(s);
  *net=atoi(p+1);
  p=strchr(p, '/');
  if (p==NULL)
  { s[strlen(s)]=c;
    return 1;
  }
  if (!isdigit(p[1]))
  { s[strlen(s)]=c;
    return 1;
  }
  *node=atoi(p+1);
  p=strchr(p, '.');
  if (p==NULL)
    *point=0;
  else
  { if (!isdigit(p[1]))
    { s[strlen(s)]=c;
      return 1;
    }
    *point=atoi(p+1);
  }
  s[strlen(s)]=c;
  return 0;
}

int config(char *argv[])
{
  myname=argv[0];
#ifdef UNIX
  strcpy(str, SYSCONFDIR);
  addslash(str);
  strcat(str, "forward.cfg");
#else
#ifdef __OS2__
  { PPIB pib;
    PTIB tib;
    myname=NULL;
    DosGetInfoBlocks(&tib, &pib);
    if (pib)
    { for (myname=pib->pib_pchenv; myname[0] || myname[1]; myname++);
      myname+=2;
    }
    if (myname==NULL || *myname=='\0')
      myname=argv[0];
  }
#endif
  strcpy(str, myname);
  p=strrchr(str, PATHSEP);
  if (p==NULL) p=str;
  p=strchr(p, '.');
  if (p==NULL)
  { puts("Invalid argv[0]!");
    return 13;
  }
  strcpy(p, ".cfg");
#endif
  fout=fopen(str, "r");
  if (fout==NULL)
  { printf("Can't find %s!\n", str);
    return 12;
  }
  netdir[0]=rescan[0]=0;
  nforw=0;
  attror=attrand=attrxor=0;
  while (fgets(str, sizeof(str), fout))
  { if (str[0]=='#') continue;
    p=strchr(str, ';');
    if (p) *p=0;
    for (p=str+strlen(str); p--!=str;)
    { if ((*p==' ') || (*p=='\n') || (*p=='\t'))
        *p=0;
      else
        break;
    }
    if (str[0]==0) continue;
    if (strnicmp(str, "netmail", 7)==0)
    { for(p=str+7; (*p==' ') || (*p=='\t'); p++);
      strncpy(netdir, p, sizeof(netdir)-2);
      netdir[sizeof(netdir)-2]=0;
      if (netdir[strlen(netdir)-1]==PATHSEP && strlen(netdir)>DISKPATH+1)
        netdir[strlen(netdir)-1]='\0';
      continue;
    }
    if (strnicmp(str, "rescan", 6)==0)
    { for(p=str+6; (*p==' ') || (*p=='\t'); p++);
      strncpy(rescan, p, sizeof(rescan)-1);
      rescan[sizeof(rescan)-1]=0;
      continue;
    }
    if (strnicmp(str, "attrib", 6)==0)
    { for(p=str+6; (*p==' ') || (*p=='\t'); p++);
      for (; *p; p++)
      { switch(*p)
        { case '+': a=&attror;
                    break;
          case '-': a=&attrand;
                    break;
          case '*': a=&attrxor;
                    break;
          default:  puts("Incorrect ATTRIB string in config!");
                    return 8;
        }
        p++;
        switch(tolower(p[0]))
        {
          case 'l': a[0]|=msgLOCAL;
                    break;
          case 't': a[0]|=msgFORWD;
                    break;
          case 'd': a[0]|=msgDIRECT;
                    break;
          case 'c': a[0]|=msgCRASH;
                    break;
          case 'i': a[0]|=msgIMM;
                    break;
          case 'r': a[0]|=msgREAD;
                    break;
          case 'f': a[0]|=msgFREQ;
                    break;
          case 'a': a[0]|=msgFILEATT;
                    break;
          case 'h': a[0]|=msgHOLD;
                    break;
          case 'p': a[0]|=msgPRIVATE;
                    break;
          case 'k': a[0]|=msgKILLSENT;
                    break;
          case 0:   break;
          default:  printf("Unknown attribute '%c' ignored!\n", *p);
                    break;
        }
        if (*p==0) break;
      }
      attrand=~attrand;
      continue;
    }
    if (strnicmp(str, "forward", 7)==0)
    { if (nforw==MAXFORW)
      { puts("Too many forward strings! Rest ignored!");
        continue;
      }
      for(p=str+7; (*p==' ') || (*p=='\t'); p++);
      if (getfidoaddr(p, &forw[nforw].fromzone, &forw[nforw].fromnet,
          &forw[nforw].fromnode, &forw[nforw].frompoint))
      {
errforw:puts("Incorrect forward string ignored:");
        puts(str);
        continue;
      }
      p=strpbrk(p, " \t");
      if (p==NULL) goto errforw;
      for(p++; (*p==' ') || (*p=='\t'); p++);
      if (getfidoaddr(p, &forw[nforw].destzone, &forw[nforw].destnet,
          &forw[nforw].destnode, &forw[nforw].destpoint))
        goto errforw;
      forw[nforw].destname[0]=forw[nforw].fromname[0]=0;
      p=strpbrk(p, " \t");
      if (p==NULL)
      { nforw++;
        continue;
      }
      for(p++; (*p==' ') || (*p=='\t'); p++);
      if (*p==0)
      { nforw++;
        continue;
      }
      if (*p=='\"')
      { p++;
        p1=strchr(p, '\"');
        if (p1==NULL)
          goto errforw;
      }
      else
      { p1=strpbrk(p, " \t");
        if (p1==NULL)
        { p1=p+strlen(p);
          p1[1]=0;
        }
      }
      *p1=0;
      strncpy(forw[nforw].fromname, p, sizeof(forw[0].fromname)-1);
      forw[nforw].fromname[sizeof(forw[0].fromname)-1]=0;
      p=p1+1;
      for(; (*p==' ') || (*p=='\t'); p++);
      if (*p==0)
      { nforw++;
        continue;
      }
      if (*p=='\"')
      { p++;
        p1=strchr(p, '\"');
        if (p1==NULL)
          goto errforw;
      }
      else
      { p1=strpbrk(p, " \t");
        if (p1==NULL)
          p1=p+strlen(p);
      }
      *p1=0;
      strncpy(forw[nforw].destname, p, sizeof(forw[0].destname)-1);
      forw[nforw].destname[sizeof(forw[0].destname)-1]=0;
      nforw++;
      continue;
    }
    puts("Unknown string in config ignored:");
    puts(str);
  }
  return 0;
}

unsigned potolok;

char hgetc(void)
{
  if ((ibuf==BUFSIZE) || (ibuf==potolok))
  { potolok=read(f, buffer, BUFSIZE);
    ibuf=0;
  }
  if (potolok==0)
    return 0;
  return buffer[ibuf++];
}

int hgets(void)
{
  int i;
  char r;

  str[0]=0;
  for(i=0; i<sizeof(str)-2;)
  { r=hgetc();
    str[i++]=(char)r;
    if (r==0)
      return i-1;
    if (r=='\r')
      break;
    if (r=='\n')
      break;
  }
  str[i]=0;
  return i;
}

static char *stristr(char *s1, char *s2)
{ int i, l1, l2;

  l1=strlen(s1);
  l2=strlen(s2);
  for (i=0; i<=l1-l2; i++)
  { if (strnicmp(s1+i, s2, l2)==0)
      return s1+i;
  }
  return NULL;
}

int main(int argc, char *argv[])
{
  r=config(argv);
  if (r) return r;
  resc=0;
  d=opendir(netdir);
  if (d==NULL)
  { printf("Can't read directory %s!\n", netdir);
    return 1;
  }
  while ((df=readdir(d))!=NULL)
  {
    if (df->d_name[0]=='.') continue;
    if (strlen(df->d_name)<5) continue;
    for (p=df->d_name; isdigit(*p); p++);
    if (stricmp(p, ".msg")) continue;
    strcpy(str, netdir);
    addslash(str);
    strcat(str, df->d_name);
    f=open(str, O_BINARY|O_RDONLY|O_DENYNONE);
    if (f==-1) continue;
#if 0
    for (i=0; i<5; i++)
      if (flock(f, LOCK_EX | LOCK_NB))
        sleep(1);
      else
        break;
    if (i==5)
    { close(f);
      continue;
    }
#endif
    read_msghdr(f, &msghdr);
    if (msghdr.attr & msgSENT)
    {
#if 0
      flock(f, LOCK_UN);
#endif
      close(f);
      continue;
    }
    for (i=0; i<nforw; i++)
      if ((msghdr.dest_net==forw[i].fromnet) &&
          (msghdr.dest_node==forw[i].fromnode))
      { if (forw[i].fromname[0])
        {
#if 0
          if (stristr(msghdr.to, forw[i].fromname))
#elif 0
          if (strnicmp(forw[i].fromname, msghdr.to, sizeof(msghdr.to))==0)
#else
          if (cmpaddr(msghdr.to, forw[i].fromname)==0)
#endif
            break;
        }
        else
          break;
      }
    if (i==nforw)
    {
#if 0
      flock(f, LOCK_UN);
#endif
      close(f);
      continue;
    }
    /* read the message, check point number */
    ibuf=BUFSIZE;
    attrib=msghdr.attr;
    zz=0;
    pp=0;
    flags[0]=0;
    while (hgets())
    { if (str[0]!=1) continue;
      if (strncmp(str+1, "INTL ", 5)==0)
      { /* Check dest zone */
        zz=atoi(str+5);
        continue;
      }
      if (strncmp(str+1, "TOPT ", 5)==0)
      { pp=atoi(str+5);
        continue;
      }
      if (strncmp(str+1, "FLAGS ", 6)==0)
      {
        for (p=str+6; (*p!='\r') && (*p!=0); p+=3)
        { while (*p==' ') p++;
          if (strncmp(p, "DIR", 3)==0)
          { attrib|=msgDIRECT;
            continue;
          }
          /*
          if (strncmp(p, "LOK")
          { attrib|=msgLOCK;
            continue;
          }
          */
          strcat(flags, " ");
          strncpy(flags+strlen(flags), p, 3);
        }
      }

    }
    if ((forw[i].frompoint!=pp) || ((forw[i].fromzone!=zz) && (zz!=0)))
    { for (i++; i<nforw; i++)
      { if (((forw[i].fromzone==zz) || (zz==0)) &&
             (forw[i].fromnet==msghdr.dest_net) &&
             (forw[i].fromnode==msghdr.dest_node) &&
             (forw[i].frompoint==pp))
        { if (forw[i].fromname[0])
          {
            if (stristr(msghdr.to, forw[i].fromname))
/*          if (strnicmp(forw[i].fromname, msghdr.to, sizeof(msghdr.to))==0)
*/
              break;
          }
          else
            break;
        }
      }
      if (i==nforw)
      {
#if 0
        flock(f, LOCK_UN);
#endif
        close(f);
        continue;
      }
    }
    /* need to forward */
    strcpy(fromname, msghdr.to);
    attrib&=attrand;
    attrib|=attror;
    attrib^=attrxor;
    if (forw[i].destname[0])
    { if (strlen(forw[i].destname)>=sizeof(msghdr.to))
      { if (strchr(forw[i].destname, '@'))
          strcpy(msghdr.to, "uucp");
        else
        { forw[i].destname[sizeof(msghdr.to)-1]=0;
          strcpy(msghdr.to, forw[i].destname);
        }
      }
      else
      { forw[i].destname[sizeof(msghdr.to)-1]=0;
        strcpy(msghdr.to, forw[i].destname);
      }
    }
    msghdr.attr=(unsigned)attrib;
    msghdr.dest_zone=forw[i].destzone;
    msghdr.dest_net=forw[i].destnet;
    msghdr.dest_node=forw[i].destnode;
    msghdr.dest_point=forw[i].destpoint;
    lseek(f, sizeof(msghdr), SEEK_SET);
    ibuf=BUFSIZE;
    strcpy(s, netdir);
    addslash(s);
    strcat(s, "TMP_FORW.MSG");
    if (!access(s, 0))
      unlink(s);
    fout=myfopen(s, "wb");
    if (fout==NULL)
    { printf("ERROR! Can't open %s!\n", s);
      close(f);
      continue;
    }
    msghdr_byteorder(&msghdr);
    fwrite(&msghdr, sizeof(msghdr), 1, fout);
    firstline=1;
    while (hgets())
    { if (str[0]==1)
      { if (strncmp(str+1, "INTL ", 5)==0)
        { p=str+5;
          while (*p==' ') p++;
          p=strchr(p, ' ');
          if ((p==NULL) || (*p=='\r'))
            continue;
          while (*p==' ') p++;
          fprintf(fout, "\x01INTL %u:%u/%u %s",
                  forw[i].destzone, forw[i].destnet, forw[i].destnode, p);
          continue;
        }
        if (strncmp(str+1, "TOPT ", 5)==0)
          continue;
        if (strncmp(str+1, "FLAGS ", 6)==0)
          continue;
      }
      if (firstline && (str[0]!=1))
      {
fstln:  if (forw[i].destpoint)
          fprintf(fout, "\1TOPT %u\r", forw[i].destpoint);
        if (flags[0] || (attrib >> 16))
        { fputs("\x01""FLAGS", fout);
          fputs(flags, fout);
          if (attrib & msgDIRECT)
            fputs(" DIR", fout);
          fputs("\r", fout);
        }
        fprintf(fout, "\x01Resd addressed to ");
        if (forw[i].destname[0])
          fprintf(fout, "%s ", fromname);
        fprintf(fout, "%u:%u/%u",
                forw[i].fromzone, forw[i].fromnet, forw[i].fromnode);
        if (forw[i].frompoint)
          fprintf(fout, ".%u", forw[i].frompoint);
        fputs("\r", fout);
        if (strlen(forw[i].destname)>=sizeof(msghdr.to))
          fprintf(fout, "To: %s\r", forw[i].destname);
        firstline=0;
      }
      if ((fputs(str, fout)==EOF) && str[0])
      {
errspace:
        fclose(fout);
#if 0
        flock(f, LOCK_UN);
#endif
        close(f);
        unlink(s);
        closedir(d);
        puts("ERROR! Disk full!");
        if (resc && rescan[0])
        {
          fout=fopen(rescan, "w");
          if (fout) fclose(fout);
        }
        return 7;
      }
      continue;
    }
    if (firstline) goto fstln;
    if (str[0])
      if (fputs(str, fout)==EOF)
        goto errspace;
    if (fclose(fout)==EOF)
      goto errspace;
#if 0
    flock(f, LOCK_UN);
#endif
    close(f);
    strcpy(str, netdir);
    addslash(str);
    strcat(str, df->d_name);
    unlink(str);
    rename(s, str);
    printf("Forwarded %u:%u/%u", forw[i].fromzone,
           forw[i].fromnet, forw[i].fromnode);
    if (forw[i].frompoint)
      printf(".%u", forw[i].frompoint);
    if (forw[i].destname[0])
      printf(" %s", fromname);
    else
      printf(" %s", msghdr.to);
    printf(" to %u:%u/%u",
           forw[i].destzone, forw[i].destnet, forw[i].destnode);
    if (forw[i].destpoint)
      printf(".%u", forw[i].destpoint);
    if (forw[i].destname[0])
      printf(" %s", forw[i].destname);
    puts("");
    resc=1;
  }
  closedir(d);
  if (resc && rescan[0])
  {
    fout=fopen(rescan, "w");
    if (fout) fclose(fout);
  }
  return 0;
}
