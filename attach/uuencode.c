#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#include <stdio.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <string.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#include <sys/stat.h>
#include <ctype.h>
#include <fidolib.h>
#include "exec.h"
#include "gate.h"

time_t curtime;
struct tm *curtm;

char sstr[2048], addrlist[1024];
static char nearfname[FNAME_MAX], tmpname[FNAME_MAX], tmpuue[FNAME_MAX];
static char cmdline[FNAME_MAX];
static struct stat statbuf;
static struct tm ftime;
static enctype enc;
static int  seqf=0;
static char part_id[128];
static char sendhosts[128];
static int  nsendhosts;

#ifdef __MSDOS__
static int exec_rmail(int h)
{ int r, oldstdin;

  debug(5, "exec_rmail('%s')", addrlist);
  if (uupcver==KENDRA)
    sprintf(sstr, "%s %s", rmail, addrlist);
  else if (uupcver==SENDMAIL)
    sprintf(sstr, "%s -f %s@%s %s", rmail, user, local, addrlist);
  else
    /* sprintf(sstr, "-u -l -%c %s", (uupcver==5) ? 'f' : 'R', user); */
    sprintf(sstr, "%s -u -l", rmail);
  /* redirect h->stdin */
  /* setmode(h, O_RDONLY|O_BINARY|O_DENYWRITE);
  */
  fflush(stdin);
  oldstdin=dup(fileno(stdin));
  lseek(h, 0, SEEK_SET);
  dup2(h, fileno(stdin));
  debug(5, "Exec_Rmail: execute %s %s", rmail, sstr);
  r=swap_system(sstr);
  fflush(stdout);
  dup2(oldstdin, fileno(stdin));
  close(oldstdin);
  if (r && (r!=48))
  { if (r==-1)
      logwrite('?', "Can't exec rmail: %s\n", strerror(errno));
    else
      logwrite('?', "Rmail retcode is %d\n", r);
    return 1;
  }
  return 0;
}

#else /* not MSDOS */
static int rmail_pid;

static FILE *exec_rmail(char *addrlist)
{ int r;
  FILE *f;

  debug(5, "exec_rmail('%s')", addrlist);
  if (uupcver==KENDRA)
    sprintf(sstr, "%s %s", rmail, addrlist);
  else if (uupcver==SENDMAIL)
    sprintf(sstr, "%s -f %s@%s %s", rmail, user, local, addrlist);
  else
    /* sprintf(sstr, "%s -u -%c %s %s", rmail, (uupcver==5)?'f':'R', user, addrlist); */
    sprintf(sstr, "%s -u %s", rmail, addrlist);
  rmail_pid=pipe_system(&r, NULL, sstr);
  if (rmail_pid==-1)
  { logwrite('?', "Can't execute rmail!\n");
    return NULL;
  }
  setmode(r, O_BINARY);
  f=fdopen(r, "wb");
  if (f==NULL)
  { logwrite('?', "Can't fdopen pipe: %s!\n", strerror(errno));
    close(r);
    waitpid(rmail_pid, &r, 0);
    rmail_pid=-1;
  }
  return f;
}

static int wait_rmail(void)
{ int r;

  debug(5, "wait_rmail");
  if (rmail_pid==-1)
  { /* confirm requested, stdin saved in tmpname */
    int h, savein;
    
    h=open(tmpname, O_BINARY|O_RDONLY);
    if (h==-1)
    { unlink(tmpname);
      return h;
    }
    savein=dup(fileno(stdin));
    dup2(h, fileno(stdin));
    close(h);
    if (uupcver==KENDRA)
      sprintf(sstr, "%s %s", rmail, addrlist);
    else if (uupcver==SENDMAIL)
      sprintf(sstr, "%s -f %s@%s %s", rmail, user, local, addrlist);
    else
      sprintf(sstr, "%s -u %s", rmail, addrlist);
    r=swap_system(sstr);
    dup2(savein, fileno(stdin));
    close(savein);
    if (r) unlink(tmpname);
#ifdef __OS2__
    else
    { easet(tmpname, "To", addrlist);
      sprintf(sstr, "<%s>", part_id);
      easet(tmpname, "Message-Id", sstr);
      curtime=time(NULL);
      curtm=localtime(&curtime);
      sprintf(sstr, "%s, %2u %s %u  %02u:%02u:%02u %c%02u00",
          weekday[curtm->tm_wday], curtm->tm_mday,
          montable[curtm->tm_mon], curtm->tm_year+1900,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          (tz<=0) ? '+' : '-', (tz<0) ? -tz : tz);
      easet(tmpname, "Date", sstr);
    }
#endif
  }
  else
  { waitpid(rmail_pid, &r, 0);
    r&=0xffff;
    r=(r << 8) | (r >> 8);
    r &= 0xffff;
  }
  return r;
}

#endif

static FILE *puthdr(int parts, int curpart, char *passwd, long confirm)
{ FILE *h;
  char *p, *fname;

  debug(5, "PutHdr");
#ifdef __MSDOS__
  h=myfopen(tmpname, "wb+");
  if (h==NULL)
  { logwrite('?', "Can't create file %s, reason: %s\n", tmpname, strerror(errno));
    return NULL;
  }
  if ((uupcver!=SENDMAIL) && (uupcver!=KENDRA))
  { fputs("rmail\n--\n", h);
    for (p=addrlist; *p; p++)
      fputc((*p==' ') ? '\n' : *p, h);
    fputs("\n<<NULL>>\n", h);
  }
#else /* OS/2, unix */
  if (!confirm)
  { h=exec_rmail(addrlist);
    if (h==NULL)
      return h;
  }
  else
  { h=myfopen(tmpname, "wb+");
    if (h==NULL)
    { logwrite('?', "Can't create file %s, reason: %s\n", tmpname, strerror(errno));
      return NULL;
    }
    rmail_pid=-1;
  }
#endif
  curtime=time(NULL);
  curtm=localtime(&curtime);
  if (curpart==1)
    sprintf(part_id, "%08lx-%04x-%04x@%s",
            time(NULL), (unsigned)getpid(), seqf++, local);
  if (uupcver != SENDMAIL)
    fprintf(h, "From %s %s %s %02u %02u:%02u:%02u %u\n",
            user, weekday[curtm->tm_wday],
            montable[curtm->tm_mon], curtm->tm_mday,
            curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
            curtm->tm_year+1900);
  fprintf(h, "From: %s@%s\n", user, local);
  fprintf(h, "Date: %s, %2u %s %u  %02u:%02u:%02u %c%02u00\n",
          weekday[curtm->tm_wday], curtm->tm_mday,
          montable[curtm->tm_mon], curtm->tm_year+1900,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          (tz<=0) ? '+' : '-', (tz<0) ? -tz : tz);
  if (parts==1)
    fprintf(h, "Message-Id: <%s>\n", part_id);
  else
    fprintf(h, "Message-Id: <%08lx-%04x-%04x@%s>\n",
              time(NULL), (unsigned)getpid(), seqf++, local);
  fname=basename(nearfname);
  if ((parts>1) && (enc!=ENC_BASE64))
    fprintf(h, "Subject: %s, %u/%u; %02u.%02u.%02u %02u:%02u:%02u\n",
            fname,curpart, parts,
            ftime.tm_mday, ftime.tm_mon+1, ftime.tm_year%100,
            ftime.tm_hour, ftime.tm_min, ftime.tm_sec);
  else
    fprintf(h, "Subject: %s; %02u.%02u.%02u %02u:%02u:%02u\n",
            fname, ftime.tm_mday, ftime.tm_mon+1, ftime.tm_year%100,
            ftime.tm_hour, ftime.tm_min, ftime.tm_sec);
  fputs("To: ", h);
  for (p=addrlist; *p;)
  { if (isspace(*p) || (*p==','))
    { fputs(",\n\t", h);
      while (isspace(*p) || (*p==','))
        p++;
      continue;
    }
    fputc(*p++, h);
  }
  fputc('\n', h);
  fprintf(h, "X-FTNattach-Version: " FORMATVER " (LuckyGate " VER ")\n");
  fputs("X-Mailer: " NAZVA "\n", h);
  if (passwd[0])
    fprintf(h, "X-Password: %s\n", passwd);
  if (confirm && curpart<=1)
    fprintf(h, "X-Confirm-To: %s@%s\n", user, local);
  if (pgpsig && curpart==1)
  { int i;
    fprintf(h, "X-PGP-Sig:");
    for (i=0; pgpsig[i]; i++)
    { if (i%60==0)
        fputs("\n\t", h);
      fputc(pgpsig[i], h);
    }
    fputc('\n', h);
  }
  if (precedence[0])
    fprintf(h, "Precedence: %s\n", precedence);
  /* if (enc==ENC_BASE64) */
  { fprintf(h, "Mime-Version: 1.0\n");
    if (parts>1)
      fprintf(h, "Content-Type: message/partial; id=\"%s\";\n"
                 "              number=%d; total=%d\n", part_id, curpart, parts);
    if ((parts>1) && (curpart==1))
      fprintf(h, "\n");
    if ((parts<=1) || (curpart==1))
    { fprintf(h, "Content-Type: application/octet-stream; name=\"%s\"; crc32=%08lX\n",
              fname, fcrc32);
      fputs("Content-Transfer-Encoding: ", h);
      switch (enc)
      { case ENC_BASE64: fputs("base64\n", h);     break;
        case ENC_UUE:    fputs("x-uuencode\n", h); break;
        case ENC_PGP:    fputs("x-pgp\n", h);      break;
        default:         fputs("binary\n", h);     break; /* never happens */
      }
      fprintf(h, "Content-Disposition: attachment; filename=\"%s\"\n", fname);
    }
  }
  fprintf(h, "\n");
  return h;
}

static int exec_uue(FILE *to)
{
  int newh, oldstdout, oldstdin, r;

  /* copy the file to temp to avoid collisions uuencode.exe with mailer */
  debug(4, "Exec_Uue, file %s", nearfname);
  
  strcpy(sstr, tmpdir);
  addslash(sstr);
  strcat(sstr, basename(nearfname));
  if (uuencode_fmt[0] && (enc==ENC_UUE))
  { if (copyfile(nearfname, sstr))
    { logwrite('?', "Can't uuencode %s: error copy file to %s!\n",
               nearfname, sstr);
      return 0;
    }
    strcpy(cmdline, uuencode_fmt);
#ifndef UNIX
    strlwr(cmdline);
#endif
    chsubstr(cmdline, "%infile", sstr);
    /* redirect h->stdout */
    fflush(stdout);
    oldstdout=dup(fileno(stdout));
    fflush(to);
    dup2(fileno(to), fileno(stdout));
    fclose(to);
    debug(5, "exec_uue: run external uuencode");
    r=swap_system(cmdline);
    /* restore stdout */
    fflush(stdout);
    newh=dup(fileno(stdout));
    dup2(oldstdout, fileno(stdout));
    close(oldstdout);
    if (!quiet)
      puts("");
    unlink(sstr);
  }
  else if (enc==ENC_PGP)
  { /* pgp +batchmode -eaf gul@lucky.carrier.kiev.ua -u fnet@lucky.carrier.kiev.ua < lgate.inf > lgate.out */
    newh=open(nearfname, O_BINARY|O_RDONLY); /* avoid lock collisions */
    if (newh==-1)
    { logwrite('?', "Can't pgpencode %s: error open file!\n",
               nearfname);
      return 0;
    }
    strcpy(cmdline, pgpenc_fmt);
#ifndef UNIX
    strlwr(cmdline);
#endif
    chsubstr(cmdline, "%remote", addrlist);
    sprintf(sstr, "%s@%s", user, local);
    chsubstr(cmdline, "%myaddr", sstr);
    /* redirect stdout */
    fflush(stdout);
    oldstdout=dup(fileno(stdout));
    fflush(to);
    dup2(fileno(to), fileno(stdout));
    fclose(to);
    /* redirect stdin */
    oldstdin=dup(fileno(stdin));
    dup2(newh, fileno(stdin));
    close(newh);
    debug(5, "exec_uue: run pgp encrypt");
    r=swap_system(cmdline);
    /* restore stdout */
    fflush(stdout);
    newh=dup(fileno(stdout));
    dup2(oldstdout, fileno(stdout));
    close(oldstdout);
    /* restore stdin */
    dup2(oldstdin, fileno(stdin));
    close(oldstdin);
    unlink(sstr);
    if (!quiet) fputs("\n", stderr);
  }
  else
  { /* internal uuencode */
    if (enc==ENC_BASE64)
    { debug(5, "exec_uue: run internal base64");
      r=do_base64(nearfname, to);
    }
    else
    { debug(5, "exec_uue: run internal uuencode");
      r=do_uuencode(nearfname, to);
    }
    fflush(to);
    newh=dup(fileno(to));
    fclose(to);
  }
  if (r)
  { logwrite('?', "Can't encode %s: %s retcode is %d.\n",
             nearfname, enc==ENC_PGP ? "pgp" : "uuencode", r);
    close(newh);
    return 0;
  }
  if (newh==-1)
    newh=0;
  debug(5, "exec_uue: done");
  return newh;
}

static void delsem(void)
{ int i, j;

  for (i=0; i<nsendhosts; i++)
  { if (tosend[sendhosts[i]].sem==NO_SEM)
      continue;
    if (tosend[sendhosts[i]].host==curhost)
      continue; /* lo processing */
    for (j=0; j<nsend; j++)
      if ((tosend[j].sem==tosend[sendhosts[i]].sem) &&
          (tosend[j].host==tosend[sendhosts[i]].host) &&
          ((tosend[j].attr & msgSENT)==0))
        break;
    if (j<nsend) continue;
    debug(8, "delsem: delete semaphore for %u:%u/%u.%u",
          hosts[tosend[sendhosts[i]].host].addr.zone,
          hosts[tosend[sendhosts[i]].host].addr.net,
          hosts[tosend[sendhosts[i]].host].addr.node,
          hosts[tosend[sendhosts[i]].host].addr.point);
    if (tosend[sendhosts[i]].sem==FD_SEM)
      j=DelFDSem(&hosts[tosend[sendhosts[i]].host].addr, semdir);
    else /* bink */
      j=DelBinkSem(&hosts[tosend[sendhosts[i]].host].addr, binkout, my.zone);
    if (j)
      logwrite('!', "Can't unlink semaphore: %s\n", strerror(errno));
  }
}

void flushsend(void)
{ int i, j;
  FILE *h, *hin;
  int  cursize;
  long fsize, partsize, fpos;
  int  parts, curpart;
  int  hsize, sign;
  struct tm *pftime;

  debug(5, "FlushSend");
  for (i=0; i<nsend; i++)
  { if (tosend[i].attr & msgSENT) continue;
    strcpy(addrlist, hosts[tosend[i].host].host);
    strcpy(nearfname, tosend[i].filename);
    nsendhosts=1;
    sendhosts[0]=i;
    if (stat(nearfname, &statbuf)==0)
    { pftime=localtime(&statbuf.st_mtime);
      memcpy(&ftime, pftime, sizeof(ftime));
      curtime=time(NULL);
      curtm=localtime(&curtime);
    }
    else
    { logwrite('?', "%s not sent to %s: file not found!\n", nearfname, addrlist);
      tosend[i].attr|=msgSENT;
      delsem();
      continue;
    }
    debug(8, "FlushSend: %s for %s", nearfname, addrlist);
    fcrc32=filecrc32(nearfname);
    tosend[i].attr|=msgSENT;
    fsize=(statbuf.st_size*4)/3; /* size after uuencode (not excect) */
    cursize=hosts[tosend[i].host].size;
    sign=hosts[tosend[i].host].pgpsig;
    if (pgpsig)
    { free(pgpsig);
      pgpsig=NULL;
    }
    if ((tosend[i].attr & (msgTFS | msgKFS))==0 &&
        hosts[tosend[i].host].passwd[0]=='\0' &&
        hosts[tosend[i].host].confirm==0)
      for (j=i+1; j<nsend; j++)
      { if (tosend[j].attr & msgSENT) continue;
        if (stricmp(tosend[i].filename,tosend[j].filename)) continue;
        if (hosts[tosend[j].host].passwd[0]) continue;
        if (hosts[tosend[j].host].confirm) continue;
        if (strlen(addrlist)+strlen(hosts[tosend[j].host].host)+2>=sizeof(addrlist))
          continue;
        if (hosts[tosend[i].host].enc!=hosts[tosend[j].host].enc)
          continue;
        if (hosts[tosend[i].host].enc==ENC_PGP)
          continue;
        hsize=hosts[tosend[j].host].size;
        if (((cursize==0) && (hsize==0)) || /* do not split */
               (cursize*1024l>=fsize) ||      /* can split, but do not */
               (hsize*1024l>=fsize) ||        /* correct any case */
               ((cursize>0) && (hsize>0)))    /* split to minimum */
          { if (cursize>0)
            { if (hsize==0)
                cursize=0;
              else if (hsize<cursize)
                cursize=hsize;
            }
            sign |= hosts[tosend[j].host].pgpsig;
            strcat(addrlist, " ");
            strcat(addrlist, hosts[tosend[j].host].host);
            tosend[j].attr|=msgSENT;
            sendhosts[nsendhosts++]=j;
            if (tosend[j].attr & (msgKFS | msgTFS))
            { tosend[i].attr|=tosend[j].attr;
              break;
            }
            if (nsendhosts==sizeof(sendhosts)/sizeof(sendhosts[0]))
              break;
          }
        }
    if (cursize*1024>=fsize)
      cursize=0;
    /* send nearfname to addrlist */
    curtime=time(NULL);
    curtm=localtime(&curtime);
    strcpy(sstr, (cursize || hosts[tosend[i].host].confirm==0) ? tmpdir : sentdir);
    addslash(sstr);
    strcat(sstr, TMPSENT);
    mktempname(sstr, tmpname);
    if (!access(tmpname, 0))
      unlink(tmpname);
    enc=hosts[tosend[i].host].enc;
    if (sign)
    { /* get pgp signature */
      pgpsig=getsign(nearfname);
    }
    /* put message header */
    if (cursize==0)
    { h=puthdr(0, 0, hosts[tosend[i].host].passwd, hosts[tosend[i].host].confirm);
      if (h==NULL)
      { logwrite('?', "%s (%lu bytes) not sent to %s. :-(\n",
                 nearfname, statbuf.st_size, addrlist);
        movebad(nearfname, tosend[i].attr);
        delsem();
        if (pgpsig) free(pgpsig);
        pgpsig=NULL;
        continue;
      }
    }
    else
    { debug(5, "FlushSend: split file, partsize=%dK", cursize);
      h=myfopen(tmpname, "wb+");
      if (h==NULL)
      { logwrite('?', "Can't create %s: %s!\n", tmpname, strerror(errno));
        logwrite('?', "%s (%lu bytes) not sent to %s. :-(\n",
                 nearfname, statbuf.st_size, addrlist);
        movebad(nearfname, tosend[i].attr);
        delsem();
        continue;
      }
    }
    j=exec_uue(h);
    if (j==0)
    {
uuefail:
      logwrite('?', "%s (%lu bytes) not sent to %s. :-(\n",
               nearfname, statbuf.st_size, addrlist);
      unlink(tmpname);
      movebad(nearfname, tosend[i].attr);
      delsem();
      continue;
    }
    if (cursize==0)
    {
#ifdef __MSDOS__
      if (exec_rmail(j))
      { close(j);
        goto uuefail;
      }
      close(j);
      if (!hosts[tosend[i].host].confirm)
        if (unlink(tmpname))
          logwrite('!', "Can't delete %s: %s!\n", tmpname, strerror(errno));
#else
      close(j);
      if (wait_rmail())
        goto uuefail;
#endif
    }
    else
    { /* split and/or confirm */
      long len=lseek(j, 0, SEEK_END);
      strcpy(tmpuue, tmpname);
      parts=(int)((len-1)/(1024l*cursize))+1;
      debug(8, "FlushSend: total %d parts", parts);
      partsize=(len/parts)-32; /* 32 - half of line length */
      hin=fdopen(j, "rb");
      fseek(hin, 0, SEEK_SET);
      for (curpart=1; curpart<=parts; curpart++)
      { strcpy(sstr, hosts[tosend[i].host].confirm ? sentdir : tmpdir);
        addslash(sstr);
        strcat(sstr, hosts[tosend[i].host].confirm ? TMPSENT : TMPUUE);
        mktempname(sstr, tmpname);
        h=puthdr(parts, curpart, hosts[tosend[i].host].passwd, hosts[tosend[i].host].confirm);
        if (h==NULL)
        { fclose(hin);
          unlink(tmpuue);
          goto uuefail;
        }
        fpos=0;
        while (fgets(sstr, sizeof(sstr), hin))
        { if (fputs(sstr, h)==EOF)
          { fclose(h);
            fclose(hin);
            unlink(tmpuue);
            goto uuefail;
          }
          fpos+=strlen(sstr);
          if ((fpos>partsize) && (curpart!=parts))
            break;
        }
        fflush(h);
#ifdef __MSDOS__
        j=exec_rmail(fileno(h));
        fclose(h);
        if (!hosts[tosend[i].host].confirm)
          if (unlink(tmpname))
            logwrite('!', "Can't delete %s: %s!\n", tmpname, strerror(errno));
#else
        fclose(h);
        j=wait_rmail();
#endif
        if (j)
        { fclose(hin);
          unlink(tmpuue);
          goto uuefail;
        }
      }
      fclose(hin);
      unlink(tmpuue);
    }
    if (pgpsig) free(pgpsig);
    pgpsig=NULL;
    logwrite('$', "File %s size %lu sent to %s\n", nearfname, statbuf.st_size, addrlist);
    retcode|=RET_SENT;
    if (tosend[i].attr & msgKFS)
    { logwrite('$', "Deleting sent file %s\n", nearfname);
      unlink(nearfname);
    }
    else if (tosend[i].attr & msgTFS)
    { logwrite('$', "Truncating sent file %s\n", nearfname);
      j=myopen(nearfname, O_RDWR);
      if (j!=-1)
      { chsize(j, 0);
        close(j);
      }
      else
      { printf("Can't truncate file!\n");
        logwrite('!', "Can't truncate file!\n");
      }
    }
    delsem();
  }
  nsend=0;
  debug(5, "FlushSend: done");
}

void sendack(char *addr, char *msgid, acktype result, char *reason)
{ FILE *f;
  int  r;

#ifdef __MSDOS__
  static char ackname[80];

  mktempname("temp????.ack", ackname);
  f=fopen(ackname, "w");
  strcpy(addrlist, addr);
#else
  f=exec_rmail(addr);
#endif
  if (f==NULL)
  { logwrite('!', "Can't send %sACK to %s!\n", (result==ACK_OK) ? "" : "N", addr);
    return;
  }
#ifdef __MSDOS__
  if (uupcver!=KENDRA && uupcver!=SENDMAIL)
  { fprintf(f, "rmail\n--\n%s\n<<NULL>>\n", addr);
  }
#endif
  curtime=time(NULL);
  curtm=localtime(&curtime);
  if (uupcver != SENDMAIL)
    fprintf(f, "From %s %s %s %02u %02u:%02u:%02u %u\n",
            user, weekday[curtm->tm_wday],
            montable[curtm->tm_mon], curtm->tm_mday,
            curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
            curtm->tm_year+1900);
  fprintf(f, "From: %s@%s\n", user, local);
  fprintf(f, "To: %s\n", addr);
  fprintf(f, "Date: %s, %2u %s %u  %02u:%02u:%02u %c%02u00\n",
          weekday[curtm->tm_wday], curtm->tm_mday,
          montable[curtm->tm_mon], curtm->tm_year+1900,
          curtm->tm_hour, curtm->tm_min, curtm->tm_sec,
          (tz<=0) ? '+' : '-', (tz<0) ? -tz : tz);
  fprintf(f, "Message-Id: <%08lx-%04x-%04x@%s>\n",
          time(NULL), (unsigned)getpid(), seqf++, local);
  fprintf(f, "References: %s\n", msgid);
  fprintf(f, "Subject: Confirmation %sACK %s: %s\n",
          (result==ACK_OK) ? "" : "N", msgid, reason);
  fprintf(f, "X-Confirm-Status: %s %s (%s)\n",
          (result==ACK_OK) ? "OK" : "FAIL", msgid, reason);
  fprintf(f, "Mime-Version: 1.0\n");
  fprintf(f, "Content-Type: text/plain; charset=us-ascii\n");
  fprintf(f, "Content-Transfer-Encoding: 7bit\n");
  fprintf(f, "Content-Length: 0\n");
  fprintf(f, "Lines: 0\n");
  fprintf(f, "\n");
#ifdef __MSDOS__  
  { int h;
    fflush(f);
    h=dup(fileno(f));
    fclose(f);
    r=exec_rmail(h);
    close(h);
    unlink(ackname);
  }
#else
  fclose(f);
  r=wait_rmail();
#endif
  if (r)
    logwrite('!', "Can't send %sACK to %s: sendmail retcode %d!\n",
             (result==ACK_OK) ? "" : "N", addr, r);
  else
    debug(1, "%sACK sent to %s", (result==ACK_OK) ? "" : "n", addr);
}
