/*
 * $Id$
 *
 * $Log$
 * Revision 2.7  2004/07/20 18:29:26  gul
 * \r\n -> \n
 *
 * Revision 2.6  2004/05/28 13:25:28  gul
 * Accept confirmations without reason
 *
 * Revision 2.5  2001/07/26 12:48:55  gul
 * 7bit- and 8bit-encoded attaches bugfix
 *
 * Revision 2.4  2001/07/20 21:43:26  gul
 * Decode attaches with 8bit encoding
 *
 * Revision 2.3  2001/07/20 21:22:52  gul
 * multipart/mixed decode cleanup
 *
 * Revision 2.2  2001/07/20 16:35:35  gul
 * folded Content-Disposition header held
 *
 * Revision 2.1  2001/07/20 14:55:22  gul
 * Decode quoted-printable attaches
 *
 * Revision 2.0  2001/01/10 20:42:16  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#ifdef HAVE_PROCESS_H
#include <process.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#include <fidolib.h>
#include "exec.h"
#include "gate.h"

static FILE *fin, *fout;
static char s[80], nstr[80];
static char cmdline[1024];
static int  n;
static char *p;
static enctype enc;

char *dayext[]={"SU", "MO", "TU", "WE", "TH", "FR", "SA"};

int isbeg(char *str);
static void onelet(pwdtype passwd, int nhost, int decodepart);
static char tmp_uue[FNAME_MAX], tmp_arc[FNAME_MAX];
static char arcname[FNAME_MAX], execparam[1024];
static time_t ftime;
static int splited;
char *pgpsig;
char confirm[80], msgid[256], unsec_reason[128];
char boundary[1024];
static char confirmstatus[256];
unsigned long fcrc32;

void mkarcname(char *src, char *arcname, pwdtype passwd)
{
  makename(src, arcname, (passwd==SECURE ? pktout : unsecure));
}

void makename(char *src, char *arcname, char *destdir)
{
  strcpy(arcname, destdir);
  addslash(arcname);
  strcat(arcname, basename(src));
}

void uudecode(char *filebox)
{ int  inhdr, inparthdr, emptyline, nhost, npart, decodepart;
  pwdtype passwd;
  char password[MAXPASSWD];
  char sstr[1024], s2[64];

  arcname[0]=0;
  if (bypipe)
    fin=stdin;
  else
  { fin=myfopen(filebox, "r+");
    if (fin==NULL)
      return;
    if (flock(fileno(fin), LOCK_EX|LOCK_NB))
    { fclose(fin);
      return;
    }
  }
  if (!bypipe)
  { long l=ftell(fin);
    fseek(fin, 0, SEEK_END);
    if (ftell(fin)==0)
    { flock(fileno(fin), LOCK_UN);
      fclose(fin);
#if 0
      unlink(filebox);
#endif
      return;
    }
    fseek(fin, l, SEEK_SET);
  }
  fout=NULL;
  inhdr=inparthdr=0;
  emptyline=1;
  splited=0;
  passwd=RESEND;
  password[0]='\0';
  boundary[0]='\0';
  ftime=0;
  nhost=nhosts;
  npart=decodepart=0;
  nstr[0]=from[0]='\0';
  while (fgets(sstr, sizeof(sstr), fin))
  {
nextline:
    if (strcmp(sstr, "\x1A\n")==0) continue;
    if (sstr[0]=='\n')
    {
      if (fout && (fout!=stdin))
        fputs(sstr, fout);
      if (inhdr)
      { unsec_reason[0]=0;
        if (passwd==SECURE && confirmstatus[0]=='\0')
        { if (hosts[nhost].passwd[0] && strcmp(hosts[nhost].passwd, password))
            sprintf(unsec_reason, "%s password",
                    password[0] ? "Incorrect" : "Missing");
          else if (hosts[nhost].passwd[0]=='\0' && password[0])
            debug(2, "Ignoring password from %s", hosts[nhost].host);
#if 0 /* MB signature inside the file */
          if (hosts[nhost].pgpsig && pgpsig==NULL && !splited)
            sprintf(unsec_reason, "Message without PGP-signature");
          else
#endif
          if (pgpsig && !hosts[nhost].pgpsig)
          { debug(2, "Ignoring PGP-signature from %s", hosts[nhost].host);
            free(pgpsig);
            pgpsig=NULL;
          }
          if (unsec_reason[0])
          { logwrite('!', "%s from %s\n", unsec_reason, hosts[nhost].host);
            passwd=unsecure[0] ? UNSECURE : RESEND;
          }
        }
        else if (pgpsig)
        { debug(2, "Ignoring PGP-signature from unknown %s", from);
          free(pgpsig);
          pgpsig=NULL;
        }
        if (enc!=ENC_UUE && tmp_arc[0] && confirmstatus[0]=='\0')
          mkarcname(tmp_arc, arcname, passwd);
        inhdr=0;
      }
      else
      { if (inparthdr && enc!=ENC_UUE && tmp_arc[0])
          mkarcname(tmp_arc, arcname, passwd);
        inparthdr=0;
        emptyline=1;
      }
      continue;
    }
    if (bypipe && !fout)
      goto newmess;
    if (uupcver==KENDRA)
    { if ((!bypipe) && (strcmp(sstr, "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\n")==0))
      { if (!fgets(sstr, sizeof(sstr), fin))
          break;
        goto newmess;
      }
    }
    else if ((isbeg(sstr)==0) && emptyline && ((!bypipe) || (!fout)))
    { /* new message */
newmess:
      debug(3, "uudecode: found new message in mailbox");
      if (fout)
      { if (tmp_uue[0])
        { fclose(fout);
          fout = NULL;
        }
        if (enc==ENC_UUCP)
        { enc=ENC_UUE;
          if (passwd==UNSECURE) passwd=RESEND;
        }
        onelet(passwd, nhost, decodepart);
      }
      passwd = unsecure[0] ? UNSECURE : RESEND;
      password[0]=boundary[0]=from[0]='\0';
      inhdr=1;
      emptyline=0;
      splited=0;
      pgpsig=NULL;
      unsec_reason[0]='\0';
      confirm[0]=msgid[0]=confirmstatus[0]='\0';
      fcrc32=(unsigned long)-1;
      if (bypipe && isfile(fileno(stdin)) && (uudecode_fmt[0]=='\0') &&
          (uupcver!=SENDMAIL || !isbeg(sstr)))
      { fout=stdin;
        tmp_uue[0]='\0';
      }
      else
      { mktempname(TMPUUE, tmp_uue);
        fout=myfopen(tmp_uue, "w");
        if (fout==NULL) break;
        if (isbeg(sstr)) /* skip "From_" line for clean resend */
          fputs(sstr,fout);
      }
      arcname[0]=tmp_arc[0]=0;
      enc=ENC_UUCP;
      npart=decodepart=0;
      continue;
    }
    if (!fout)
    { logwrite('?', "Incorrect mailbox start!\n");
      retcode |= RET_ERR;
      flock(fileno(fin), LOCK_UN);
      fclose(fin);
      return;
    }
    if (fout!=stdin)
      fputs(sstr, fout);
    emptyline=0;
    if (inhdr && (strnicmp(sstr, "Subject:", 8)==0))
    {
      p=strchr(sstr, ',');
      if (p)
      { for (p++; (*p==' ') || (*p=='\t'); p++);
        if ((*p>='0') && (*p<='9'))
        { for (p++; (*p>='0') && (*p<='9'); p++);
          if ((*p=='/') && (p[1]>='0') && (p[1]<='9') && (atoi(p+1)>1))
            splited=1;
        }
      }
      p=strchr(sstr, ';');
      if (p)
      { int i, fday, fmon, fyear, fhour, fmin, fsec;

        for (p++; (*p==' ') || (*p=='\t'); p++);
        i=sscanf(p, "%u.%u.%u %u:%u:%u", &fday, &fmon, &fyear, &fhour, &fmin, &fsec);
        if (i==6)
        { struct tm ftm;
          ftm.tm_mday=fday;
          ftm.tm_mon=fmon-1;
          ftm.tm_year=fyear;
          if (ftm.tm_year>=1900) ftm.tm_year-=1900;
          if (ftm.tm_year<70) ftm.tm_year+=100;
          ftm.tm_hour=fhour;
          ftm.tm_min=fmin;
          ftm.tm_sec=fsec;
          ftm.tm_isdst=0;
          ftime=mktime(&ftm);
        }
      }
    }
    if ((inhdr || inparthdr) && (strnicmp(sstr, "Content-", 8)==0))
    { if (strnicmp(sstr, "Content-Transfer-Encoding:", 26)==0)
      { if (decodepart==0 || decodepart==npart)
        { for (p=sstr+26; (*p==' ') || (*p=='\n'); p++);
          if (strnicmp(p, "base64", 6)==0)
            enc=ENC_BASE64;
          if (strnicmp(p, "quoted-printable", 16)==0)
            enc=ENC_QP;
          if (strnicmp(p, "8bit", 16)==0)
            enc=ENC_8BIT;
          if (strnicmp(p, "7bit", 16)==0)
            enc=ENC_7BIT;
          else if (strnicmp(p, "x-pgp", 5)==0)
            enc=ENC_PGP;
          else if ((strnicmp(p, "x-uue", 5)==0) ||
                   (strnicmp(p, "x-uucode", 8)==0) ||
                   (strnicmp(p, "x-uuencode", 10)==0))
            enc=ENC_UUE;
        }
      }
      else if (strnicmp(sstr, "Content-Type:", 13)==0)
      { char scrc32[32];
        int  gotnextline=0;
        p=sstr+strlen(sstr);
        while (p-sstr<sizeof(sstr)-1)
        { if (!fgets(p, sizeof(sstr)-(int)(p-sstr), fin))
            break;
          if (!isspace(*p) || *p=='\n')
          { gotnextline=1;
            *--p='\0';
            break;
          }
          if (fout!=stdin)
            fputs(p, fout);
          p+=strlen(p);
        }
        for (p=sstr+13; (*p==' ') || (*p=='\n'); p++);
        if (inhdr && strnicmp(p, "message/partial", 15)==0)
          splited=1;
        else if (inhdr && strnicmp(p, "multipart/mixed", 15)==0)
          getparam(sstr, "boundary", boundary, sizeof(boundary));
#if 1
        else if (strnicmp(p, "message/", 8) &&
                 strnicmp(p, "multipart/", 10) &&
                 strnicmp(p, "text", 4))
        { if (decodepart == 0)
            decodepart = npart;
          if (enc == ENC_UUCP) enc = ENC_7BIT;
        }
#endif
        if (tmp_arc[0]=='\0')
        { getparam(sstr, "name", tmp_arc, sizeof(tmp_arc));
          if (tmp_arc[0])
          { decodepart=npart;
            if (enc == ENC_UUCP) enc = ENC_7BIT;
          }
        }
        if (decodepart==npart || decodepart==0)
        { getparam(sstr, "crc32", scrc32, sizeof(scrc32));
          if (scrc32[0])
            sscanf(scrc32, "%lX", &fcrc32);
          if (gotnextline)
          { strcpy(sstr, sstr+strlen(sstr)+1);
            goto nextline;
          }
        }
      }
      else if (strnicmp(sstr, "Content-Disposition:", 20)==0)
      { int  gotnextline=0;
        p=sstr+strlen(sstr);
        while (p-sstr<sizeof(sstr)-1)
        { if (!fgets(p, sizeof(sstr)-(int)(p-sstr), fin))
            break;
          if (!isspace(*p) || *p=='\n')
          { gotnextline=1;
            *--p='\0';
            break;
          }
          if (fout!=stdin)
            fputs(p, fout);
          p+=strlen(p);
        }
        getvalue(sstr, s2, sizeof(s2));
        if (decodepart==0 && stricmp(s2, "attachment")==0)
        { decodepart=npart;
          if (enc == ENC_UUCP) enc = ENC_7BIT;
        }
        if (decodepart==npart || decodepart==0)
        { if (tmp_arc[0]=='\0')
            getparam(sstr, "filename", tmp_arc, sizeof(tmp_arc));
          if (tmp_arc)
          { decodepart=npart;
            if (enc == ENC_UUCP) enc = ENC_7BIT;
          }
        }
        if (gotnextline)
        { strcpy(sstr, sstr+strlen(sstr)+1);
          goto nextline;
        }
      }
    }
    else if (((passwd==RESEND) || (passwd==UNSECURE)) && inhdr)
    { if (strnicmp(sstr, "From:", 5)==0)
      {
        p=strchr(sstr, '\n');
        if (p) *p=0;
        for (p=sstr+5; *p && isspace(*p); p++);
        strncpy(from, p, sizeof(from));
        strncpy(nstr, p, sizeof(nstr));
        strupr(p);
        for (nhost=0; nhost<nhosts; nhost++)
        { if (hosts[nhost].enc==ENC_UUCP) continue;
          strcpy(s, hosts[nhost].host);
          strupr(s);
          if (strstr(p, s))
          { strcpy(from, hosts[nhost].host);
            debug(5, "uudecode: message from known host %s", from);
            break;
          }
        }
        if (nhost!=nhosts)
          passwd=SECURE;
        else if (unsecure[0] && (strstr(p, "MAILER-DAEMON")==NULL))
          passwd=UNSECURE;
        else
          passwd=RESEND;
      }
    }
    else if (inhdr && strnicmp(sstr, "X-Password:", 11)==0)
      getvalue(sstr, password, sizeof(password));
    else if (inhdr && strnicmp(sstr, "X-Confirm-To:", 13)==0)
      getvalue(sstr, confirm, sizeof(confirm));
    else if (inhdr && strnicmp(sstr, "Message-Id:", 11)==0)
      getvalue(sstr, msgid, sizeof(msgid));
    else if (inhdr && strnicmp(sstr, "X-Confirm-Status:", 17)==0)
    { char *p;
      for (p=sstr+17; isspace(*p); p++);
      strncpy(confirmstatus, p, sizeof(confirmstatus)-1);
      confirmstatus[sizeof(confirmstatus)-1]='\0';
      if (confirmstatus[0])
        for (p=confirmstatus+strlen(confirmstatus)-1; isspace(*p); *p--='\0');
    }
    else if (inhdr && strnicmp(sstr, "X-PGP-Sig:", 10)==0)
    { char *p, *p1;
      int was_eol;
      was_eol=(strchr(sstr, '\n')!=NULL);
      for (p=sstr+10; isspace(*p); p++);
      if (*p)
        for (p1=p+strlen(p)-1; isspace(*p1); *p1--='\0');
      if (pgpsig) free(pgpsig);
      pgpsig=malloc(strlen(p)+1);
      if (pgpsig==NULL)
      { logwrite('!', "Not enough memory to check PGP-signature!\n");
        continue;
      }
      strcpy(pgpsig, p);
      while (fgets(sstr, sizeof(sstr), fin))
      { if (was_eol && sstr[0]!=' ' && sstr[0]!='\t')
          goto nextline;
        if (fout!=stdin)
          fputs(sstr, fout);
        was_eol=(strchr(sstr, '\n')!=NULL);
        for (p=sstr; isspace(*p); p++);
        if (*p=='\0') continue;
        for (p1=p+strlen(p)-1; isspace(*p1); *p1--='\0');
        pgpsig=realloc(pgpsig, strlen(pgpsig)+strlen(p)+1);
        if (pgpsig==NULL)
        { logwrite('!', "Not enough memory to check PGP-signature!\n");
          break;
        }
        strcat(pgpsig, p);
      }
      if (pgpsig[0]=='\0')
      { free(pgpsig);
        pgpsig=NULL;
      }
    }
    else if ((!inhdr) && (!inparthdr) &&
             (enc==ENC_UUE || enc==ENC_UUCP || enc==ENC_8BIT || enc==ENC_7BIT))
    { if ((strnicmp(sstr, "begin ", 6)==0) && isdigit(sstr[6]))
      { enc=ENC_UUE;
        decodepart=npart;
        if (arcname[0]==0)
        { if (sscanf(sstr+6, "%d %s", &n, tmp_arc)==2)
            mkarcname(tmp_arc, arcname, passwd);
          else
            tmp_arc[0]=0;
        }
      }
    }
    if (!inhdr && !inparthdr && boundary[0])
      if (sstr[0]=='-' && sstr[1]=='-' && 
          strncmp(sstr+2, boundary, strlen(boundary))==0 &&
          sstr[strlen(boundary)+2]=='\n')
      { inparthdr=1;
        npart++;
      }
  }
  if (!bypipe)
  { if (fout)
    { fseek(fin, 0, SEEK_SET);
      chsize(fileno(fin), 0);
    }
    flock(fileno(fin), LOCK_UN);
    fclose(fin);
  }
  if (fout)
  { if (fout!=stdin)
    { fclose(fout);
      fout = NULL;
    }
    if (enc==ENC_UUCP)
    { enc=ENC_UUE;
      if (passwd==UNSECURE) passwd=RESEND;
    }
    onelet(passwd, nhost, decodepart);
#if 0
    if (!bypipe)
      unlink(filebox);
#endif
  }
  return;
}

void topostmast(char *tmp_uue)
{
  int r;

  if (tmp_uue==NULL) tmp_uue="";
  if (tmp_uue[0]=='\0')
    fseek(fout, 0, SEEK_SET);
  if (uupcver==KENDRA)
    sprintf(execparam, "%s %s %s%s",
            rmail, postmaster,
            tmp_uue[0] ? "<" : "", tmp_uue);
  else if (uupcver==SENDMAIL)
    sprintf(execparam, "%s -f %s@%s %s %s%s",
            rmail,user, local, postmaster,
            tmp_uue[0] ? "<" : "", tmp_uue);
  else
    sprintf(execparam, "%s -%c %s %s %s%s",
            rmail, (uupcver==5)?'f':'R', user, postmaster,
            tmp_uue[0] ? "<" : "", tmp_uue);
  
            r=swap_system(execparam);
  if (fout && fout!=stdin)
    fclose(fout);
  fout=NULL;
  if ((r!=0) && (r!=48))
  { if (r==-1)
      logwrite('?', "Can't execute rmail for resend message: %s\n", strerror(errno));
    else
      logwrite('?', "Can't resend message from %s: rmail retcode %u!\n", from, r);
    retcode|=RET_ERR;
  }
  else
  { if (tmp_uue[0])
      unlink(tmp_uue);
    if (!bypipe) retcode|=RET_FWD;
  }
}

static void sendfile(char *fname, char *address)
{
  debug(6, "sendfile %s to %s", fname, address);
  if (uupcver==KENDRA)
    sprintf(cmdline, "%s %s <%s", rmail, address, fname);
  else if (uupcver==SENDMAIL)
    sprintf(cmdline, "%s -f %s@%s %s <%s", rmail, user, local, address, fname);
  else
    sprintf(cmdline, "%s -u -l <%s", rmail, fname); /* address list included */
  if (swap_system(cmdline))
    logwrite('?', "Can't resend file %s!\n", fname);
  else
  { debug(6, "file sent successfully, touch it");
    touch(fname);
    if (debuglevel>=10)
    { struct stat st;
      stat(fname, &st);
      debug(10, "ctime=%lu, mtime=%lu, now=%lu\n",
            st.st_ctime, st.st_mtime, time(NULL));
    }
  }
}

void resendfile(char *fname)
{
  FILE *f;

  debug(4, "resend file %s", fname);
  if (uupcver!=KENDRA && uupcver!=SENDMAIL)
  { /* address inside, rmail -l switch */
    sendfile(fname, NULL);
    return;
  }
#ifdef __OS2__
  { char *p=get_ea(fname, "To");
    if (p)
    { debug(8, "resendfile: got address from ea: %s", p);
      sendfile(fname, p);
      free(p);
      return;
    }
  }
#endif
  /* get address (only one!) */
  addrlist[0]='\0';
  f=fopen(fname, "r");
  while (fgets(str, sizeof(str), f))
  { if (strcmp(str, "\n")==0)
      break;
    if (strnicmp(str, "To:", 3)==0)
    { getvalue(str, addrlist, sizeof(addrlist));
      debug(8, "resendfile: got address from hdr: %s", addrlist);
      break;
    }
  }
  fclose(f);
  if (addrlist[0]=='\0')
  { logwrite('?', "Can't resend file %s: bad header!\n", tmp_uue);
    return;
  }
  sendfile(fname, addrlist);
}

static void processconfirm(char *line)
{
  /* "(OK|FAIL) (<.*>) \(.*\) */
  /* "OK <asdasd@remote.domain> (secure)" */
  /* "FAIL <asdasd@remote.domain> (internal error)" */
  DIR *d;
  struct dirent *df;
  acktype ack;
  char *msgid;
  char *reason;
  char *p;
  int  found;
  FILE *f;

  /* Parse string */
  debug(6, "process confirm: %s", line);
  if (strnicmp(line, "ok ", 3)==0)
    ack=ACK_OK;
  else if (strnicmp(line, "fail ", 5)==0)
    ack=ACK_FAIL;
  else
errconfirm:
  { logwrite('!', "Unknown ack ignored: %s\n", line);
    return;
  }
  for (p=strchr(line, ' '); isspace(*p); p++);
  if (*p!='<') goto errconfirm;
  msgid=p;
  while (*p && !isspace(*p) && *p!='>') p++;
  if (*p!='>' || (p[1] && !isspace(p[1])))
    goto errconfirm;
  p++;
  if (*p) *p++='\0';
  while (*p && isspace(*p)) p++;
  reason="";
  if (*p=='(')
  { reason=p-1;
    p=strchr(p, ')');
    if (p) p[1]='\0';
  }
  debug(12, "processconfirm: ack=%s, msgid=\"%s\", reason=\"%s\"",
        (ack==ACK_OK) ? "ACK_OK" : "ACK_FAIL", msgid, reason);
  /* find messages with this message-id or part_id */
  d=opendir(sentdir);
  if (d==NULL)
  { logwrite('?', "Can't opendir %s: %s!\n", sentdir, strerror(errno));
    return;
  }
  found=0;
  while ((df=readdir(d))!=NULL)
  {
    if (df->d_name[0]=='.') continue;
    if (cmpaddr(df->d_name, TMPSENT))
      if (cmpaddr(df->d_name, SENTBAD))
        continue;
    strcpy(tmp_uue, sentdir);
    addslash(tmp_uue);
    strcat(tmp_uue, df->d_name);
    debug(20, "processconfirm: checking %s", tmp_uue);
#ifdef __OS2__
    p=get_ea(tmp_uue, "Message-Id");
    if (p)
    {
      debug(20, "processconfirm: got msgid from ea: %s", p);
      if (strcmp(p, msgid)==0)
      { found=1;
        debug(4, "processconfirm: found file %s", tmp_uue);
        if (ack==ACK_FAIL)
          resendfile(tmp_uue);
        else
        { unlink(tmp_uue);
          debug(2, "processconfirm: file %s unlinked", tmp_uue);
        }
      }
      free(p);
      continue;
    }
#endif
    if ((f=fopen(tmp_uue, "r"))==NULL)
    { logwrite('!', "Can't open %s: %s!\n", tmp_uue, strerror(errno));
      continue;
    }
    while (fgets(str, sizeof(str), f))
    {
gotresendline:
      if (strnicmp(str, "Message-Id:", 11)==0)
      { getvalue(str, s, sizeof(s));
        debug(20, "processconfirm: got msgid from header: %s", s);
        if (strcmp(s, msgid)==0)
        { found=1;
          fclose(f);
          f=NULL;
          debug(4, "processconfirm: found file %s", tmp_uue);
          if (ack==ACK_FAIL)
            resendfile(tmp_uue);
          else
          { unlink(tmp_uue);
            debug(2, "processconfirm: file %s unlinked", tmp_uue);
          }
          break;
        }
      }
      else if (strnicmp(str, "Content-Type:", 13)==0)
      { char c;

        while (strlen(str)<sizeof(str)-1)
        { p=str+strlen(str);
          if (!fgets(p, sizeof(str)-strlen(str), f))
            break;
          if (*p=='\n' || !isspace(*p))
            break;
        }
        c=*p;
        *p='\0';
        s[0]='<';
        getparam(str, "id", s+1, sizeof(s)-2);
        strcat(s, ">");
        if (s[2])
          debug(20, "processconfirm: got part id from header: %s", s);
        if (strcmp(s, msgid))
        { if (c)
          { *p=c;
            strcpy(str, p);
            goto gotresendline;
          }
          continue;
        }
        found=1;
        fclose(f);
        f=NULL;
        debug(4, "processconfirm: found file %s", tmp_uue);
        if (ack==ACK_FAIL)
          resendfile(tmp_uue);
        else
        { unlink(tmp_uue);
          debug(2, "processconfirm: file %s unlinked", tmp_uue);
        }
        break;
      }
      else if (strcmp(str, "\n")==0)
        break;
    }
    if (f) fclose(f);
  }
  closedir(d);
  if (found)
  { if (ack==ACK_OK)
      logwrite('$', "Received ACK %s%s\n", msgid, reason);
    else
      logwrite('!', "Received NACK %s%s, file(s) resent\n", msgid, reason);
  }
  else
    logwrite('!', "Received %sACK %s%s, corresponding files not found\n",
             (ack==ACK_OK) ? "" : "N",  msgid, reason);
}

static time_t parsedate(char *p)
{ int  i, k;
  struct tm tm;
  char smon[32];

  debug(14, "ParseDate('%s')", p);
  while (*p && (!isdigit(*p))) p++;
  i=sscanf(p, "%u %s %u %u:%u:%u", &tm.tm_mday, smon, &tm.tm_year,
             &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
  if (i<5)
    return 0;
  if (i==5)
    tm.tm_sec=0;
  if (strlen(smon)!=3)
    smon[3]=0;
  if (tm.tm_year>1900) tm.tm_year-=1900;
  else if (tm.tm_year<50) tm.tm_year+=100; /* >1999 */
  /* look for TZ */
  for (k=0; k<12; k++)
    if (stricmp(smon, montable[k])==0)
      break;
  if (k==12) return 0;
  tm.tm_mon=k;
  tm.tm_isdst=0;
  return mktime(&tm);
}

void resend(void)
{
  DIR *d;
  struct dirent *df;
  time_t filedate;
  char *p;
  int  i;
  struct stat st;

  d=opendir(sentdir);
  if (d==NULL)
  { logwrite('?', "Can't opendir %s: %s!\n", sentdir, strerror(errno));
    return;
  }
  while ((df=readdir(d))!=NULL)
  {
    if (df->d_name[0]=='.') continue;
    if (cmpaddr(df->d_name, TMPSENT)) continue;
    strcpy(tmp_uue, sentdir);
    addslash(tmp_uue);
    strcat(tmp_uue, df->d_name);
    debug(20, "resend: checking %s", tmp_uue);
    filedate=0;
    addrlist[0]='\0';
#ifdef __OS2__
    p=get_ea(tmp_uue, "Date");
    if (p)
    { filedate=parsedate(p);
      debug(20, "resend: got date from ea: \"%s\" (unixtime %lu, current %lu)",
                 p, filedate, time(NULL));
      free(p);
    }
    p=get_ea(tmp_uue, "To");
    if (p)
    { strcpy(addrlist, p);
      debug(20, "resend: got address from ea: %s", p);
      free(p);
    }
    if (filedate==0 || addrlist[0]=='\0')
#endif
    { FILE *f;
      if ((f=fopen(tmp_uue, "r"))==NULL)
      { logwrite('!', "Can't open file %s: %s!\n", tmp_uue, strerror(errno));
        continue;
      }
      while (fgets(str, sizeof(str), f))
      { if (strcmp(str, "\n")==0)
          break;
        if (strnicmp(str, "Date:", 5)==0)
        { for (p=str+5; isspace(*p); p++);
          if (filedate==0)
          { filedate=parsedate(p);
            debug(20, "resend: got date from header: \"%s\" (unixtime %lu, current %lu)",
                  p, filedate, time(NULL));
          }
        }
        else if (strnicmp(str, "To:", 3)==0)
        { if (addrlist[0]=='\0')
          { getvalue(str, addrlist, sizeof(addrlist));
            debug(20, "resend: got address from header: %s", addrlist);
          }
        }
      }
      fclose(f);
    }
    if (addrlist[0]=='\0' || filedate==0)
    { logwrite('!', "Can't resend file %s: incorrect header!\n", tmp_uue);
      goto sendbad;
    }
    for (i=0; i<nhosts; i++)
    { if (hosts[i].enc==ENC_UUCP) continue;
      if (stricmp(addrlist, hosts[i].host)==0)
        break;
    }
    if (i==nhosts)
    { logwrite('!', "Can't resend file %s: unknown host %s\n", tmp_uue, addrlist);
      goto sendbad;
    }
    if (!hosts[i].confirm)
    { logwrite('!', "Can't resend file %s: no confirm param for %s!\n",
               tmp_uue, addrlist);
      goto sendbad;
    }
    if (time(NULL)>=filedate+hosts[i].confirm_fail)
    { logwrite('?', "Fail waiting confirm from %s for %s!\n",
               addrlist, tmp_uue);
sendbad:
      strcpy(str, sentdir);
      addslash(str);
      strcat(str, SENTBAD);
      mktempname(str, s);
      move(tmp_uue, s);
      continue;
    }
    stat(tmp_uue, &st);
    if (time(NULL)>=st.st_mtime+hosts[i].confirm)
    { logwrite('!', "No confirm from %s for %s, resend\n", addrlist, tmp_uue);
      debug(20, "resend: mtime(\"%s\")=%lu, curtime=%lu, confirm_interval=%lu",
            tmp_uue, st.st_mtime, time(NULL), hosts[i].confirm);
      sendfile(tmp_uue, addrlist);
    }
  }
  closedir(d);
}

static void onelet(pwdtype passwd, int nhost, int decodepart)
{ struct stat statbuf;
  int r;

  if (confirmstatus[0])
  { if (tmp_uue[0])
      unlink(tmp_uue);
    else if (fout && fout!=stdin)
    { fclose(fout);
      fout=NULL;
    }
    processconfirm(confirmstatus);
    confirmstatus[0]='\0';
    return;
  }
  if (tmp_uue[0]=='\0')
    fseek(fout, 0, SEEK_SET);
  if (passwd==RESEND)
  { /* resend */
    if (pgpsig)
    { free(pgpsig);
      pgpsig=NULL;
    }
    if (unsec_reason[0]=='\0')
    { strcpy(unsec_reason, "unknown address");
      logwrite('!', "Message from unknown address %s, resent to postmaster\n", from);
    }
    if (confirm[0])
      sendack(confirm, msgid, ACK_FAIL, unsec_reason);
    topostmast(tmp_uue);
    return;
  }
  if (splited)
  { if (pgpsig)
    { free(pgpsig);
      pgpsig=NULL;
    }
    strcpy(str, incomplete);
    addslash(str);
    strcat(str, TMPUUE);
    mktempname(str, s);
    if (tmp_uue[0])
    { /* move to incomplete dir */
      if (move(tmp_uue, s))
      { if (copyfile(tmp_uue, s))
          logwrite('!', "Can't move %s to incomplete dir!\n", tmp_uue);
        else
          unlink(tmp_uue);
      }
      return;
    }
    strcpy(tmp_uue, s);
    fout=myfopen(tmp_uue, "w");
    if (fout==NULL)
    { logwrite('?', "Can't create %s: %s!\n", tmp_uue, strerror(errno));
      fout=stdin;
      if (confirm[0])
        sendack(confirm, msgid, ACK_FAIL, "internal error");
      topostmast(tmp_uue);
      return;
    }
    while (fgets(str, sizeof(str), stdin))
      if (fputs(str, fout)==EOF)
      { logwrite('?', "Can't write to %s: %s!\n", tmp_uue, strerror(errno));
        fclose(fout);
        unlink(tmp_uue);
        tmp_uue[0]='\0';
        fout=stdin;
        if (confirm[0])
          sendack(confirm, msgid, ACK_FAIL, "internal error");
        topostmast(tmp_uue);
        return;
      }
    if (fout!=stdin)
    { fclose(fout);
      fout=NULL;
    }
    return;
  }
  if (arcname[0]==0)
  { time_t curtime;
    struct tm *curtm;

    /* look for day of week */
    curtime=time(NULL);
    curtm=localtime(&curtime);
    if (nhost!=nhosts)
      strcpy(nstr, from);
    else if (nstr[0]=='\0')
      strcpy(nstr, "user@domain");
    sprintf(arcname, "%s%08lx.%s0", (passwd==SECURE) ? pktout : unsecure,
            crc32(nstr), dayext[curtm->tm_wday]);
  }
  mktempname(TMPARCNAME, tmp_arc);
  if (uudecode_fmt[0] && enc==ENC_UUE)
  { strcpy(execparam, uudecode_fmt);
#ifndef UNIX
    strlwr(execparam);
#endif
    chsubstr(execparam, "%infile", tmp_uue);
    chsubstr(execparam, "%outfile", tmp_arc);
    if (swap_system(execparam))
baduuderet:
    { if (access(tmp_arc, 0)==0)
        unlink(tmp_arc);
      logwrite('?', "Error while decoding message from %s, resent to postmaster\n", from);
      if (pgpsig) free(pgpsig);
      pgpsig=NULL;
      if (confirm[0])
        sendack(confirm, msgid, ACK_FAIL, "decode error");
      topostmast(tmp_uue);
      return;
    }
  } else if (enc==ENC_PGP)
  { if (pgpdec_fmt[0]==0)
    { logwrite('?', "Can't decode pgp message: pgp-decode not specified!\n");
      if (pgpsig) free(pgpsig);
      pgpsig=NULL;
      if (confirm[0])
        sendack(confirm, msgid, ACK_FAIL, "internal error (can't decode pgp)");
      topostmast(tmp_uue);
      return;
    }
    sprintf(execparam, "%s <%s >%s", pgpdec_fmt, tmp_uue, tmp_arc);
    r = swap_system(execparam);
    if (!quiet) fputs("\n", stderr);
    if (r!=0 && r!=1) /* 1 - alternate success, no signature found */
      goto baduuderet;
    if (r==0 && pgpsig==NULL && nhost!=nhosts && hosts[nhost].pgpsig)
    { debug(1, "PGP signature inside the encoded file");
      pgpsig=strdup(""); /* signature OK (only in batchmode!) */
    }
  } else if (enc == ENC_BASE64)
  { if (do_unbase64(tmp_uue, tmp_arc, decodepart))
      goto baduuderet;
  } else if (enc == ENC_QP)
  { if (do_unqp(tmp_uue, tmp_arc, decodepart))
      goto baduuderet;
  } else if (enc == ENC_8BIT)
  { if (do_un8bit(tmp_uue, tmp_arc, decodepart))
      goto baduuderet;
  } else if (enc == ENC_7BIT)
  { if (do_un7bit(tmp_uue, tmp_arc, decodepart))
      goto baduuderet;
  } else
  { if (do_uudecode(tmp_uue, tmp_arc))
      goto baduuderet;
  }
  if (access(tmp_arc, 0))
  { logwrite('?', "Error while decoding message from %s, resent to postmaster\n", from);
    if (pgpsig) free(pgpsig);
    pgpsig=NULL;
    if (confirm[0])
      sendack(confirm, msgid, ACK_FAIL, "decode error");
    topostmast(tmp_uue);
    return;
  }
  if (fcrc32!=(unsigned long)-1)
  { unsigned long calccrc32;
    calccrc32=filecrc32(tmp_arc);
    if (calccrc32!=(unsigned long)-1)
    { if (calccrc32!=fcrc32)
      { logwrite(nocrc ? '!' : '?', "CRC error (%08lX!=%08lX) in file %s from %s!\n",
                 calccrc32, fcrc32, basename(arcname), from);
        if (!nocrc)
        { if (pgpsig) free(pgpsig);
          pgpsig=NULL;
          unlink(tmp_arc);
          if (confirm[0])
            sendack(confirm, msgid, ACK_FAIL, "crc error");
          topostmast(tmp_uue);
          return;
        }
      }
      else
        debug(2, "file %s crc32 ok (%08lX)", basename(arcname), crc32);
    }
  }
  if (pgpsig)
  { if (pgpsig[0] && checkpgpsig(tmp_arc, pgpsig, hosts[nhost].host))
    { free(pgpsig);
      pgpsig=NULL;
      logwrite('!', "Bad pgp signature from %s!\n", from);
nopgp:
      if (passwd==SECURE)
      {
        if (unsecure[0]=='\0')
        { unlink(tmp_arc);
          passwd=RESEND;
          if (confirm[0])
            sendack(confirm, msgid, ACK_FAIL, "bad pgp signature");
          topostmast(tmp_uue);
          return;
        }
        else
        { /* move arcname to unsecure dir */
          passwd=UNSECURE;
          makename(arcname, execparam, unsecure);
          strcpy(arcname, execparam);
        }
      }
    }
    else
      debug(2, "Good pgp signature from %s", from);
    if (pgpsig) free(pgpsig);
    pgpsig=NULL;
  }
  else if (nhost!=nhosts && hosts[nhost].pgpsig)
  { logwrite('!', "No pgp signature from %s!\n", from);
    goto nopgp;
  }
  strcpy(execparam, arcname);
  if (rmove(tmp_arc, arcname))
  { logwrite('!', "Can't move %s to %s!\n", tmp_arc, arcname);
    unlink(tmp_arc);
    passwd=RESEND;
    if (confirm[0])
      sendack(confirm, msgid, ACK_FAIL, "internal error");
    topostmast(tmp_uue);
    return;
  }
  debug(1, "Saving %s as %s", basename(execparam), arcname);
  if (tmp_uue[0])
    unlink(tmp_uue);
  if (ftime)
  { struct utimbuf utb;
    utb.actime = utb.modtime = ftime;
    utime(arcname, &utb);
  }
  stat(arcname, &statbuf);
  logwrite('$', "File %s from %s size %lu bytes successfully decoded\n",
           basename(arcname), from, statbuf.st_size);
  if (confirm[0])
    sendack(confirm, msgid, ACK_OK, (passwd==SECURE) ? "secure" : "unsecure");
  if (!bypipe) retcode|=RET_RCV;
  newecho=1;
  fout=NULL;
}

int uucp(char *filename, char *host)
{
  int r;

#ifndef UNIX
  strcpy(s, uupcdir);
  strcat(s, "uucp" EXEEXT);
  if (access(s, 0))
  { logwrite('?', "Can't find %s!\n", s);
    retcode|=RET_ERR;
    return 4;
  }
  sprintf(cmdline, "%s -C -r %s %s >nul >&nul", s, filename, host);
#else
  sprintf(cmdline, "uucp -C -r %s %s >/dev/null 2>&1", filename, host);
#endif
  r=swap_system(cmdline);
  if (r)
  { logwrite('?', "Can't send %s to %s - uucp retcode %u!\n",
             filename, host, r);
    retcode|=RET_ERR;
    return 5;
  }
  return 0;
}

void getvalue(char *field, char *value, unsigned valsize)
{ char *p;

  if (valsize==0) return;
  value[0]='\0';
  for (p=field; *p && !isspace(*p); p++);
  if (*p=='\0') return;
  for (p++; isspace(*p); p++);
  if (*p!='"')
  { for (;*p && (!isspace(*p)) && (*p!=';'); *value++=*p++)
      if (valsize--==1) break;
  }
  else
    for (p++; *p && (*p!='"') && (*p!='\n') && (*p!='\r'); *value++=*p++)
      if (valsize--==1) break;
  *value='\0';
}

void getparam(char *field, char *argname, char *value, unsigned valsize)
{
  char *p;

  if (valsize==0) return;
  value[0]='\0';
  for (p=field; *p && !isspace(*p); p++);
  if (*p=='\0') return;
  for (;;)
  {
    for (; *p && (*p!=';') && (*p!='"'); p++);
    if (*p=='"')
    { for(p++; *p && (*p!='"'); p++);
      if (*p!='"') return;
      p++;
      continue;
    }
    if (*p!=';') return;
    for (p++; isspace(*p); p++);
    if (*p=='\0') return;
    if (strnicmp(p, argname, strlen(argname)))
      continue;
    p+=strlen(argname);
    if (*p++!='=') continue;
    /* found */
    if (*p!='"')
    { for (; *p && !isspace(*p); *value++=*p++)
        if (valsize--==1) break;
    }
    else
      for (p++; *p && (*p!='"') && (*p!='\n') && (*p!='\r'); *value++=*p++)
        if (valsize--==1) break;
    *value='\0';
  }
}
