/*
 * $Id$
 *
 * $Log$
 * Revision 2.5  2001/07/20 21:43:26  gul
 * Decode attaches with 8bit encoding
 *
 * Revision 2.4  2001/07/20 21:22:52  gul
 * multipart/mixed decode cleanup
 *
 * Revision 2.3  2001/07/20 16:35:35  gul
 * folded Content-Disposition header held
 *
 * Revision 2.2  2001/07/20 14:55:22  gul
 * Decode quoted-printable attaches
 *
 * Revision 2.1  2001/01/26 14:29:14  gul
 * Added libgen.h for basename()
 *
 * Revision 2.0  2001/01/10 20:42:15  gul
 * We are under CVS for now
 *
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#include <fcntl.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_ALLOC_H
#include <alloc.h>
#endif
#include <stdlib.h>
#ifdef HAVE_DOS_H
#include <dos.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#include "gate.h"

#ifdef __MSDOS__
#define NAMELEN 13
#else
#define NAMELEN 128
#endif

static struct listtype
       { char uuename[NAMELEN];
         char arcname[NAMELEN];
         time_t ftime;
         int  parts, curpart;
         int  host;
         pwdtype passwd;
         enctype enc;
         char part_id[80];
         char *boundary;
         struct listtype *next;
       } *flist, *cur, *last;
static DIR *d;
static struct dirent *df;
static char tmpname[FNAME_MAX], inname[FNAME_MAX], tmp_arc[FNAME_MAX];
static char subj[128];
char from[128];
static FILE *fin, *fout;
static char cont_type[1024], password[MAXPASSWD];
static int  partial;
static char part_id[80];
static enctype enc;

static void alltopostmast(struct listtype *last)
{ int curpart;

  debug(4, "Resend all parts to postmaster");
  for (curpart=1; curpart<=last->parts; curpart++)
  {
    for (cur=flist; cur!=NULL; cur=cur->next)
    { if (cur->curpart!=curpart)
        continue;
      if (last->part_id[0] && (strcmp(last->part_id, cur->part_id)==0))
        break;
      if (stricmp(last->arcname, cur->arcname))
        continue;
      if (memcmp(&(cur->ftime), &(last->ftime), sizeof(cur->ftime)))
        continue;
      if (last->parts!=cur->parts)
        continue;
      break;
    }
    strcpy(str, incomplete);
    addslash(str);
    strcat(str, cur->uuename);
    debug(7, "Calling topostmast(%s)", str);
    topostmast(str);
    debug(12, "topostmast() returns");
  }
}

void checktmp(void)
{ int r;
  int curpart, parts, inparthdr, npart=0, decodepart=0;
  int day, mon, year, hour, min, sec;
  char *p, *p1;
  struct stat statbuf;

  /* 1. Build list */

  flist=NULL;
  d=opendir(incomplete);
  if (d==NULL)
  { logwrite('!', "Can't opendir %s: %s!\n", incomplete, strerror(errno));
    return;
  }
  while ((df=readdir(d))!=NULL)
  { if (strlen(df->d_name)!=12) continue;
    if (strnicmp(df->d_name, "temp", 4)) continue;
    if (stricmp(df->d_name+8, ".uue")) continue;
    strcpy(tmpname, incomplete);
    addslash(tmpname);
    strcat(tmpname, df->d_name);
    debug(5, "CheckTmp: found %s", tmpname);
    fin=myfopen(tmpname, "r");
    if (fin==NULL)
    { logwrite('?', "Can't open %s: %s!\n", tmpname, strerror(errno));
      if (!bypipe) retcode|=RET_ERR;
      continue;
    }
    /* read header */
    subj[0]=from[0]=0;
    partial=0;
    enc=ENC_UUE;
    cont_type[0]='\0';
    part_id[0]='\0';
    inname[0]='\0';
    password[0]='\0';
    boundary[0]='\0';
    curpart=parts=npart=decodepart=0;
    while (fgets(str, sizeof(str), fin))
    {
gotline:
      if (str[0]=='\n')
      { if (partial && (curpart==1))
        { partial=0;
          continue; /* continue of the header */
        }
        break;
      }
      if (strnicmp(str, "Subject:", 8)==0)
        strncpy(subj, str+8, sizeof(subj)-1);
      if (strnicmp(str, "From:", 5)==0)
        strncpy(from, str+5, sizeof(from)-1);
      if (strnicmp(str, "X-Password:", 11)==0)
        getvalue(str, password, sizeof(password));
      if (strnicmp(str, "Content-Transfer-Encoding:", 26)==0)
      { for (p=str+26; (*p==' ') || (*p=='\t'); p++);
        debug(8, "CheckTmp: content-transfer-encoding is %s", p);
        if (decodepart==0 || decodepart==npart)
        {
          if (strnicmp(p, "base64", 6)==0)
            enc=ENC_BASE64;
          else if (strnicmp(p, "quoted-printable", 16)==0)
            enc=ENC_QP;
          else if (strnicmp(p, "8bit", 16)==0)
            enc=ENC_8BIT;
          else if (strnicmp(p, "x-pgp", 5)==0)
            enc=ENC_PGP;
        }
      }
      if (strnicmp(str, "Content-Type:", 13)==0)
      { strcpy(cont_type, str);
        while (fgets(str, sizeof(str), fin))
        { if ((str[0]==' ') || (str[0]=='\t'))
            strncat(cont_type, str, sizeof(cont_type));
          else
          { getvalue(cont_type, sstr, sizeof(sstr));
            debug(8, "CheckTmp: content-type is %s", cont_type);
            if (stricmp(sstr, "message/partial")==0)
            { partial=1;
              getparam(cont_type, "number", sstr, sizeof(sstr));
              curpart=atoi(sstr);
              getparam(cont_type, "total", sstr, sizeof(sstr));
              parts=atoi(sstr);
              getparam(cont_type, "id", part_id, sizeof(part_id));
              debug(8, "CheckTmp: partial, number=%d, total=%d, id=%s",
                    curpart, parts, part_id);
            }
            else
            { if (stricmp(sstr, "multipart/mixed")==0)
                getparam(cont_type, "boundary", boundary, sizeof(boundary));
              else if (inname[0]=='\0')
                getparam(cont_type, "name", inname, sizeof(inname));
              partial=0; /* for case of incorrect header with two content-type */
            }
            goto gotline;
          }
        }
        break;
      }
      if (strnicmp(str, "Content-Disposition:", 20)==0)
      { strcpy(sstr, str);
        while (fgets(str, sizeof(str), fin))
        { if ((str[0]==' ') || (str[0]=='\t'))
            strncat(sstr, str, sizeof(sstr));
          else
          { getparam(sstr, "filename", inname, sizeof(inname));
            if (inname[0]=='\0')
              getvalue(sstr, inname, sizeof(inname));
            goto gotline;
          }
        }
        break;
      }
    }
    fclose(fin);
    if (subj[0]==0)
    { if ((part_id[0]=='\0') || (curpart==0))
        continue;
      if ((inname[0]=='\0') && (curpart==1))
        continue;
    }
    for (p=subj; (*p==' ') || (*p=='\t'); p++);
    if (inname[0]=='\0')
    { p1=strpbrk(subj, ",;");
      if (p1==NULL)
      { strcpy(inname, p);
        p1=strpbrk(inname, " \t\n");
        if (p1) *p1='\0';
      }
      else
      { r=*p1;
        *p1='\0';
        strcpy(inname, p);
        *p1=r;
      }
    }
    if ((inname[0]=='\0') && (part_id[0]=='\0')) continue;
    if (curpart==0)
    { p=strchr(subj, ',');
      if (p==NULL) continue;
      r=sscanf(p+1, "%u/%u", &curpart, &parts);
      if (r!=2) continue;
    }
    if (curpart==0) continue;
    if ((parts==0) && (part_id[0]=='\0'))
      continue;
    p=strchr(subj, ';');
    if (p)
    { r=sscanf(p+1, "%u.%u.%u %u:%u:%u", &day, &mon, &year, &hour, &min, &sec);
      if (r!=6)
        day=mon=year=min=sec=0;
      else
      { if (year>=1900) year-=1900;
        if (year<70) year+=100;
      }
    }
    if ((part_id[0]=='\0') && (mon==0))
      continue;
    if (last==NULL)
    { last=malloc(sizeof(*flist));
      if (last==NULL)
      { logwrite('?', "Non enough memory\n");
        if (!bypipe) retcode|=RET_ERR;
        continue;
      }
      flist=last;
    }
    else
    { last->next=malloc(sizeof(*flist));
      if (last->next==NULL)
      { logwrite('?', "Non enough memory\n");
        if (!bypipe) retcode|=RET_ERR;
        continue;
      }
      last=last->next;
    }
    strncpy(last->arcname, inname, sizeof(last->arcname));
    debug(3, "CheckTmp: arcname=%s, part=%d", inname, curpart);
    last->arcname[sizeof(last->arcname)-1]='\0';
    strcpy(last->uuename, df->d_name);
    strcpy(last->part_id, part_id);
    last->enc=enc;
    { struct tm t;
      t.tm_year=year;
      t.tm_mon=mon-1;
      t.tm_mday=day;
      t.tm_hour=hour;
      t.tm_min=min;
      t.tm_sec=sec;
      t.tm_isdst=-1;
      last->ftime=mktime(&t);
    }
    last->parts=parts;
    last->curpart=curpart;
    last->next=NULL;
    for (r=0; r<nhosts; r++)
    { strcpy(subj, hosts[r].host);
      strupr(subj);
      strupr(from);
      if (strstr(from, subj))
        break;
    }
    last->host=r;
    last->passwd=RESEND;
    if ((r==nhosts) && unsecure[0])
      last->passwd=UNSECURE;
    else if (r<nhosts)
    { last->passwd=SECURE;
      if (hosts[r].passwd[0])
        if (strcmp(hosts[r].passwd, password))
          last->passwd=unsecure[0] ? UNSECURE : RESEND;
    }
    if (last->passwd==RESEND)
    { /* resend this part to postmaster */
      strlwr(from);
      logwrite('!', "Unsecure delayed message from %s, resent to postmaster\n",
               from);
      topostmast(tmpname);
      /* remove from queue */
      if (last==flist)
      { free(last);
        last=flist=NULL;
      }
      else
      { for (cur=flist; cur->next!=last; cur=cur->next);
        free(last);
        last=cur;
        last->next=NULL;
      }
    }
    str[0]=0;
    if (boundary[0])
      last->boundary=strdup(boundary);
    else
      last->boundary=NULL;
  }
  closedir(d);

  debug(4, "CheckTmp: Search for complete files");
  /* 2. Search for messages with all parts received */
  for (last=flist; last!=NULL; last=last->next)
  {
    if (last->curpart!=1)
      continue;
    if (last->parts==0)
    { for (cur=flist; cur!=NULL; cur=cur->next)
      { if (strcmp(last->part_id, cur->part_id)==0)
          if (cur->parts)
          { last->parts=cur->parts;
            break;
          }
      }
    }
    if (last->parts==0)
      continue;
    for (curpart=2; curpart<=last->parts; curpart++)
    {
      for (cur=flist; cur!=NULL; cur=cur->next)
      { if (cur->curpart!=curpart)
          continue;
        if (last->part_id[0] && (strcmp(last->part_id, cur->part_id)==0))
          break;
        if (stricmp(last->arcname, cur->arcname))
          continue;
        if (cur->ftime!=last->ftime)
          continue;
        if (last->parts!=cur->parts)
          continue;
        if (last->host!=cur->host)
          continue;
        break;
      }
      if (cur==NULL) break;
    }
    if (curpart<=last->parts)
      continue;

    /* All parts exists, decode with single (first) header */

    debug(3, "CheckTmp: found all %d parts for %s", last->parts, last->arcname);
    mktempname(TMPUUE, tmpname);
    fout=myfopen(tmpname, "w");
    if (fout==NULL)
    { logwrite('?', "Can't create %s: %s!\n",tmpname,strerror(errno));
      if (!bypipe) retcode|=RET_ERR;
      continue;
    }
    if (pgpsig) free(pgpsig);
    pgpsig=NULL;
    confirm[0]=msgid[0]=boundary[0]=0;
    fcrc32=(unsigned long)-1;
    for (curpart=1; curpart<=last->parts; curpart++)
    {
      for (cur=flist; cur; cur=cur->next)
      { if (cur->curpart!=curpart)
          continue;
        if (last->part_id[0] && (strcmp(last->part_id, cur->part_id)==0))
          break;
        if (stricmp(last->arcname, cur->arcname))
          continue;
        if (cur->ftime!=last->ftime)
          continue;
        if (last->parts!=cur->parts)
          continue;
        break;
      }
      if (curpart==1 && cur->boundary)
        strcpy(boundary, cur->boundary);
      if (curpart==1 && cur->arcname[0] && last->arcname[0]=='\0')
        strcpy(last->arcname, cur->arcname);
      strcpy(inname, incomplete);
      addslash(inname);
      strcat(inname, cur->uuename);
      fin=myfopen(inname, "r");
      if (fin==NULL)
      { logwrite('?', "Can't open %s: %s!\n", inname, strerror(errno));
        if (!bypipe) retcode|=RET_ERR;
        fclose(fout);
        unlink(tmpname);
        fout=NULL;
        break;
      }
      debug(5, "CheckTmp: add %s (part %d) to %s", inname, curpart, tmpname);
      /* look for from */
      partial=0;
      while (fgets(str, sizeof(str), fin))
      {
nextline:
        if (strcmp(str, "\x1A\n")==0) break;
        if (curpart==1)
          if (fputs(str, fout)==EOF)
            goto errfputs;
        if (strcmp(str, "\n")==0)
        { if ((!partial) || (curpart!=1))
            break;
          partial=0;
          /* remove first header */
          fseek(fout, 0, SEEK_SET);
          chsize(fileno(fout), 0);
          fseek(fout, 0, SEEK_SET);
        }
        else if ((strnicmp(str, "From:", 5)==0) && (curpart==1))
        { for (p=str+5; (*p==' ') || (*p=='\t'); p++);
          strcpy(from, p);
          p=strchr(from, '\n');
          if (p) *p=0;
        }
        else if ((strnicmp(str, "Message-Id:", 11)==0) && (curpart==1))
          getvalue(str, msgid, sizeof(msgid));
        else if ((strnicmp(str, "X-Confirm-To:", 13)==0) && (curpart==1))
          getvalue(str, confirm, sizeof(confirm));
        else if (strnicmp(str, "Content-Type:", 13)==0)
        { char scrc32[32];
          getvalue(str, sstr, sizeof(sstr));
          if (stricmp(sstr, "message/partial")==0)
            partial=1;
          else
            partial=0;
          getparam(str, "crc32", scrc32, sizeof(scrc32));
          if (scrc32[0])
            sscanf(scrc32, "%lX", &fcrc32);
        }
        else if (curpart==1 && strnicmp(str,"X-PGP-Sig:",10)==0)
        { char *p1;
          int was_eol;
          was_eol=(strchr(str, '\n')!=NULL);
          for (p=str+10; isspace(*p); p++);
          if (*p)
            for (p1=p+strlen(p)-1; isspace(*p1); *p1--='\0');
          if (pgpsig) free(pgpsig);
          pgpsig=malloc(strlen(p)+1);
          if (pgpsig==NULL)
          { logwrite('!', "Not enough memory to check PGP-signature!\n");
            continue;
          }
          strcpy(pgpsig, p);
          while (fgets(str, sizeof(str), fin))
          { if (was_eol && str[0]!=' ' && str[0]!='\t')
              goto nextline;
            if (fputs(str,fout)==EOF)
              goto errfputs;
            was_eol=(strchr(str, '\n')!=NULL);
            for (p=str; isspace(*p); p++);
            if (*p=='\0') continue;
            for (p1=p+strlen(p)-1; isspace(*p1); *p1--='\0');
            pgpsig=realloc(pgpsig, strlen(pgpsig)+strlen(p)+1);
            if (pgpsig==NULL)
            { logwrite('!', "Not enough memory to check PGP-signature!\n");
              break;
            }
            strcat(pgpsig, p);
          }
          if (pgpsig[0]==0)
          { free(pgpsig);
            pgpsig=NULL;
          }
        }
      }
      if (strcmp(str, "\n"))
        continue;
      inparthdr=0;
      while (fgets(str, sizeof(str), fin))
gotline1:
        if (strcmp(str, "\n"))
        {
          if (strcmp(str, "\x1A\n")==0) break;
          if (fputs(str, fout)==EOF)
errfputs:
          { logwrite('!', "Error write to file %s: %s!\n", tmpname, strerror(errno));
            fclose(fin);
            fclose(fout);
            unlink(tmpname);
            fout=NULL;
            break;
          }
          if (boundary[0] && str[0]=='-' && str[1]=='-')
            if (strncmp(str+2, boundary, strlen(boundary))==0 &&
                str[strlen(boundary)+2]=='\n')
            { inparthdr=1;
              npart++;
              continue;
            }
          if (inparthdr)
          { if (strnicmp(str, "Content-Type:", 13)==0)
            { strcpy(cont_type, str);
              while (fgets(str, sizeof(str), fin))
              { if ((str[0]==' ') || (str[0]=='\t'))
                  strncat(cont_type, str, sizeof(cont_type));
                else
                { if (decodepart==0 || decodepart==npart || inname[0]==0)
                  { getparam(cont_type, "name", inname, sizeof(inname));
                    if (inname[0])
                    { strncpy(last->arcname, inname, sizeof(last->arcname));
                      decodepart=npart;
                    }
                  }
                  goto gotline1;
                }
              }
              break;
            }
            else if (strnicmp(str, "Content-Transfer-Encoding:", 26)==0)
            { for (p=str+26; isspace(*p); p++);
              if (decodepart==0 || decodepart==npart)
              { if (strnicmp(p, "base64", 6)==0)
                  last->enc=ENC_BASE64;
                else if (strnicmp(p, "quoted-printable", 16)==0)
                  last->enc=ENC_QP;
                else if (strnicmp(p, "8bit", 16)==0)
                  last->enc=ENC_8BIT;
                else if (strnicmp(p, "x-pgp", 5)==0)
                  last->enc=ENC_PGP;
              }
            }
            else if (strnicmp(str, "Content-Disposition:", 20)==0)
            { strcpy(sstr, str);
              while (fgets(str, sizeof(str), fin))
              { if ((str[0]==' ') || (str[0]=='\t'))
                  strncat(sstr, str, sizeof(sstr));
                else
                { if (decodepart==0 || decodepart==npart || inname[0]==0)
                  { getparam(sstr, "filename", inname, sizeof(inname));
                    if (inname[0])
                    { strncpy(last->arcname, inname, sizeof(last->arcname));
                      decodepart=npart;
                    }
                  }
                  goto gotline1;
                }
              }
              break;
            }
          }
          else
          { if ((enc==ENC_UUE || enc==ENC_8BIT) && strnicmp(str, "begin ", 6)==0 &&
                isdigit(str[6]) && isdigit(str[7]) && isdigit(str[8]) &&
                ((str[9]==' ' && str[10] && !isspace(str[10])) ||
                (isdigit(str[9]) && str[10]==' ' && str[11] && !isspace(str[11]))))
            { p=str+10;
              if (*p==' ') p++;
              strncpy(last->arcname, p, sizeof(last->arcname));
              last->arcname[sizeof(last->arcname)-1]='\0';
              for (p=last->arcname; *p && !isspace(*p); p++);
              *p='\0';
              enc=ENC_UUE;
            }
          }
        }
        else
        {
          inparthdr=0;
          if (fputs(str, fout)==EOF)
            goto errfputs;
        }
      if (fout==NULL)
        break;
      fclose(fin);
    }
    if (curpart<=last->parts)
    { if (pgpsig) free(pgpsig);
      pgpsig=NULL;
      continue;
    }
    fclose(fout);
    if (last->part_id[0])
      sprintf(msgid, "<%s>", last->part_id);
    if (last->passwd==SECURE)
    {
#if 0 /* PGP signature can be inside the file */
      if (last->host!=nhosts && hosts[last->host].pgpsig && !pgpsig)
      { logwrite('!', "No PGP signature from %s!\n", from);
        last->passwd = unsecure[0] ? UNSECURE : RESEND;
        if (last->passwd==RESEND)
        { /* resend all parts to postmaster */
          unlink(tmpname);
          if (confirm[0])
            sendack(confirm, msgid, ACK_FAIL, "no pgp signature found");
          alltopostmast(last);
          continue;
        }
      }
      else
#endif
      if ((last->host==nhosts || hosts[last->host].pgpsig==0) && pgpsig)
      { debug(2, "CheckTemp: PGP signature from %s ignored", from);
        free(pgpsig);
        pgpsig=NULL;
      }
    }
    /* run uudecode */
    mkarcname(last->arcname, inname, last->passwd);
    mktempname(TMPARCNAME, tmp_arc);
    if (uudecode_fmt[0] && (last->enc==ENC_UUE))
    { strcpy(str, uudecode_fmt);
#ifndef UNIX
      strlwr(str);
#endif
      chsubstr(str, "%infile", tmpname);
      chsubstr(str, "%outfile", tmp_arc);
      debug(5, "CheckTmp: exec '%s'", str);
      r=swap_system(str);
    }
    else if (last->enc==ENC_PGP)
    { if (pgpdec_fmt[0]==0)
      { logwrite('?', "Can't decode pgp message: pgp-decode not specified!\n");
        r=1;
      }
      else
      { sprintf(str, "%s <%s >%s", pgpdec_fmt, tmpname, tmp_arc);
        debug(5, "CheckTmp: exec '%s'", str);
        r=swap_system(str);
        if (!quiet) fputs("\n", stderr);
        if (r==0 && last->host!=nhosts && hosts[last->host].pgpsig && pgpsig==NULL)
        { debug(1, "Signature found inside encoded file");
          pgpsig=strdup("");
        }
        else if (r==1)
          r=0; /* success, no signature found */
      }
    }
    else
    { /* internal */
      if (last->enc==ENC_BASE64)
      { debug(5, "CheckTmp: run internal unbase64 %s to %s", tmpname, tmp_arc);
        r=do_unbase64(tmpname, tmp_arc, decodepart);
      }
      else if (last->enc==ENC_QP)
      { debug(5, "CheckTmp: run internal q-p decoder %s to %s", tmpname, tmp_arc);
        r=do_unqp(tmpname, tmp_arc, decodepart);
      }
      else if (last->enc==ENC_8BIT)
      { debug(5, "CheckTmp: run internal 8bit decoder %s to %s", tmpname, tmp_arc);
        r=do_un8bit(tmpname, tmp_arc, decodepart);
      }
      else
      { debug(5, "CheckTmp: run internal uudecode %s to %s", tmpname, tmp_arc);
        r=do_uudecode(tmpname, tmp_arc);
      }
    }
    debug(5, "CheckTmp: retcode %d", r);
    if (r)
    { if (access(tmp_arc, 0)==0)
        unlink(tmp_arc);
      logwrite('?', "Error while decoding %s\n", basename(inname));
      unlink(tmpname);
      if (!bypipe) retcode|=RET_ERR;
      if (pgpsig) free(pgpsig);
      pgpsig=NULL;
      if (confirm[0])
        sendack(confirm, msgid, ACK_FAIL, "decode error");
      alltopostmast(last);
      continue;
    }
    if (access(tmp_arc, 0))
    { logwrite('?', "Error while decoding %s\n", basename(inname));
      if (!bypipe) retcode|=RET_ERR;
      unlink(tmpname);
      if (pgpsig) free(pgpsig);
      pgpsig=NULL;
      if (confirm[0])
        sendack(confirm, msgid, ACK_FAIL, "decode error");
      alltopostmast(last);
      continue;
    }
    
    /* remove all parts and rebuilded file */
    debug(5, "CheckTmp: delete %s", tmpname);
    unlink(tmpname);
    if (fcrc32!=(unsigned long)-1)
    { unsigned long calccrc32=filecrc32(tmp_arc);
      if (calccrc32!=(unsigned long)-1)
      { if (calccrc32!=fcrc32)
        { logwrite(nocrc ? '!' : '?', "CRC error (%08lX!=%08lX) for file %s from %s!\n",
                   calccrc32, fcrc32, basename(inname), from);
          if (!nocrc)
          { unlink(tmp_arc);
            if (confirm[0])
              sendack(confirm, msgid, ACK_FAIL, "crc error");
            alltopostmast(last);
            continue;
          }
        }
        else
          debug(2, "file %s crc ok (%08lX)", basename(inname), fcrc32);
      }
    }
    if (pgpsig)
    { if (pgpsig[0] && checkpgpsig(tmp_arc, pgpsig, from))
      { free(pgpsig);
        pgpsig=NULL;
        logwrite('!', "Bad pgp signature from %s!\n", from);
nopgp:
        if (last->passwd==SECURE)
        {
          if (unsecure[0]=='\0')
          { unlink(tmp_arc);
            last->passwd=RESEND;
            if (confirm[0])
              sendack(confirm, msgid, ACK_FAIL, "pgp signature error");
            /* resend all parts to postmaster */
            alltopostmast(last);
            continue;
          }
          else
          { /* move arcname to unsecure dir */
            last->passwd=UNSECURE;
            makename(inname, str, unsecure);
            strcpy(inname, str);
          }
        }
      }
      else
        debug(2, "Good pgp signature from %s", from);
      if (pgpsig) free(pgpsig);
      pgpsig=NULL;
    }
    else if (last->host!=nhosts && hosts[last->host].pgpsig)
    { logwrite('!', "No pgp signature from %s!\n", from);
      goto nopgp;
    }
    strcpy(str, inname);
    if (rmove(tmp_arc, inname))
    { logwrite('!', "Can't move %s to %s!\n", tmp_arc, inname);
      unlink(tmp_arc);
      last->passwd=RESEND;
      if (confirm[0])
        sendack(confirm, msgid, ACK_FAIL, "internal error");
      alltopostmast(last);
      continue;
    }
    debug(1, "Saving %s as %s", basename(str), inname);

    if (last->ftime)
    { struct utimbuf utb;
      debug(4, "CheckTmp: set original date & time for %s", inname);
      utb.actime = utb.modtime = last->ftime;
      utime(inname, &utb);
    }
    stat(inname, &statbuf);
    if (!bypipe) retcode|=RET_RCV;
    newecho=1;
    if (confirm[0])
      sendack(confirm, msgid, ACK_OK, (last->passwd==SECURE) ? "secure" : "unsecure");
    logwrite('$', "File %s from %s size %lu successfully decoded (multipart)\n",
             last->arcname, from, statbuf.st_size);
    for (curpart=1; curpart<=last->parts; curpart++)
    {
      for (cur=flist; cur!=NULL; cur=cur->next)
      { if (cur->curpart!=curpart)
          continue;
        if (last->part_id[0] && (strcmp(last->part_id, cur->part_id)==0))
          break;
        if (stricmp(last->arcname, cur->arcname))
          continue;
        if (memcmp(&(cur->ftime), &(last->ftime), sizeof(cur->ftime)))
          continue;
        if (last->parts!=cur->parts)
          continue;
        break;
      }
      strcpy(str, incomplete);
      addslash(str);
      strcat(str, cur->uuename);
      unlink(str);
      debug(6, "CheckTmp: delete %s", str);
    }
  }
  /* free memory */
  debug(8, "CheckTmp: free memory");
  for (last=flist; last!=NULL;)
  { cur=last->next;
    if (last->boundary) free(last->boundary);
    free(last);
    last=cur;
  }
  debug(8, "CheckTmp: done");
}
