#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include "gate.h"

static char arr_base64[64]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/";
static char sfile[FNAME_MAX];

void putfiles(VIRT_FILE *fout, char *subj, char *bound)
{
  char str[sizeof(msghdr.subj)+1];
  char stype[64];
  char c, *p, *p1, *p2, *ext, *codedname;
  char oct[3];
  int  bytes, n, name8bit;
  FILE * f;
  long filelen;

  debug(6, "PutFiles('%s')", subj);
  strncpy(str, subj, sizeof(str));
  str[sizeof(str)-1]='\0';
  for (p=str; *p; p=p1)
  { while (isspace(*p)) p++;
    if (*p=='\0') break;
    for (p1=p; *p1 && !isspace(*p1); p1++);
    c=*p1;
    *p1='\0';
    /* убираем путь */
    for (p2=p1-1; p2>p; p2--)
      if ((*p2=='/') || (*p2=='\\') || (*p2==':'))
      { p2++;
        break;
      }
    virt_fprintf(fout, "\n--%s\n", bound);
    if (packed)
    { sprintf(sfile, "%s%s", tmpdir, p2);
      if (access(sfile, 0) && pktin[0])
        sprintf(sfile, "%s%s", pktin, p2);
    }
    else
      if (strpbrk(p, "/\\") == NULL)
        sprintf(sfile, "%s%s", inb_dir, p);
      else
        strncpy(sfile, p, sizeof(sfile)); 
    debug(4, "PutFiles: encoding file %s", sfile);
    { char *p;
      name8bit=0;
      for (p=p2; *p; p++)
      { if (*p & 0x80)
        { name8bit=1;
          break;
        }
      }
    }
    f=fopen(sfile, "rb");
    if (f==NULL)
    { logwrite('!', "Can't open attached file %s: %s\n",sfile,strerror(errno));
      int2ext(p2);
      virt_fprintf(fout, "Content-Type: text/plain; charset=%s\n\n",
                   name8bit ? myextsetname : "us-ascii");
      virt_fprintf(fout, "Cannot open attached file %s: %s\n", p2, strerror(errno));
      *p1=c;
      continue;
    }
    ext=strrchr(p2, '.');
    if (ext==NULL) ext=p1; /* null string */
    else p++;
    if (stricmp(ext, "gif")==0)
      sprintf(stype, "image/gif");
    else if ((stricmp(ext, "jpg")==0) || (stricmp(ext, "jpeg")==0))
      sprintf(stype, "image/jpeg");
    else if ((stricmp(ext, "mpg")==0) || (stricmp(ext, "mpeg")==0))
      sprintf(stype, "video/mpeg");
    /* и разные другие ;-) */
    else
      sprintf(stype,"application/octet-stream");
    codedname=NULL;
    if (name8bit)
    { if (hdr8bit)
        codedname=malloc(strlen(p2)*3+strlen(myextsetname)+4);
      else
        int2ext(p2);
    }
    if (codedname)
    { char *src, *dest;
      sprintf(codedname, "%s\'\'", myextsetname);
      for (src=p2, dest=codedname+strlen(codedname); *src; src++)
      { if (((*src & 0x80)==0) && (isalpha(*src) || isdigit(*src) || *src=='.'))
          *dest++=int2ext_tab[*src];
        else
        { sprintf(dest, "%%%02X", int2ext_tab[*src]);
          dest+=3;
        }
      }
    }
    debug(6, "PutFiles: set content-type for %s as %s", p2, stype);
    if (codedname)
      virt_fprintf(fout, "Content-Type: %s; name*=%s\n", stype, codedname);
    else
      virt_fprintf(fout, "Content-Type: %s; name=\"%s\"\n", stype, p2);
    virt_fprintf(fout, "Content-Transfer-Encoding: base64\n");
    if (codedname)
    { virt_fprintf(fout, "Content-Disposition: attachment; filename*=%s\n", codedname);
      free(codedname);
      codedname=NULL;
    }
    else
      virt_fprintf(fout, "Content-Disposition: attachment; filename=\"%s\"\n", p2);
    fseek(f, 0, SEEK_END);
    filelen=ftell(f);
    fseek(f, 0, SEEK_SET);
    virt_fprintf(fout, "Content-Length: %lu\n", ((filelen+2)/3)*4+(filelen+44)/45);
    virt_fprintf(fout, "Lines: %lu\n", (filelen+44)/45);
    virt_fputs("\n",fout);
    *p1=c;
    
    /* base64 encoding */
    bytes=0;
    for (;;)
    { n=fread(oct,1,3,f);
      if (n<=0) break;
      bytes+=4;
      if (n<3) oct[n]=0;
      virt_putc(arr_base64[oct[0]>>2],fout);
      virt_putc(arr_base64[((oct[0] & 0x3)<<4) | (oct[1]>>4)],fout);
      if (n==1)
      { virt_putc('=',fout);
        virt_putc('=',fout);
        break;
      }
      virt_putc(arr_base64[((oct[1] & 0xf)<<2) | (oct[2]>>6)],fout);
      if (n==2)
      { virt_putc('=',fout);
        break;
      }
      virt_putc(arr_base64[oct[2] & 0x3f],fout);
      if (bytes==60)
      { virt_putc('\n',fout);
        bytes=0;
      }
    }
    if (bytes)
      virt_putc('\n',fout);
    fclose(f);
  }
  debug(6, "PutFiles: done", subj);
}

void delsentfiles(unsigned long attr, char *subj)
{
  char c, *p, *p1, *p2;
  int  h;

  debug(6, "DelSentFiles");
  if (packed)
    attr |= msgKFS;
  if ((attr & (msgKFS | msgTFS)) == 0)
    if (((attr & msgFORWD) == 0) || (!deltransfiles))
      return;
  for (p=subj;*p;p++)
  {
    while (isspace(*p)) p++;
    if (*p=='\0') break;
    for (p1=p;*p1 && !isspace(*p1);p1++);
    c=*p1;
    *p1='\0';
    if (packed)
    { /* remove path */
      for (p2=p1-1;p2>p;p2--)
        if ((*p2=='/') || (*p2=='\\') || (*p2==':'))
        { p2++;
          break;
        }
      sprintf(sfile, "%s%s", tmpdir, p2);
      if (access(sfile,0) && pktin[0])
        sprintf(sfile, "%s%s", pktin, p2);
      else
      { /* delete later - file can be attached to another recipient */
        for (h=0; h<nkillattfiles; h++)
          if (stricmp(killattfiles[h].name, p2)==0)
            break;
        if (h<nkillattfiles)
        { killattfiles[h].attr |= msgSENT;
          *p1=c;
          p=p1;
          if (*p=='\0') break;
          continue;
        }
      }
    }
    else
      if (strpbrk(p, "/\\") == NULL)
        sprintf(sfile, "%s%s", inb_dir, p);
      else
        strncpy(sfile, p, sizeof(sfile)); 
    if ((attr & msgKFS) ||
        ((attr & msgFORWD) && deltransfiles))
    { if (nkillattfiles<sizeof(killattfiles)/sizeof(killattfiles[0]))
      { killattfiles[nkillattfiles].name=strdup(sfile);
        killattfiles[nkillattfiles++].attr=msgKFS|msgSENT;
      }
      else
      { if (unlink(sfile))
          logwrite('?',"Can't delete sent file %s: %s!\n",sfile,strerror(errno));
        else
          debug(4, "DelSentFiles: file %s deleted", sfile);
      }
    }
    else if (attr & msgTFS)
    { if (nkillattfiles<sizeof(killattfiles)/sizeof(killattfiles[0]))
      { killattfiles[nkillattfiles].name=strdup(sfile);
        killattfiles[nkillattfiles++].attr=msgTFS|msgSENT;
      }
      else
      { h=open(sfile,O_BINARY|O_RDWR|O_EXCL);
        if (h!=-1)
        { chsize(h,0);
          close(h);
          debug(4, "DelSentFiles: file %s truncated", sfile);
        }
        else
          logwrite('?',"Can't truncate sent file %s: %s!\n",sfile,strerror(errno));
      }
    }
    *p1=c;
    p=p1;
    if (*p=='\0') break;
  }
}
