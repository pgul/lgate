#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "gate.h"

void fido2rfc(char *from, char *msgfrom,
             uword zone, uword net, uword node, uword point,
             char *domain)
{
  char *p;

  debug(10, "Fido2RFC: '%s' %d:%d/%d.%d @%s", msgfrom,
        zone,net,node,point,domain);
  if ((msgfrom[0]=='@') || (msgfrom[0]=='%') || (msgfrom[0]==0))
  { from[0]=' ';
    strcpy(from+1, msgfrom);
  }
  else
    strcpy(from, msgfrom);
  for (p=from; *p; p++)
  { /* '%' и '!' сознательно оставляем */
    if ((*p==' ') || (*p=='\t'))
    { *p=fsp1004 ? '.' : '_';
      if (curgate!=ngates)
        if (gates[curgate].yes==2) /* ifmail */
          *p='.';
    }
    if ((*p=='(') || (*p=='<'))
      *p='{';
    if ((*p==')') || (*p=='>'))
      *p='}';
    if ((*p==':') || (*p==',') || (*p==';') || (*p=='#'))
      *p='.';
    if (*p=='@')
      *p='%';
  }
#ifdef PERCENT
  if (zone==myaka[0].zone)
  { if (point)
      sprintf(p, "%%%u/%u.%u@%s", net, node, point, domain);
    else
      sprintf(p, "%%%u/%u@%s", net, node, domain);
  }
  else
  { if (point)
      sprintf(p, "%%%u.%u/%u.%u@%s", zone, net, node, point, domain);
    else
      sprintf(p, "%%%u.%u/%u@%s", zone, net, node, domain);
  }
#else
  if (point)
    sprintf(p, "@p%u.f%u.n%u.z%u.%s", point, node, net, zone, domain);
  else
    sprintf(p, "@f%u.n%u.z%u.%s", node, net, zone, domain);
#endif
  p=strchr(domain, '@');
  if (p)
  { p=strchr(from, '@');
    if (p) *p='%';
  }
  /* дописываем real name в скобках */
  if (curgate==ngates)
  { strcat(from, " (");
    strcat(from, msgfrom);
    strcat(from, ")");
  }
  debug(10, "Fido2RFC: result is '%s'", from);
}

int gettz(char *p)
{ int i;

  debug(10, "GetTZ: %s", p);
  if ((*p=='+') || (*p=='-'))
  { i=atoi(p+1);
    if (i>=100) i/=100;
    if (i>=24) i=0;
    if (*p=='-') i=-i;
    debug(10, "GetTZ: return %d", i);
    return i;
  }
  if (strnicmp(p, "est", 3)==0) return -5;
  if (strnicmp(p, "edt", 3)==0) return -4;
  if (strnicmp(p, "cst", 3)==0) return -6;
  if (strnicmp(p, "cdt", 3)==0) return -5;
  if (strnicmp(p, "mst", 3)==0) return -7;
  if (strnicmp(p, "mdt", 3)==0) return -6;
  if (strnicmp(p, "pst", 3)==0) return -8;
  if (strnicmp(p, "pdt", 3)==0) return -7;
  if ((strnicmp(p, "ut", 2)==0) || (strnicmp(p, "gmt", 3)==0)) return 0;
  if (isalpha(p[1])) return 0;
  if (*p=='Z') return 0;
  if (*p=='A') return -1;
  if (*p=='M') return -12;
  if (*p=='N') return 1;
  if (*p=='Y') return 12;
  return 0;
}

static char product[128];

void convrcv(char *via, char *rcv)
{
  char *p, *p1=NULL;
  char c;
  uword nz, nn, nf, np;
  int year, mon, day, hour, min, sec, tz=0;
  int waszone, wasnet, wasnode, faddr;
  int i;

  debug(9, "ConvRcv: %s", via);
  strcpy(rcv, "Received: by ");
  /* все, что до адреса - product */
  faddr=1;
  for (p=via; p; p=strpbrk(p, " \t"))
  {
    while (isspace(*p)) p++;
    if (*p=='\0')
    { p=NULL;
      break;
    }
    if (*p=='@')
    { /* @19970221.171355 ? */
      if (sscanf(p, "@%4d%2d%2d.%2d%2d%2d",
                 &year, &mon, &day, &hour, &min, &sec)!=6)
        continue;
      if ((year<1970) || (year>2050) || (mon<1) || (mon>12) || (day<1) ||
          (day>31) || (hour<0) || (hour>23) || (min<0) || (min>59) ||
          (sec<0) || (sec>59))
        continue;
      *p='\0';
      strcat(rcv, via);
      *p='@';
      np=1;
      faddr=0;
      goto nofidoaddr;
    }
    if (getfidoaddr(&nz, &nn, &nf, &np, p)!=0)
      continue;
    /* А действительно ли написан валидный адрес? */
    waszone=wasnet=wasnode=0;
    for (p1=p; *p1; p1++)
    { if (isdigit(*p1)) continue;
      if (*p1==':')
      { if (waszone || wasnet || wasnode || (p==p1) || !isdigit(p1[1]))
          break;
        waszone=1;
        continue;
      }
      if (*p1=='/')
      { if (wasnet || wasnode || (p==p1) || !isdigit(p1[1]))
          break;
        wasnet=1;
        continue;
      }
      if (*p1=='.')
      { if (wasnode || !wasnet || !isdigit(p1[1]))
          break;
        wasnode=1;
        continue;
      }
      break;
    }
    if ((strchr(" ,;\t@", *p1)!=NULL) && wasnet)
    {
      c=*p;
      *p=0;
      strcpy(product, via);
      *p=c;
      break;
    }
  }
  if (p==NULL)
  { strcat(rcv, via);
    /* ищем время, дописываем, если нет */
    p=strrchr(rcv, ';');
    if (p)
    { for (; !isdigit(*p); p++);
      if ((atoi(p)>0) && (atoi(p)<=31))
      { p=strpbrk(p, " \t");
        if (p)
        { for(; (*p==' ') || (*p=='\t'); p++);
          for (mon=0; mon<12; mon++)
            if (strnicmp(p, montable[mon], 3)==0) break;
          if (mon<12)
          { /* ладно, облом дальше корректность проверять ;) */
            debug(9, "ConvRcv: return: %s", rcv);
            return;
          }
        }
      }
    }
    p=strchr(rcv, '\n');
    if (p) *p=0;
    strcat(rcv, "; Mon, 1 Jan 1970 00:00:00 GMT\n");
    debug(9, "ConvRcv: return: %s", rcv);
    return;
  }
  if (np)
    sprintf(rcv+strlen(rcv), "p%u.", np);
  sprintf(rcv+strlen(rcv), "f%u.n%u.z%u.", nf, nn, nz);
  p=strpbrk(p, "@ \t,;");
  if (p && *p=='@')
  { p++;
    p1=strpbrk(p, " \t,;\n");
    if (p1==NULL) p1=p+strlen(p);
    c=*p1;
    *p1=0;
    /* ищем этот домен */
    for (i=0; i<naka; i++)
      if (stricmp(p, myaka[i].ftndomain)==0)
        break;
    if (i<naka)
    { *p1=c;
      p=p1;
      strcat(rcv, myaka[i].domain);
      p1=strpbrk(rcv, "%@");
      if (p1) *p1=0;
    }
    else
    { strcat(rcv, p);
      *p1=c;
      p=p1;
    }
  }
  else
  { strcat(rcv, myaka[curaka].domain);
    p1=strpbrk(rcv, "%@");
    if (p1) *p1=0;
  }
  strcat(rcv, " ");
  /* читаем время */
  np=0;
  tz=0;
  for (; p; p=strpbrk(p, " \t,;"))
  {
loopdate:
    p++;
    if (*p=='@')
    { /* предполагаем дату */
      if (sscanf(p+1, "%4u%2u%2u.%2u%2u%2u",
                 &year, &mon, &day, &hour, &min, &sec)==6)
      { if ((year>2050) || (year<1970) || (mon>12) || (mon<1) || (day<1) ||
            (day>31) || (hour>23) || (min>59) || (sec>59))
          continue;
nofidoaddr:
        p=strpbrk(p+10, " \t,;.");
        np=1;
        mon--;
        nf=0;
        if (*p=='.')
        { p1=strpbrk(p+1, ". \t,;");
          if (p1)
            if (*p1=='.')
              p=p1;
          if ((strnicmp(p, ".utc",4)==0) && ((p[4]=='+') || (p[4]=='-')))
            p+=3;
          tz=gettz(p+1);
          p=strpbrk(p+1, " \t,;");
        }
        else
        { /* не tz ли это lgate-овское? */
          if (*p==' ')
          { while (*p==' ') p++;
            if (((*p=='+') || (*p=='-')) && (isdigit(p[1])))
            { tz=gettz(p);
              p=strpbrk(p, " \t,;");
            }
          }
        }
        break;
      }
      continue;
    }
    if (isdigit(*p))
    { /* не число ли это? */
      day=atoi(p);
      if ((day<1) || (day>31)) continue;
      p=strpbrk(p, " \t,;");
      if (p==NULL) break;
      if ((*p==',') || (*p==';')) goto loopdate;
      while ((*p==' ') || (*p=='\t')) p++;
      for (mon=0; mon<12; mon++)
        if (strnicmp(p, montable[mon], 3)==0)
          break;
      if (mon==12) goto loopdate;
      goto getyear;
    }
    else if (strlen(p)>3 && p[3]==' ')
    { for (mon=0; mon<12; mon++)
        if (strnicmp(p, montable[mon], 3)==0)
          break;
      if (mon==12) continue;
      p+=3;
      while ((*p==' ') || (*p=='\t')) p++;
      if (!isdigit(*p)) goto loopdate;
      day=atoi(p);
      if ((day==0) || (day>31)) goto loopdate;
getyear:
      p=strpbrk(p, " \t,;");
      if (p==NULL) break;
      if ((*p==',') || (*p==';')) goto loopdate;
      while ((*p==' ') || (*p=='\t')) p++;
      if (!isdigit(*p)) goto loopdate;
      year=atoi(p);
      if (year<1900) year+=1900;
      if ((year<1970) || (year>2050)) goto loopdate;
      p=strpbrk(p, " \t");
      if (p==NULL) break;
      while ((*p==' ') || (*p=='\t')) p++;
      if (strnicmp(p, "at ", 3)==0)
      { p+=3;
        while ((*p==' ') || (*p=='\t')) p++;
      }
      /* читаем время */
      if (!isdigit(*p)) goto loopdate;
      if (sscanf(p, "%2u:%2u:%2u", &hour, &min, &sec)!=3)
      { sec=0;
        if (sscanf(p, "%2u:%2u", &hour, &min)!=2) goto loopdate;
      }
      nf=0;
      np=2;
      p1=p;
      p=strpbrk(p, " \t");
      if (p==NULL) break;
      while ((*p==' ') || (*p=='\t')) p++;
      tz=gettz(p);
      break;
    }
  }

  /* после времени (которое '@') может быть product */
  if (strchr(product, '\n')!=NULL)
    *strchr(product, '\n')=0;
  stripspc(product);
  if (strlen(product)>3 && stricmp(product+strlen(product)-3," on")==0)
  { product[strlen(product)-3]=0;
    stripspc(product);
  }
  if (np==1)
  { if (p)
    { if (product[0]) strcat(product, " ");
      while ((*p==' ') || (*p=='\t') || (*p==';') || (*p==','))
        p++;
      strcat(product, p);
      p=strchr(product, '\n');
      if (p) *p=0;
      stripspc(product);
    }
  }
  else if (np==2)
  { p=strchr(p1, '(');
    if (p)
    { np=1;
      p1=p;
      while(np)
      { p1=strpbrk(p1+1, "()");
        if (p1==NULL) break;
        if (*p1=='(') np++;
        else np--;
      }
      if (p1)
      { *p1=0;
        if (product[0]) strcat(product," ");
        strcat(product, p+1);
      }
    }
  }
  else
  { /* no date */
    debug(9, "ConvRcv: no date found, via ignored");
    rcv[0]='\0';
    return;
  }
  if (product[0])
    sprintf(rcv+strlen(rcv), "(%s)", product);
  if (faddr)
    strcat(rcv, " with FTN");
  strcat(rcv, "; ");
  sprintf(rcv+strlen(rcv), "%s, %2u %s %u %02u:%02u:%02u ",
          weekday[dayweek(year-1900, mon, day)], day, montable[mon], year,
          hour, min, sec);
  if (tz)
    sprintf(rcv+strlen(rcv), "%c%02u00",
            (tz>=0) ? '+' : '-', (tz>0) ? tz : -tz);
  else
    sprintf(rcv+strlen(rcv), "UTC");
  debug(9, "ConvRcv: return: %s", rcv);
  strcat(rcv, "\n");
}

void stripspc(char *str)
{ char *p;
  for (p=str+strlen(str)-1; ((*p==' ') || (*p=='\t')) && (p>=str); p--)
    *p=0;
}
