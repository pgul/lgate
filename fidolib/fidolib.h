
#ifndef _FIDOLIB_H
#define _FIDOLIB_H

/* аттрибуты письма для заголовка .msg */
#define  msgPRIVATE   0x0001
#define  msgCRASH     0x0002
#define  msgREAD      0x0004
#define  msgSENT      0x0008
#define  msgFILEATT   0x0010
#define  msgFORWD     0x0020
#define  msgORPHAN    0x0040
#define  msgKILLSENT  0x0080
#define  msgLOCAL     0x0100
#define  msgHOLD      0x0200

#define  msgFREQ      0x0800
#define  msgRETRECREQ 0x1000
#define  msgRETREC    0x2000
#define  msgAUDITTR   0x4000
#define  msgUPREQ     0x8000

/* Non-standard attributes */
#define msgDIRECT     0x10000l
#define msgLOCK       0x20000l
#define msgIMM        0x40000l
#define msgKFS        0x80000l
#define msgTFS        0x100000l
#define msgCFM        0x200000l

/* для ScanBinkOutbound */
#define IGNOREZEROLO   1
#define SETBSY         2

#ifndef PATHSEP
#ifdef UNIX
#define PATHSEP        '/'
#define PATHSTR        "/"
#define DISKPATH       0
#else
#define PATHSEP        '\\'
#define PATHSTR        "\\"
#define DISKPATH       2
#endif
#endif

#ifdef UNIX
#ifndef O_BINARY
#define O_BINARY 0
#define O_TEXT   0
#endif
#endif

typedef short int word;
typedef unsigned short int uword;

/* заголовок .msg */
struct message
     {
       char from[36];
       char to[36];
       char subj[72];
       char date[20];
       word times_read,
            dest_node,
            orig_node,
            cost,
            orig_net,
            dest_net,
            dest_zone,
            orig_zone,
            dest_point,
            orig_point;
       word replyto;
       uword attr;
       word next_reply;
     };

/* заголовок .pkt */
struct packet
     {
       word OrigNode,
            DestNode,
            year,
            month,
            day,
            hour,
            min,
            sec,
            baud,
            two,
            OrigNet,
            DestNet;
       char ProdCodeL,
            RevisionMaj;
       char password[8];
       word OrigZone,
            DestZone,
            AuxNet,
            CWvalidationCopy;
       char ProdCodeH,
            RevisionMin;
       word CapabilWord,
            OrigZone_,
            DestZone_,
            OrigPoint,
            DestPoint,
            ProductData[2];
     };

typedef struct
        { uword zone,net,node,point;
        } ftnaddr;

#ifdef __PASCAL__
#define weekday   _weekday
#define montable  _montable
#define daymon    _daymon
#endif

/* имена дней недели - по 3 символа */
/* weekday[0] - "Sun" */
extern char * weekday[7];
/* названия месяцев, по 3 символа */
/* montable[0] - "Jan" */
extern char * montable[12];
/* Кол-во дней в месяцах */
/* daymon[0]=31, daymon[1]=28 */
extern char daymon[12];

/* открывает файл. Если не открывается по share - делает несколько попыток */
int  myopen(char * fname,unsigned attr);
/* просто копирует файл */
int  copyfile(char * from,char * to);
/* читает фидошный адрес из строки addr */
int  getfaddr(char * addr,ftnaddr * node,unsigned defzone,unsigned defnet);
int  getfidomask(char * addr,ftnaddr * node,uword defzone);
/* считает crc32 строки, например, для флагов занятости FrontDoor */
unsigned long crc32(char * str);
unsigned long filecrc32(char * fname);
/* Выставляет бзюху для бинки. Возвращает 0 в случае успеха */
int  SetBinkSem(ftnaddr * addr,char * path,uword defzone);
/* То же для FronDoor */
int  SetFDSem(ftnaddr * addr,char * path);
/* удаление флага занятости */
int  DelBinkSem(ftnaddr * addr,char * path,uword defzone);
int  DelFDSem(ftnaddr * addr,char * path);
/* выдает полное имя бзюхи (создает все нужные каталоги при необходимости) */
char * GetBinkBsyName(ftnaddr * addr,char * path,uword defzone);
#ifndef __MSDOS__
int  SetLBSOSem(ftnaddr *addr, char *domain, char *path);
int  DelLBSOSem(ftnaddr *addr, char *domain, char *path);
char *GetLBSOBsyName(ftnaddr *addr, char *domain, char *path);
#endif
/* читает фидошную маску */
/* -1 - это '*' */
int  getfmask(char * addr,ftnaddr * node,uword defzone);
/* подходит ли адрес по маске */
int  chkmask(ftnaddr * addr,ftnaddr * mask);
int  checkmask(uword zone,uword net,uword node,uword point,
               uword mzone,uword mnet,uword mnode,uword mpoint);
/* переместить файл, возвращает 0 в случае успеха */
int  move(char * oldname,char * newname);
/* как move, но изменяет расширение, если файл уже существует */
int  rmove(char * oldname,char * newname);
/* возвращает день недели (0 - воскресенье) */
/* Месяц от 0, год от 1900 */
int  dayweek(int year,int month,int day);
/* поставить дату файла на текущую. Создать файл, если его нет */
int touch(char * fname);
#if defined (_SYS_STAT_H) || defined(_STAT_H_INCLUDED) || defined(_STAT_H) || defined(__STAT_H)
/* требует предварительного #include <sys/stat.h> (для struct stat) */
/* просмотреть весь bink outbound, для каждой лошки вызвать chklo */
/* Если attr & IGNOREZEROLO - лошки нулевой длины игнорируются */
/* если attr & SETBSY - смотрятся и устанавливаются бзюхи */
void ScanBinkOutbound(char *path, unsigned zone, char attr,
                void (*chklo)(char *lopath, struct stat *ff, ftnaddr *loaddr));
#endif
#ifdef __MSDOS__
/* записать значение переменной в себя, для случая .com */
/* exewrite есть в библиотеке glib */
int  comwrite(void * var,unsigned size);
/* просто задержка */
/* автоопределяет DesqView и отдает тики процессора */
/* без DesqView отдает по int 28h */
void dvdelay(unsigned miliseconds);
#endif

#endif
