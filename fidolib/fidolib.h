
#ifndef _FIDOLIB_H
#define _FIDOLIB_H

/* ���ਡ��� ���쬠 ��� ��������� .msg */
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

/* ��� ScanBinkOutbound */
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

/* ��������� .msg */
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

/* ��������� .pkt */
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

/* ����� ���� ������ - �� 3 ᨬ���� */
/* weekday[0] - "Sun" */
extern char * weekday[7];
/* �������� ����楢, �� 3 ᨬ���� */
/* montable[0] - "Jan" */
extern char * montable[12];
/* ���-�� ���� � ������ */
/* daymon[0]=31, daymon[1]=28 */
extern char daymon[12];

/* ���뢠�� 䠩�. �᫨ �� ���뢠���� �� share - ������ ��᪮�쪮 ����⮪ */
int  myopen(char * fname,unsigned attr);
/* ���� ������� 䠩� */
int  copyfile(char * from,char * to);
/* �⠥� 䨤��� ���� �� ��ப� addr */
int  getfaddr(char * addr,ftnaddr * node,unsigned defzone,unsigned defnet);
int  getfidomask(char * addr,ftnaddr * node,uword defzone);
/* ��⠥� crc32 ��ப�, ���ਬ��, ��� 䫠��� ������� FrontDoor */
unsigned long crc32(char * str);
unsigned long filecrc32(char * fname);
/* ���⠢��� ����� ��� �����. �����頥� 0 � ��砥 �ᯥ� */
int  SetBinkSem(ftnaddr * addr,char * path,uword defzone);
/* �� �� ��� FronDoor */
int  SetFDSem(ftnaddr * addr,char * path);
/* 㤠����� 䫠�� ������� */
int  DelBinkSem(ftnaddr * addr,char * path,uword defzone);
int  DelFDSem(ftnaddr * addr,char * path);
/* �뤠�� ������ ��� ���� (ᮧ���� �� �㦭� ��⠫��� �� ����室�����) */
char * GetBinkBsyName(ftnaddr * addr,char * path,uword defzone);
#ifndef __MSDOS__
int  SetLBSOSem(ftnaddr *addr, char *domain, char *path);
int  DelLBSOSem(ftnaddr *addr, char *domain, char *path);
char *GetLBSOBsyName(ftnaddr *addr, char *domain, char *path);
#endif
/* �⠥� 䨤���� ���� */
/* -1 - �� '*' */
int  getfmask(char * addr,ftnaddr * node,uword defzone);
/* ���室�� �� ���� �� ��᪥ */
int  chkmask(ftnaddr * addr,ftnaddr * mask);
int  checkmask(uword zone,uword net,uword node,uword point,
               uword mzone,uword mnet,uword mnode,uword mpoint);
/* ��६����� 䠩�, �����頥� 0 � ��砥 �ᯥ� */
int  move(char * oldname,char * newname);
/* ��� move, �� ������� ���७��, �᫨ 䠩� 㦥 ������� */
int  rmove(char * oldname,char * newname);
/* �����頥� ���� ������ (0 - ����ᥭ�) */
/* ����� �� 0, ��� �� 1900 */
int  dayweek(int year,int month,int day);
/* ���⠢��� ���� 䠩�� �� ⥪����. ������� 䠩�, �᫨ ��� ��� */
int touch(char * fname);
#if defined (_SYS_STAT_H) || defined(_STAT_H_INCLUDED) || defined(_STAT_H) || defined(__STAT_H)
/* �ॡ�� �।���⥫쭮�� #include <sys/stat.h> (��� struct stat) */
/* ��ᬮ���� ���� bink outbound, ��� ������ ��誨 �맢��� chklo */
/* �᫨ attr & IGNOREZEROLO - ��誨 �㫥��� ����� ����������� */
/* �᫨ attr & SETBSY - ᬮ������ � ��⠭���������� ���� */
void ScanBinkOutbound(char *path, unsigned zone, char attr,
                void (*chklo)(char *lopath, struct stat *ff, ftnaddr *loaddr));
#endif
#ifdef __MSDOS__
/* ������� ���祭�� ��६����� � ᥡ�, ��� ���� .com */
/* exewrite ���� � ������⥪� glib */
int  comwrite(void * var,unsigned size);
/* ���� ����প� */
/* ��⮮�।���� DesqView � �⤠�� ⨪� ������ */
/* ��� DesqView �⤠�� �� int 28h */
void dvdelay(unsigned miliseconds);
#endif

#endif
