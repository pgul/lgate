/*
 * $Id$
 *
 * $Log$
 * Revision 2.1  2004/07/20 17:58:34  gul
 * \r\n -> \n
 *
 * Revision 2.0  2001/01/10 20:42:19  gul
 * We are under CVS for now
 *
 */

#ifndef _FIDOLIB_H
#define _FIDOLIB_H

/* msg header attributes .msg */
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

/* for ScanBinkOutbound */
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

/* .msg header */
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

/* .pkt header */
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

/* week day names - first 3 chars */
/* weekday[0] - "Sun" */
extern char * weekday[7];
/* names of monthes, first 3 chars */
/* montable[0] - "Jan" */
extern char * montable[12];
/* Number of days in monthes */
/* daymon[0]=31, daymon[1]=28 */
extern char daymon[12];

/* Open file. Try several times if cannot open by share */
int  myopen(char *fname, unsigned attr);
/* simple copy file */
int  copyfile(char *from, char *to);
/* read FTN-addr from text string addr */
int  getfaddr(char *addr, ftnaddr *node, unsigned defzone, unsigned defnet);
int  getfidomask(char *addr, ftnaddr *node, uword defzone);
/* calculate crc32 of the line, for example, for FrontDoor busy-flags */
unsigned long crc32(char *str);
unsigned long filecrc32(char *fname);
/* set bsy for BSO. Return 0 on success */
int  SetBinkSem(ftnaddr *addr, char *path, uword defzone);
/* The same for FronDoor */
int  SetFDSem(ftnaddr *addr, char *path);
/* remove bsy-flag */
int  DelBinkSem(ftnaddr *addr, char *path, uword defzone);
int  DelFDSem(ftnaddr *addr, char *path);
/* return full bsy-name (create all needed dirs) */
char *GetBinkBsyName(ftnaddr *addr, char *path, uword defzone);
#ifndef __MSDOS__
int  SetLBSOSem(ftnaddr *addr, char *domain, char *path);
int  DelLBSOSem(ftnaddr *addr, char *domain, char *path);
char *GetLBSOBsyName(ftnaddr *addr, char *domain, char *path);
#endif
/* read FTN-address mask (wildcard) */
/* -1 means '*' */
int  getfmask(char *addr, ftnaddr *node, uword defzone);
/* check the address by mask */
int  chkmask(ftnaddr *addr, ftnaddr *mask);
int  checkmask(uword zone, uword net, uword node, uword point,
               uword mzone, uword mnet, uword mnode, uword mpoint);
/* move the file, return 0 on success */
int  move(char *oldname, char *newname);
/* like move(), but change extension if file already exists */
int  rmove(char *oldname, char *newname);
/* get weekday (0 - sunday) */
/* month from 0, year from 1900 */
int  dayweek(int year, int month, int day);
/* Set file modtime to curtime. Create file if not exists. */
int touch(char *fname);
#if defined (_SYS_STAT_H) || defined(_STAT_H_INCLUDED) || defined(_STAT_H) || defined(__STAT_H)
/* needed #include <sys/stat.h> (for struct stat) */
/* scan all bink outbound, for every *.?lo call chklo */
/* If attr & IGNOREZEROLO - ignore zero-length lo-files */
/* If attr & SETBSY - check and set bsy-files */
void ScanBinkOutbound(char *path, unsigned zone, char attr,
                void (*chklo)(char *lopath, struct stat *ff, ftnaddr *loaddr));
#endif
#ifdef __MSDOS__
/* put var value to start-file, for .com */
/* exewrite is in the glib */
int  comwrite(void * var,unsigned size);
/* simple delay */
/* autodetect DesqView giveup cpu */
/* without DesqView giveup timeslices by int 28h */
void dvdelay(unsigned miliseconds);
#endif

#endif
