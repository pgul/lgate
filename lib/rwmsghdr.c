/*
 * $Id$
 *
 * $Log$
 * Revision 2.0  2001/01/10 20:42:23  gul
 * We are under CVS for now
 *
 */
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <string.h>
#include "libgate.h"

#ifndef HAVE_HTONS
static int intel=-1;

static void intel_test(void)
{
  intel = 1;
  intel = *(char *)&intel;
}

unsigned short htons(unsigned short n)
{
  if (intel==-1) intel_test();
  return intel ? chorders(n) : n;
}

unsigned short ntohs(unsigned short n)
{
  if (intel==-1) intel_test();
  return intel ? chorders(n) : n;
}

unsigned long htonl(unsigned long n)
{
  if (intel==-1) intel_test();
  return intel ? chorderl(n) : n;
}

unsigned long ntohl(unsigned long n)
{
  if (intel==-1) intel_test();
  return intel ? chorderl(n) : n;
}

#endif

void msghdr_byteorder(struct message *msghdr)
{
  msghdr->times_read = chorders(htons(msghdr->times_read));
  msghdr->dest_node  = chorders(htons(msghdr->dest_node));
  msghdr->orig_node  = chorders(htons(msghdr->orig_node));
  msghdr->dest_net   = chorders(htons(msghdr->dest_net));
  msghdr->orig_net   = chorders(htons(msghdr->orig_net));
  msghdr->dest_zone  = chorders(htons(msghdr->dest_zone));
  msghdr->orig_zone  = chorders(htons(msghdr->orig_zone));
  msghdr->dest_point = chorders(htons(msghdr->dest_point));
  msghdr->orig_point = chorders(htons(msghdr->orig_point));
  msghdr->cost       = chorders(htons(msghdr->cost));
  msghdr->replyto    = chorders(htons(msghdr->replyto));
  msghdr->attr       = chorders(htons(msghdr->attr));
  msghdr->next_reply = chorders(htons(msghdr->next_reply));
}

int read_msghdr(int h, struct message * msghdr)
{
  if (read(h, msghdr, sizeof(*msghdr)) != sizeof(*msghdr)) return -1;
  msghdr_byteorder(msghdr);
  return sizeof(*msghdr);
}

int write_msghdr(int h, struct message * msghdr)
{
  struct message msg;
  memcpy(&msg, msghdr, sizeof(msg));
  msghdr_byteorder(&msg);
  return write(h, &msg, sizeof(msg)); 
}

void pkthdr_byteorder(struct packet *pkthdr)
{
  pkthdr->OrigNode         = chorders(htons(pkthdr->OrigNode));
  pkthdr->DestNode         = chorders(htons(pkthdr->DestNode));
  pkthdr->year             = chorders(htons(pkthdr->year));
  pkthdr->month            = chorders(htons(pkthdr->month));
  pkthdr->day              = chorders(htons(pkthdr->day));
  pkthdr->hour             = chorders(htons(pkthdr->hour));
  pkthdr->min              = chorders(htons(pkthdr->min));
  pkthdr->sec              = chorders(htons(pkthdr->sec));
  pkthdr->baud             = chorders(htons(pkthdr->baud));
  pkthdr->two              = chorders(htons(pkthdr->two));
  pkthdr->OrigNet          = chorders(htons(pkthdr->OrigNet));
  pkthdr->DestNet          = chorders(htons(pkthdr->DestNet));
  pkthdr->OrigZone         = chorders(htons(pkthdr->OrigZone));
  pkthdr->DestZone         = chorders(htons(pkthdr->DestZone));
  pkthdr->AuxNet           = chorders(htons(pkthdr->AuxNet));
  pkthdr->CWvalidationCopy = chorders(htons(pkthdr->CWvalidationCopy));
  pkthdr->CapabilWord      = chorders(htons(pkthdr->CapabilWord));
  pkthdr->OrigZone_        = chorders(htons(pkthdr->OrigZone_));
  pkthdr->DestZone_        = chorders(htons(pkthdr->DestZone_));
  pkthdr->OrigPoint        = chorders(htons(pkthdr->OrigPoint));
  pkthdr->DestPoint        = chorders(htons(pkthdr->DestPoint));
  pkthdr->ProductData[0]   = chorders(htons(pkthdr->ProductData[0]));
  pkthdr->ProductData[1]   = chorders(htons(pkthdr->ProductData[1]));
}
