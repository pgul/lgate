@ $Id$
@if [reason]==attach
@set Subject="File attach held"
@else
@set Subject="Too large message held"
@endif
@set GateName="FTN->Internet Gate"
@ set GateAddr="2:46/128"
   Hello [ToName]!
@if [reason]==attach
   Here's file attach from Internet to you.
@else
   Here's message from internet to you, but I can't gate it and send %
by default routing because it's too large. :-(  I held it for you.
@endif
Please, don't send binary information via my gate.
Your message header:
===============================
@ifndef FromName
From: [FromAddr]
@else
From: [FromName] <[FromAddr]>
@endif
To:   [ToName] [ToAddr]
Subj: [OldSubject]
@if [reason]==attach
File: [FileName]
@endif
Date: [Date]
Size: [Size] bytes
===============================
Poll [Uplink] for get message body.
                                 Lucky carrier,
                                              Gate Daemon.
