@ Send carbon copy to gatemaster?
@Set CcMaster=Yes
@Set GateName=FTN->uucp gate
@Set Subject=Your message rejected
@if [Reason]==Binary
@Set Str=you can't send binary information via this gate
@endif
@if [Reason]==Destination
@Set Str=you can't send message to [ToName]
@endif
@if [Reason]==NoAddress
@if [ToMaster]==Yes
@Set DontSend=Yes
@else
@Set Str=you didn't specify valid TO address
@endif
@endif
@if [Reason]==Twit
@Set Str=you can't use this gate
@Set Hdr=" header"
@endif
@if [Reason]==Size
@Set Str=it's too large
@Set Hdr=" header"
@endif
@if [Reason]==External
@Set Str=i can't send message
@endif
@if [Reason]==Attach
@Set Str=you can't send fileattaches via gate
@endif
@if not [CcMaster]==Yes
@if [ToMaster]==Yes
@Set DontSend=Yes
@endif
@endif
@ifndef DontSend
@if [ToMaster]==Yes
@set Hdr=" header"
@endif
   Hello [FromName]!
   
Your message was rejected because [Str].
Original message[hdr] follows:
========================================================================
From: [FromName]  [FromAddr]
To:   [ToName]  [ToAddr]
@ifdef OldSubject
Subj: [OldSubject]
@endif
Date: [Date]
@if [Reason]==Size
Size: [Size] bytes
@endif
========================================================================
@ifndef hdr
@Text
========================================================================
@else
\[message body suppressed]
@endif

Send your proposes and bug reports to [MastName] [MastAddr].

                        Lucky carrier,
                                Gate Daemon.
                                [LocalDate] [LocalTime]
@endif   not defined [DontSend]
