@ $Id$
@if not "[ToMaster]"=="yes"
@set Multipart=Yes
This is a Mime-encapsulated message

--[boundary]
Content-Type: text/plain; charset=us-ascii

@endif
@if [Reason]==BadAddress
@set str=address [To] is invalid
@endif
@if [Reason]==ITwit
@set str="access denied"
@endif
@if [Reason]==ITwit-To
@set str="access denied"
@endif
@if [Reason]==ITwit-Via
@set str="access denied"
@endif
@if [Reason]==ITwit-From
@set str="access denied"
@endif
@if [Reason]==TooManyHops
@set str="too many hops [Hops] ([MaxHops] max)"
@endif
@if [Reason]==FileAttach
@set str="send fileattaches via this gate denied"
@endif
@if [Reason]==TooLarge
@set str="message too large"
@endif
@if [Reason]==External
@set str="can't send messageto [To]"
@endif
@set Subject=Returned mail: [str]
Unrecoverable error: 
[str]
Therefore I must return message to you.
Original message follows:
@if [multipart]==yes

--[boundary]
Content-Type: message/rfc822

@header

@text

--[boundary]--
@else
-----
@header

-- \[message body suppressed] --
@endif
