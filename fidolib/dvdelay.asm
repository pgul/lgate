; $Id$
ifdef MODL
.model MODL,c
else
.model small,c
endif
.radix 16

MAXDELAY     equ 8000
TTT          equ 1236

.DATA

dv      db   0ff
win	db   0ff
os2	db   0ff

.CODE

cnt:	dw   ?

old_timer:dd ?
new_timer proc far
        cmp  cs:word ptr cnt, 0
        jz   rett
        dec  cs:word ptr cnt
rett:   jmp  cs:dword ptr [old_timer]
new_timer endp

dvdelay proc
        arg  delay:word
; dv installation check
	mov  ax,2B01
	mov  cx,4445
	mov  dx,5351
	int  21
	inc  al
	mov  ds:byte ptr dv,al
	cmp  al,0
	jnz  nocheck
; win installation check
	mov  ax,1600
	int  2f
	and  al,7f
	mov  ds:byte ptr win,al
	cmp  al,0
	jnz  nocheck
; OS/2 installaton check
	mov  ax,4010
	int  2f
	mov  ds:byte ptr os2,al
	cmp  ax,4010
	jz   nocheck
	mov  ds:byte ptr os2,1
; save timer interrupt
nocheck:mov  ax,3508
	int  21
        mov  cs:word ptr old_timer,bx
        mov  bx,es
        mov  cs:word ptr old_timer+2,bx
; calculate counter cnt=(TIME_CHAS/100h)*[bp+4]/(10*100h)
        mov  ax,delay
        cmp  ax,MAXDELAY
        jc   notover
        mov  ax,MAXDELAY
notover:mov  cx,TTT ; TIME_CHAS/100h
        mul  cx
        mov  cx,10d*100h
        div  cx
        mov  cs:word ptr cnt,ax
; set our timer interrupt
        mov  dx,offset new_timer
        push ds
        push cs
        pop  ds
        mov  ax,2508
        int  21
        pop  ds
; wait
        sti
lp:
; giveup cpu
	int  28
	cmp  ds:byte ptr dv,0
	jz   nodv
	mov  ax,1000
	int  15 ; give up cpu
nodv:   cmp  ds:byte ptr win,0
	jz   nowin
	mov  ax,1680
	int  2f
nowin:	cmp  ds:byte ptr os2,0
	jz   noos2
	mov  ax,1680
	int  2f
noos2:	cmp  cs:word ptr cnt,0
        jnz  lp
; restore timer interrupt
        push ds
        lds  dx,cs:dword ptr old_timer
        mov  ax,2508
        int  21
        pop  ds
; return
        pop  bp
        ret  2
dvdelay endp

        public dvdelay

        end
