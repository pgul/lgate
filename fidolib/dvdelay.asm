ifdef MODL
.model MODL,c
else
.model small,c
endif
.radix 16

MAXDELAY     equ 8000
TTT          equ 1236

.DATA

dv      db   ?

.CODE

nakop:  dw   ?

old_timer:dd ?
new_timer proc far
        cmp  cs:word ptr nakop,0
        jz   rett
        dec  cs:word ptr nakop
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
; сохраняем прерывание таймера
	mov  ax,3508
	int  21
        mov  cs:word ptr old_timer,bx
        mov  bx,es
        mov  cs:word ptr old_timer+2,bx
; считаем накопитель nakop=(TIME_CHAS/100h)*[bp+4]/(10*100h)
        mov  ax,delay
        cmp  ax,MAXDELAY
        jc   notover
        mov  ax,MAXDELAY
notover:mov  cx,TTT ; TIME_CHAS/100h
        mul  cx
        mov  cx,10d*100h
        div  cx
        mov  cs:word ptr nakop,ax
; устанавливаем свое прерывание таймера
        mov  dx,offset new_timer
        push ds
        push cs
        pop  ds
        mov  ax,2508
        int  21
        pop  ds
; ждем
        sti
lp:
; отдаем процессор
	int  28
	cmp  ds:byte ptr dv,0
	jz   nodv
	mov  ax,1000
	int  15 ; give up cpu
nodv:   cmp  cs:word ptr nakop,0
        jnz  lp
; восстанавливаем прерывание таймера
        push ds
        lds  dx,cs:dword ptr old_timer
        mov  ax,2508
        int  21
        pop  ds
; завершаемся
        pop  bp
        ret  2
dvdelay endp

        public dvdelay

        end
