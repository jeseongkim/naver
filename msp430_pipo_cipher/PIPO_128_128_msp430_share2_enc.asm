; *****************************************************************************
; File:     Enc_l_m.asm
; Date:     15. Mar 2022
;
;	Encryption Function of PIPO 128-128 Cipher with loop, masking code
;	
;	###### Modification log ######
;	
; *****************************************************************************

;============================================================================
;	Encryption Function with masking
;	Input : uint16_t P[], uint16_t K[], uint16_t C[]
;	Output: Store Cipher text to the address C[].
;============================================================================

      .cdecls C,NOLIST,"msp430.h"       ; Processor specific definitions
      									; Include C header without converted assembly code

;-------------------------------------------------------------------------------
;	Declaration
			.ref	rand                        ; Std C function, store random 16bit into R12 using R13,14,15

;			.bss	mask, 16					; Reserve uninitialized space

			.global    Enc_l_m					; Declare symbol to be exported
			.sect ".text"						; Code is relocatable
;-------------------------------------------------------------------------------

;-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
;-*-*-*-*-*-*-*-*-*-										*-*-*-*-*-*-*-*-*-*-
;-*-*-*-*-*-*-*-*-*-		macro 		section				*-*-*-*-*-*-*-*-*-*-
;-*-*-*-*-*-*-*-*-*-										*-*-*-*-*-*-*-*-*-*-
;-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-
;	macro List			|	params
;	1. myrand				
;	2. HO_masking			
;	3. HO_unmasking			
;	4. mask_refresh 		dst, dstm
;	5. ISW_and				Ra, Ram, Rb, Rbm, dst, dstm
;	6. ISW_or				Ra, Ram, Rb, Rbm, dst, dstm
;	6. masked_round_enc		
;	--	mask_slayer						
;	--	mask_player						
;	--	Key_xor				loop_idx_reg		
			
;===============================================================================
myrand		.macro
			push	R13							; clock : 3
			push	R14							;
			push	R15							;
			call	#rand						;
			pop		R15							; clock : 2
			pop		R14							;
			pop		R13							;
			.endm
;===============================================================================

;===============================================================================
HO_masking	.macro								;	push X[7], ... ,X[0]
			call	#rand						; R12 = random, R13,14,15 change
			xor.w	R12,		R11				;
			push	R12

			call	#rand						;
			xor.w	R12,		R10				;
			push	R12

			call	#rand						;
			xor.w	R12,		R9 				;
			push	R12

			call	#rand						;
			xor.w	R12,		R8 				;
			push	R12

			call	#rand						;
			xor.w	R12,		R7 				;
			push	R12

			call	#rand						;
			xor.w	R12,		R6 				;
			push	R12

			call	#rand						;
			xor.w	R12,		R5 				;
			push	R12

			call	#rand						;
			xor.w	R12,		R4 				;
			push	R12
			.endm
;===============================================================================

;===============================================================================
HO_unmasking	.macro
			xor.w	@SP+,		R4 				;	SP	+	0 	->	|_________mask[0]________|
			xor.w	@SP+,		R5 				;	SP	+	2 	->	|_________mask[1]________|
			xor.w	@SP+,		R6 				;	SP	+	4 	->	|_________mask[2]________|
			xor.w	@SP+,		R7 				;	SP	+	6 	->	|_________mask[3]________|
			xor.w	@SP+,		R8 				;	SP	+	8 	->	|_________mask[4]________|
			xor.w	@SP+,		R9 				;	SP	+	a 	->	|_________mask[5]________|
			xor.w	@SP+,		R10				;	SP	+	c 	->	|_________mask[6]________|
			xor.w	@SP+,		R11				;	SP	+	e 	->	|_________mask[7]________|
			.endm								;	SP	+	10	->	|________key_addr________|	<- SP (after HO_unmasking)
												;	SP	+	12	->	|_______cipher_addr______|
;===============================================================================

;===============================================================================
mask_refresh	.macro dst, dstm
			myrand								; random -> R12
			xor.w 	R12,		dst				; 
			xor.w 	R12,		dstm			; 
			.endm
;===============================================================================

;===============================================================================
ISW_and		.macro	Ra, Ram, Rb, Rbm, dst, dstm
;	dst		== Ra & Rb + r
			myrand								; random -> R12
			mov.w	 Ra,		dst				; 
			and.w	 Rb,		dst				; 
			xor.w	 R12,		dst				; dst == Ra & Rb + r

;	dstm	== Ra & Rbm + Ram & Rb + Ram & Rbm + r
			mov.w	 Ra,		dstm			; 
			and.w	 Rbm,		dstm			; 
			xor.w	 dstm,		R12				; R12 == Ra & Rbm + r

			mov.w	 Ram,		dstm			; 
			and.w	 Rb,		dstm			; 
			xor.w	 dstm,		R12				; R12 == (Ra & Rbm + r) + Ram & Rb

			mov.w	 Ram,		dstm			; 
			and.w	 Rbm,		dstm			; 
			xor.w	 R12,		dstm			; dstm == (Ra & Rbm + r + Ram & Rb) + Ram & Rbm
			.endm
;===============================================================================

;===============================================================================
ISW_or		.macro	Ra, Ram, Rb, Rbm, dst, dstm
;	dst 	== Ra + Rb + (Ra & Rb + r)
;	dstm	== Ram + Rbm + (Ra & Rbm + Ram & Rb + Ram & Rbm + r)

			ISW_and	Ra, Ram, Rb, Rbm, dst, dstm	;

			xor.w	 Ra,		dst				;
			xor.w	 Rb,		dst				;

			xor.w	 Ram,		dstm			;
			xor.w	 Rbm,		dstm			;
			.endm
;===============================================================================

;============================================================================
mask_slayer	.macro
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|________loop_idx________|	|	R4 	:	X[0]	
;	SP	+	2 	->	|_________mask[0]________|	|	R5 	:	X[1]	
;	SP	+	4 	->	|_________mask[1]________|	|	R6 	:	X[2]	
;	SP	+	6 	->	|_________mask[2]________|	|	R7 	:	X[3]	
;	SP	+	8 	->	|_________mask[3]________|	|	R8 	:	X[4]
;	SP	+	10	->	|_________mask[4]________|	|	R9 	:	X[5]
;	SP	+	12	->	|_________mask[5]________|	|	R10	:	X[6]
;	SP	+	14	->	|_________mask[6]________|	|	R11	:	X[7]
;	SP	+	16	->	|_________mask[7]________|	|	R12	: general
;	SP	+	18	->	|________key_addr________|	|	R13	: general
;	SP	+	20	->	|_______cipher_add_______|	|	R14	: general
;	SP	+	22	->	|________________________|	|	R15	: general
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
; S5_1
			push	R4							;
			push	R5							;
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[1]_________|	|	R4 	: general for dst	
;	SP	+	2 	->	|___________X[0]_________|	|	R5 	: general for dstm	
;	SP	+	4 	->	|________loop_idx________|	|	R6 	:	X[2]	
;	SP	+	6 	->	|_________mask[0]________|	|	R7 	:	X[3]	
;	SP	+	8 	->	|_________mask[1]________|	|	R8 	:	X[4]
;	SP	+	10	->	|_________mask[2]________|	|	R9 	:	X[5]
;	SP	+	12	->	|_________mask[3]________|	|	R10	:	X[6]
;	SP	+	14	->	|_________mask[4]________|	|	R11	:	X[7]
;	SP	+	16	->	|_________mask[5]________|	|	R12	: for random
;	SP	+	18	->	|_________mask[6]________|	|	R13	: mask leftside
;	SP	+	20	->	|_________mask[7]________|	|	R14	: mask rightside 0
;	SP	+	22	->								|	R15	: mask rightside 1
;-------------------------------------------------------------------------------
;macro for S5_1
getmask		.macro	idx1, idx2, idx3, dst1, dst2, dst3
			mov.w	(6 + idx1*2)(SP),	dst1			;
			mov.w	(6 + idx2*2)(SP),	dst2			;
			mov.w	(6 + idx3*2)(SP),	dst3			;
			.endm

setmask		.macro	src1, src2, Xi1, Xi2
			mov.w	src1,				(6 + Xi1*2)(SP)	; 
			mov.w	src2,				(6 + Xi2*2)(SP)	; 
			.endm

andequal	.macro	idx1, idx2, idx3, dst, dstm
;Example) X[7] ^= X[5] & X[6]
;Params : 7,5,6
			getmask	idx1,idx2,idx3, R13, R14, R15
			mask_refresh (R4 + idx2), R14				; loss exist. Becasue rand change (R13,14,R15), first call rand and getmask is better.
			ISW_and (R4 + idx2), R14, (R4 + idx3), R15, dst, dstm
			xor.w	dst,		(R4 + idx1)			;
			xor.w	dstm,		R13					;
			setmask R13, R14, idx1, idx2
			.endm

orequal		.macro	idx1, idx2, idx3, dst, dstm
			getmask	idx1,idx2,idx3, R13, R14, R15
			mask_refresh (R4 + idx2), R14				; loss exist. Becasue rand change (R13,14,R15), first call rand and getmask is better.
			ISW_or	(R4 + idx2), R14, (R4 + idx3), R15, dst, dstm
			xor.w	dst,		(R4 + idx1)			;
			xor.w	dstm,		R13					;
			setmask R13, R14, idx1, idx2
			.endm

xorequal	.macro	idx1, idx2									; example) X[6] ^= X[4] --> idx1, idx2= 6,4
			xor.w	 (R4 + idx2),	(R4 + idx1)					;
			xor.w	 (6 + idx2*2)(SP),	(6 + idx1*2)(SP);
			.endm
;-------------------------------------------------------------------------------
; 1) X[7] ^= X[5] & X[6]
			andequal 7,5,6,R4,R5

; 2) X[4] ^= X[5] & X[7]
			andequal 4,5,7,R4,R5

; 3) X[5] ^= X[4] | X[3]
			orequal	5,4,3,R4,R5

; 4) X[6] ^= X[4]
			xorequal	6,4

; 5) X[3] ^= X[7]
			xorequal	3,7

; 6) X[7] ^= X[3] & X[6]
			andequal	7,3,6,R4,R5

;-------------------------------------------------------------------------------
; S3
			pop		R5							;
			pop		R4							;
			push	R7							;
			push	R8							;
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[4]_________|	|	R4 	:	X[0]
;	SP	+	2 	->	|___________X[3]_________|	|	R5 	:	X[1]
;	SP	+	4 	->	|________loop_idx________|	|	R6 	:	X[2]	
;	SP	+	6 	->	|_________mask[0]________|	|	R7 	: general for dst	
;	SP	+	8 	->	|_________mask[1]________|	|	R8 	: general for dstm
;	SP	+	10	->	|_________mask[2]________|	|	R9 	:	X[5]
;	SP	+	12	->	|_________mask[3]________|	|	R10	:	X[6]
;	SP	+	14	->	|_________mask[4]________|	|	R11	:	X[7]
;	SP	+	16	->	|_________mask[5]________|	|	R12	: for random
;	SP	+	18	->	|_________mask[6]________|	|	R13	: mask leftside
;	SP	+	20	->	|_________mask[7]________|	|	R14	: mask rightside 0
;	SP	+	22	->								|	R15	: mask rightside 1
;-------------------------------------------------------------------------------
; 1) X[0] ^= X[2] & X[1]
			andequal 0,2,1,R7,R8

; 2) X[1] ^= X[2] | X[0]
			orequal	1,2,0,R7,R8

; 3) X[1] = ~X[1]
			inv.w	R5								;

; 4) X[2] ^= X[0] | X[1]
			orequal	2,0,1,R7,R8

;-------------------------------------------------------------------------------
; Extend xor
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[4]_________|	|	R4 	:	X[0]
;	SP	+	2 	->	|___________X[3]_________|	|	R5 	:	X[1]
;	SP	+	4 	->	|________loop_idx________|	|	R6 	:	X[2]	
;	SP	+	6 	->	|_________mask[0]________|	|	R7 	: general for dst	
;	SP	+	8 	->	|_________mask[1]________|	|	R8 	: general for dstm
;	SP	+	10	->	|_________mask[2]________|	|	R9 	:	X[5]
;	SP	+	12	->	|_________mask[3]________|	|	R10	:	X[6]
;	SP	+	14	->	|_________mask[4]________|	|	R11	:	X[7]
;	SP	+	16	->	|_________mask[5]________|	|	R12	: for random
;	SP	+	18	->	|_________mask[6]________|	|	R13	: mask leftside
;	SP	+	20	->	|_________mask[7]________|	|	R14	: mask rightside 0
;	SP	+	22	->								|	R15	: mask rightside 1
;-------------------------------------------------------------------------------
; 1) X[7] ^= X[2]
			xorequal	7,2
; 2) X[6] ^= X[1]
			xorequal	6,1
; 3) X[5] ^= X[0]
			xorequal	5,0

;-------------------------------------------------------------------------------
; S5_2	X[7] = T[0], X[6] = T[1], X[5] = T[2]
			pop		R8							;
			pop		R7							;
			push	R11							;
			push	R10							;
			push	R9							;
			push	R6							;
			push	R5							;
			push	R4							;
			mov.w	0x14(SP),	R4				; 
			mov.w	0x16(SP),	R5				; 
			mov.w	0x18(SP),	R13				; 
			mov.w	0x1a(SP),	R14				; 
			mov.w	0x1c(SP),	R15				; 
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[0]_________|	|	R4 	:	mask[3]
;	SP	+	2 	->	|___________X[1]_________|	|	R5 	:	mask[4]
;	SP	+	4 	->	|___________X[2]_________|	|	R6 	:	general for dst
;	SP	+	6 	->	|___________X[5]_________|	|	R7 	:	X[3]
;	SP	+	8 	->	|___________X[6]_________|	|	R8 	:	X[4]
;	SP	+	a	->	|___________X[7]_________|	|	R9 	:	T[2] = X[5]
;	SP	+	c	->	|________loop_idx________|	|	R10	:	T[1] = X[6]
;	SP	+	e	->	|_________mask[0]________|	|	R11	:	T[0] = X[7]
;	SP	+	10	->	|_________mask[1]________|	|	R12	: for random
;	SP	+	12	->	|_________mask[2]________|	|	R13	:	Tm[2] = mask[5]	
;	SP	+	14	->	|_________mask[3]________|	|	R14	:	Tm[1] = mask[6]	
;	SP	+	16	->	|_________mask[4]________|	|	R15	:	Tm[0] = mask[7]	
;	SP	+	18	->	|_________mask[5]________|
;	SP	+	1a	->	|_________mask[6]________|
;	SP	+	1c	->	|_________mask[7]________|
;-------------------------------------------------------------------------------
;	macro for S5_2
andequal2	.macro	R1, Rm1, R2, Rm2, R3, Rm3, dst, fordstm
;Example) X[4] ^= X[3] & T[0]
;Params : R8, R5, R7, R4, R11, R15, R6, R14
			push	fordstm						;
			mask_refresh R2, Rm2
			ISW_and	R2, Rm2, R3, Rm3, dst, fordstm
			xor.w	 dst,		R1				;
			xor.w	 fordstm,	Rm1				;
			pop		fordstm						;
			.endm

orequal2	.macro	R1, Rm1, R2, Rm2, R3, Rm3, dst, fordstm
			push	fordstm						;
			mask_refresh R2, Rm2
			ISW_or	R2, Rm2, R3, Rm3, dst, fordstm
			xor.w	 dst,		R1				;
			xor.w	 fordstm,	Rm1				;
			pop		fordstm						;
			.endm
;-------------------------------------------------------------------------------
; 1) X[4] ^= X[3] & T[0]
			andequal2 R8, R5, R7, R4, R11, R15, R6, R14
; 2) X[4] ^= T[1]
			xor.w	R10,		R8				;
			xor.w	R14,		R5				;
; 3) T[2] ^= X[4] | T[1]
			orequal2	R9, R13, R8, R5, R10, R14, R6, R7
; 4) T[0] ^= T[2]
			xor.w	R9 ,		R11				;
			xor.w	R13,		R15				;
; 5) T[1] ^= X[3]
			xor.w	R7 ,		R10				;
			xor.w	R4 ,		R14				;
; 6) T[2] |= T[1]
			push	R7
			mask_refresh R10, R14
			ISW_or	R10, R14, R9, R13, R6, R7
			mov.w	R6 ,		R9				;
			mov.w	R7 ,		R13				;
			pop		R7
; 7) X[3] ^= X[4] | T[0]
			orequal2	R7, R4, R8, R5, R11, R15, R6, R9
; 8) T[2] ^= T[0]
			xor.w	R11,		R9				;
			xor.w	R15,		R13				;

; Truncated XOR 								; loss exist. Since p-layer only use 8 register(exactly 7 execpt for X[0]), xor.w into Stack may be unefficient.
; X[2] ^= T[0]
			xor.w	R11,		0x4(SP)			;
			xor.w	0x12(SP),	R15				;

; X[1] ^= T[2]
			xor.w	R9,			0x2(SP)			;
			xor.w	0x10(SP),	R13				;

; X[0] ^= T[1]
			xor.w	R10,		0x0(SP)			;
			xor.w	0xe(SP),	R14				;
			.endm 								; end macro
;============================================================================

;============================================================================
mask_player	.macro
;	Initial State of stack and register when this macro was started.				
;	inner state of stack						|	inner state of register				
;	SP	+	0 	->	|___________X[0]_________|	|	R4 	:	mask[3]				
;	SP	+	2 	->	|___________X[1]_________|	|	R5 	:	mask[4]				
;	SP	+	4 	->	|___________X[2]_________|	|	R6 	:	general					
;	SP	+	6 	->	|___________X[5]_________|	|	R7 	:	X[3]				
;	SP	+	8 	->	|___________X[6]_________|	|	R8 	:	X[4]				
;	SP	+	a	->	|___________X[7]_________|	|	R9 	:	general					
;	SP	+	c	->	|________loop_idx________|	|	R10	:	general					
;	SP	+	e	->	|_________mask[0]________|	|	R11	:	general					
;	SP	+	10	->	|_________mask[1]________|	|	R12	:	general							
;	SP	+	12	->	|_________mask[2]________|	|	R13	:	mask[1]				
;	SP	+	14	->	|_________mask[3]________|	|	R14	:	mask[0]				
;	SP	+	16	->	|_________mask[4]________|	|	R15	:	mask[2]				
;	SP	+	18	->	|_________mask[5]________|									
;	SP	+	1a	->	|_________mask[6]________|									
;	SP	+	1c	->	|_________mask[7]________|									
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
;	mask p-layer
			mov.w	0x18(SP),	R9				;
			mov.w	0x1a(SP),	R10				;
			mov.w	0x1c(SP),	R11				;
;	inner state of stack						|	inner state of register				
;	SP	+	0 	->	|___________X[0]_________|	|	R4 	:	mask[3]				
;	SP	+	2 	->	|___________X[1]_________|	|	R5 	:	mask[4]				
;	SP	+	4 	->	|___________X[2]_________|	|	R6 	:	general					
;	SP	+	6 	->	|___________X[5]_________|	|	R7 	:	X[3]				
;	SP	+	8 	->	|___________X[6]_________|	|	R8 	:	X[4]				
;	SP	+	a	->	|___________X[7]_________|	|	R9 	:	mask[5]					
;	SP	+	c	->	|________loop_idx________|	|	R10	:	mask[6]					
;	SP	+	e	->	|_________mask[0]________|	|	R11	:	mask[7]					
;	SP	+	10	->	|_________mask[1]________|	|	R12	:	general							
;	SP	+	12	->	|_________mask[2]________|	|	R13	:	mask[1]				
;	SP	+	14	->	|_________mask[3]________|	|	R14	:	mask[0]				
;	SP	+	16	->	|_________mask[4]________|	|	R15	:	mask[2]				
;	SP	+	18	->	|_________mask[5]________|									
;	SP	+	1a	->	|_________mask[6]________|									
;	SP	+	1c	->	|_________mask[7]________|									
;-------------------------------------------------------------------------------
; 1) X[1] << 15
			bit.w #1, R13					; 0x1 and the value of R9 are logically ANDed. The results affects only the status bits.
											; So, if LSB is 1, carry bit becomes 1. Else, 0.
			rrc		R13						; Rotate Right through carry.
; 2) X[2] << 8
			swpb	R15						; Swap Byte
; 3) X[3] << 2
			rla.w	R4						; Rotate Left Arithmetically
			adc.w	R4						; Add carry to destination
			rla.w	R4
			adc.w	R4
; 4) X[4] << 10
			swpb	R5
			rla.w	R5
			adc.w	R5
			rla.w	R5
			adc.w	R5
; 5) X[5] << 7
			swpb	R9
			bit.w #1, R9
			rrc		R9

; 6) X[6] << 9
			swpb	R10
			rla.w	R10
			adc.w	R10

; 7) X[7] << 1
			rla.w	R11
			adc.w	R11
;	Push mask
			mov.w	R14,	0xe (SP)				;
			mov.w	R13,	0x10(SP)				;
			mov.w	R15,	0x12(SP)				;
			mov.w	R4 ,	0x14(SP)				;
			mov.w	R5 ,	0x16(SP)				;
			mov.w	R9 ,	0x18(SP)				;
			mov.w	R10,	0x1a(SP)				;
			mov.w	R11,	0x1c(SP)				;
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
;	data p-layer
			pop		R4 							;
			pop		R5 							;
			pop		R6 							;
			pop		R9 							;
			pop		R10 						;
			pop		R11 						;
;	inner state of stack						|	inner state of register	
;	SP	+	0 	->	|________loop_idx________|	|	R4 	:	X[0]
;	SP	+	2 	->	|_________mask[0]________|	|	R5 	:	X[1]
;	SP	+	4 	->	|_________mask[1]________|	|	R6 	:	X[2]
;	SP	+	6 	->	|_________mask[2]________|	|	R7 	:	X[3]
;	SP	+	8 	->	|_________mask[3]________|	|	R8 	:	X[4]
;	SP	+	a	->	|_________mask[4]________|	|	R9 	:	X[5]
;	SP	+	c	->	|_________mask[5]________|	|	R10	:	X[6]
;	SP	+	e	->	|_________mask[6]________|	|	R11	:	X[7]
;	SP	+	10	->	|_________mask[7]________|	|	R12	:	general
;	SP	+	12	->	|________key_addr________|	|	R13	:	mask[1]
;	SP	+	14	->	|_______cipher_addr______|	|	R14	:	mask[0]
;	SP	+	16	->	|________________________|	|	R15	:	mask[2]
;-------------------------------------------------------------------------------
; 1) X[1] << 15
			bit.w #1, R5					; 0x1 and the value of R9 are logically ANDed. The results affects only the status bits.
											; So, if LSB is 1, carry bit becomes 1. Else, 0.
			rrc		R5						; Rotate Right through carry.
; 2) X[2] << 8
			swpb	R6						; Swap Byte
; 3) X[3] << 2
			rla.w	R7						; Rotate Left Arithmetically
			adc.w	R7						; Add carry to destination
			rla.w	R7
			adc.w	R7
; 4) X[4] << 10
			swpb	R8
			rla.w	R8
			adc.w	R8
			rla.w	R8
			adc.w	R8
; 5) X[5] << 7
			swpb	R9
			bit.w #1, R9
			rrc		R9

; 6) X[6] << 9
			swpb	R10
			rla.w	R10
			adc.w	R10

; 7) X[7] << 1
			rla.w	R11
			adc.w	R11
			.endm
;============================================================================

;============================================================================
Key_xor		.macro	loop_idx_reg
			mov.w	0x10(SP),	R13				; Pop key address,	clock : 3
			xor.w	@R13+,		R4				;	SP	+	0 	->	|_________mask[0]________|
			xor.w	@R13+,		R5				;	SP	+	2 	->	|_________mask[1]________|
			xor.w	@R13+,		R6				;	SP	+	4 	->	|_________mask[2]________|
			xor.w	@R13+,		R7				;	SP	+	6 	->	|_________mask[3]________|
			xor.w	@R13+,		R8				;	SP	+	8 	->	|_________mask[4]________|
			xor.w	@R13+,		R9				;	SP	+	a 	->	|_________mask[5]________|
			xor.w	@R13+,		R10				;	SP	+	c 	->	|_________mask[6]________|
			xor.w	@R13,		R11				;	SP	+	e 	->	|_________mask[7]________|
			xor.w 	loop_idx_reg, R4			;	SP	+	10	->	|________key_addr________|
			.endm								;	SP	+	12	->	|_______cipher_addr______|
;============================================================================

;============================================================================
masked_round_enc	.macro
			mask_slayer
			mask_player
			pop		R15							; Pop loop idx
			Key_xor	R15
			.endm
;============================================================================



; --------- Function Start -----------------------------------------------------
Enc_l_m:    .asmfunc
; Initializing Register
			mov.w	@R12+,		R4				; R(i+4) = P[i] = X[i], clock : 2
			mov.w	@R12+,		R5				;	clock : 2
			mov.w	@R12+,		R6				;
			mov.w	@R12+,		R7				;
			mov.w	@R12+,		R8				;
			mov.w	@R12+,		R9				;
			mov.w	@R12+,		R10				;
			mov.w	@R12,		R11				;

; Push Ciphertext address, key address
			push	R14							; Push Ciphertext address, clock : 3
			push	R13							; Push Key address

; HO_masking
			HO_masking

; First Key_xor
			mov.w	#0,			R15				; loop idx
			Key_xor	R15

; Loop for round function
Roundloop
			add.w	#1,			R15				; loop idx +
			push	R15							; Push loop idx
			masked_round_enc
			cmp.b 	#19,R15						; If R15(loop index) == 19, Zero bit set. Else, Zero bit = 0
			jnz		Roundloop					; Jump if not zerobit set

; HO_unmasking
			HO_unmasking

; Store X[7], ... , X[0] into ciphertext_address
			pop		R12							; Pop key_address
			pop		R12							; Pop ciphertext_address
			mov.w	R4,   		0x0(R12)		;
			mov.w	R5,   		0x2(R12)		;
			mov.w	R6,   		0x4(R12)		;
			mov.w	R7,   		0x6(R12)		;
			mov.w	R8,   		0x8(R12)		;
			mov.w	R9,   		0xa(R12)		;
			mov.w	R10,  		0xc(R12)		;
			mov.w	R11,  		0xe(R12)		;

; function end
   .if ($defined(__MSP430_HAS_MSP430XV2_CPU__) | $defined(__MSP430_HAS_MSP430X_CPU__))
        reta
   .else
        ret
   .endif
         .endasmfunc

        .end

