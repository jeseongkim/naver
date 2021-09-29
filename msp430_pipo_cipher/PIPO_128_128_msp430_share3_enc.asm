; *****************************************************************************
; File:     Enc_l_m_share3.asm
; Date:     18. Mar 2022
;
;	Encryption Function of PIPO 128-128 Cipher with loop, share 3 masking code
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

			.global    Enc_l_m_share3			; Declare symbol to be exported
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
;	4. mask_refresh 		dst, dstm1, dstm2
;	5. ISW_and				Ra, Ram1, Ram2, Rb, Rbm1, Rbm2, dst, dstm1, dstm2
;	6. ISW_or				Ra, Ram1, Ram2, Rb, Rbm1, Rbm2, dst, dstm1, dstm2
;	7. getmask				idx, dstm1, dstm2, depth_to_mask
;	8. setmask				idx, dstm1, dstm2, depth_to_mask
;	9. masked_round_enc		
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
pushmask	.macro	dst
			call	#rand
			xor.w	R12,		dst				;
			push	R12
			.endm

HO_masking	.macro								;	push 7, ... ,0
; Step 1 firstmasking
			pushmask	R11
			pushmask	R10
			pushmask	R9 
			pushmask	R8 
			pushmask	R7 
			pushmask	R6 
			pushmask	R5 
			pushmask	R4 

			pushmask	R11
			pushmask	R10
			pushmask	R9 
			pushmask	R8 
			pushmask	R7 
			pushmask	R6 
			pushmask	R5 
			pushmask	R4 
			.endm
;===============================================================================

;===============================================================================
HO_unmasking	.macro
			xor.w	@SP+,		R4 				;	SP	+	0 	->	|_________mask1[0]________|
			xor.w	@SP+,		R5 				;	SP	+	2 	->	|_________mask1[1]________|
			xor.w	@SP+,		R6 				;	SP	+	4 	->	|_________mask1[2]________|
			xor.w	@SP+,		R7 				;	SP	+	6 	->	|_________mask1[3]________|
			xor.w	@SP+,		R8 				;	SP	+	8 	->	|_________mask1[4]________|
			xor.w	@SP+,		R9 				;	SP	+	a 	->	|_________mask1[5]________|
			xor.w	@SP+,		R10				;	SP	+	c 	->	|_________mask1[6]________|
			xor.w	@SP+,		R11				;	SP	+	e 	->	|_________mask1[7]________|
			xor.w	@SP+,		R4 				;	SP	+	10	->	|_________mask2[0]________|
			xor.w	@SP+,		R5 				;	SP	+	12	->	|_________mask2[1]________|
			xor.w	@SP+,		R6 				;	SP	+	14	->	|_________mask2[2]________|
			xor.w	@SP+,		R7 				;	SP	+	16	->	|_________mask2[3]________|
			xor.w	@SP+,		R8 				;	SP	+	18	->	|_________mask2[4]________|
			xor.w	@SP+,		R9 				;	SP	+	1a	->	|_________mask2[5]________|
			xor.w	@SP+,		R10				;	SP	+	1c	->	|_________mask2[6]________|
			xor.w	@SP+,		R11				;	SP	+	1e	->	|_________mask2[7]________|
			.endm								;	SP	+	20	->	|_________key_addr________|	<- SP (after HO_unmasking)
												;	SP	+	22	->	|________cipher_addr______|
;===============================================================================

;===============================================================================
mask_refresh	.macro dst, dstm1, dstm2
			myrand								; random -> R12
			xor.w 	R12,		dst				;
			xor.w 	R12,		dstm1			;
			myrand								;
			xor.w 	R12,		dst				;
			xor.w 	R12,		dstm2			;
			myrand								;
			xor.w 	R12,		dstm1			;
			xor.w 	R12,		dstm2			;
			.endm
;===============================================================================

;===============================================================================
ISW_and		.macro	Ra, Ram1, Ram2, Rb, Rbm1, Rbm2, dst, dstm1, dstm2
;	dst + dstm1 + dstm2 = andedData = (Ra + Ram1 + Ram2) & (Rb + Rbm1 + Rbm2)
;	= (Ra & Rb + r1 + r2) + (Ram1 & Rbm1 + Ra & Rbm1 + Ram1 & Rb + r1 + r3) + (Ram2 & Rbm2 + (Ram1 & Rbm2 + Ram2 & Rbm1 + r2) + (Ra & Rbm2 + Ram2 & Rb + r3) )

;1)	dstm1	==	Ram1 & Rbm1 + Ra & Rbm1 + Ram1 & Rb (using dst)
			mov.w	Ram1,		dstm1				; 
			and.w	Rbm1,		dstm1				; dstm1 == Ram1 & Rbm1
			mov.w	Ra  ,		dst  				; 
			and.w	Rbm1,		dst  				; dst == Ra & Rbm1
			xor.w	dst ,		dstm1				; dstm1 == Ram1&Rbm1 + Ra&Rbm1
			mov.w	Ram1,		dst  				; 
			and.w	Rb  ,		dst  				; dst == Ram1 & Rb
			xor.w	dst ,		dstm1				; dstm1 == Ram1&Rbm1 + Ra&Rbm1 + Ram1&Rb

;2)	dstm2	==	Ram2 & Rbm2 + Ram1 & Rbm2 + Ram2 & Rbm1 + Ra & Rbm2 + Ram2 & Rb (using dst)
			mov.w	Ram2,		dstm2				; 
			and.w	Rbm2,		dstm2				; dstm2 == Ram2 & Rbm2
			mov.w	Ram1,		dst  				; 
			and.w	Rbm2,		dst  				; dst == Ram1 & Rbm2
			xor.w	dst ,		dstm2				; dstm1 == Ram1&Rbm1 + Ra&Rbm1
			mov.w	Ram2,		dst  				; 
			and.w	Rbm1,		dst  				; dst == Ram2 & Rbm1
			xor.w	dst ,		dstm2				; dstm1 == Ram1&Rbm1 + Ra&Rbm1 + Ram2&Rbm1
			mov.w	Ra  ,		dst  				; 
			and.w	Rbm2,		dst  				; dst == Ra   & Rbm2
			xor.w	dst ,		dstm2				; dstm1 == Ram1&Rbm1 + Ra&Rbm1 + Ram2&Rbm1 + Ra & Rbm2
			mov.w	Ram2,		dst  				; 
			and.w	Rb  ,		dst  				; dst == Ram2 & Rb  
			xor.w	dst ,		dstm2				; dstm1 == Ram1&Rbm1 + Ra&Rbm1 + Ram2&Rbm1 + Ra & Rbm2 + Ram2&Rb

;3)	dst		== Ra & Rb
			mov.w	Ra ,		dst					; 
			and.w	Rb ,		dst					; 

;4)	r1, r2, r3	== xor ==> (dst, dstm1), (dst, dstm2), (dstm1, dstm2)
			myrand									;
			xor.w	R12 ,		dst  				; 
			xor.w	R12 ,		dstm1				; 
			myrand									;
			xor.w	R12 ,		dst  				; 
			xor.w	R12 ,		dstm2				; 
			myrand									;
			xor.w	R12 ,		dstm1				; 
			xor.w	R12 ,		dstm2				; 
			.endm
;===============================================================================

;===============================================================================
ISW_or		.macro	Ra, Ram1, Ram2, Rb, Rbm1, Rbm2, dst, dstm1, dstm2
;	dst + dstm1 + dstm2 = oredData = (Ra + Ram1 + Ram2) | (Rb + Rbm1 + Rbm2)
;	= (Ra + Ram1 + Ram2) + (Rb + Rbm1 + Rbm2) + (Ra + Ram1 + Ram2) & (Rb + Rbm1 + Rbm2)

			ISW_and	Ra, Ram1, Ram2, Rb, Rbm1, Rbm2, dst, dstm1, dstm2
			xor.w	 Ra,		dst				;
			xor.w	 Rb,		dst				;
			xor.w	 Ram1,		dstm1			;
			xor.w	 Rbm1,		dstm1			;
			xor.w	 Ram2,		dstm2			;
			xor.w	 Rbm2,		dstm2			;
			.endm
;===============================================================================

;===============================================================================
getmask		.macro	idx, dstm1, dstm2, depth_to_mask
			mov.w	(depth_to_mask + 2*idx)(SP),			dstm1	
			mov.w	(depth_to_mask + 2*idx + 0x10)(SP),		dstm2	
			.endm

setmask		.macro	idx, dstm1, dstm2, depth_to_mask
			mov.w	dstm1,	(depth_to_mask + 2*idx)(SP)										
			mov.w	dstm2,	(depth_to_mask + 2*idx + 0x10)(SP)							
			.endm
;===============================================================================


;-------------------------------------------------------------------------------
;macro for S5_1
; Note that : Params(ISW_and)	Ra, Ram1, Ram2, Rb, Rbm1, Rbm2, dst, dstm1, dstm2

andequal	.macro	idx1, idx2, idx3, dst, dstm1, dstm2, depth_to_mask

;Example) X[7] ^= X[5] & X[6]
;Params :	idx1	|idx2	|idx3	|dst	|dstm1	|dstm2	|depth_to_mask	
;			7		|5		|6		|R4 	|R5 	|R6 	|8				

			push	(R4 + idx1)									;	Store Ridx1
			getmask	idx2, R13, R14, (depth_to_mask + 2)			;	R13, R14	->	Ram1, Ram2
			getmask	idx3, R15, (R4 + idx1), (depth_to_mask + 2)	;	R15, Ridx1	->	Rbm1, Rbm2		loss exist. if using Ridx1 as dst, then xor.w @SP+, dst possible instead (pop Ridx1 + xor.w dst, Ridx1)
			mask_refresh (R4 + idx2), R13, R14
			ISW_and	(R4 + idx2), R13, R14, (R4 + idx3), R15, (R4 + idx1), dst, dstm1, dstm2
			pop		(R4 + idx1)									;
			setmask	idx2, R13, R14, depth_to_mask
			xor.w	dst,		(R4 + idx1)						;
			xor.w	dstm1, (depth_to_mask + 2*idx1)(SP)			;	andedmask1 into stack_mask1[idx1]
			xor.w	dstm2, (depth_to_mask + 2*idx1 + 0x10)(SP)	;	andedmask2 into stack_mask2[idx1]
			.endm


orequal	 	.macro	idx1, idx2, idx3, dst, dstm1, dstm2, depth_to_mask
			push	(R4 + idx1)									;	Store Ridx1
			getmask	idx2, R13, R14, (depth_to_mask + 2)			;	R13, R14	->	Ram1, Ram2
			getmask	idx3, R15, (R4 + idx1), (depth_to_mask + 2)	;	R15, Ridx1	->	Rbm1, Rbm2
			mask_refresh (R4 + idx2), R13, R14
			ISW_or	(R4 + idx2), R13, R14, (R4 + idx3), R15, (R4 + idx1), dst, dstm1, dstm2
			pop		(R4 + idx1)									;
			setmask	idx2, R13, R14, depth_to_mask
			xor.w	dst,		(R4 + idx1)						;
			xor.w	dstm1, (depth_to_mask + 2*idx1)(SP)			;	oredmask1 into stack_mask1[idx1]
			xor.w	dstm2, (depth_to_mask + 2*idx1 + 0x10)(SP)	;	oredmask2 into stack_mask2[idx2]
			.endm

xorequal	.macro	idx1, idx2, depth_to_mask					; example) X[6] ^= X[4] --> idx1, idx2, depth_to_mask = 6,4, 8
			xor.w	 (R4 + idx2),	(R4 + idx1)					;
			xor.w	 (depth_to_mask + idx2*2)(SP),	(depth_to_mask + idx1*2)(SP);
			xor.w	 (0x10 + depth_to_mask + idx2*2)(SP),	(0x10 + depth_to_mask + idx1*2)(SP);
			.endm
;===============================================================================
;-------------------------------------------------------------------------------
; S5_1
mask_S5_1	.macro
			push	R4							;
			push	R5							;
			push	R6							;
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[2]__________|	|	R4 	:	gen for dst							
;	SP	+	2 	->	|___________X[1]__________|	|	R5 	:	gen for dstm1						
;	SP	+	4 	->	|___________X[0]__________|	|	R6 	:	gen for dstm2						
;	SP	+	6 	->	|_________loop_idx________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|_________mask1[0]________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|_________mask1[1]________|	|	R9 	:	X[5]							
;	SP	+	c 	->	|_________mask1[2]________|	|	R10	:	X[6]							
;	SP	+	e 	->	|_________mask1[3]________|	|	R11	:	X[7]							
;	SP	+	10	->	|_________mask1[4]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[5]________|	|	R13	:	gen							
;	SP	+	14	->	|_________mask1[6]________|	|	R14	:	gen							
;	SP	+	16	->	|_________mask1[7]________|	|	R15	:	gen							
;	SP	+	18	->	|_________mask2[0]________|	|								
;	SP	+	1a	->	|_________mask2[1]________|	|								
;	SP	+	1c	->	|_________mask2[2]________|	|								
;	SP	+	1e	->	|_________mask2[3]________|	|								
;	SP	+	20	->	|_________mask2[4]________|	|								
;	SP	+	22	->	|_________mask2[5]________|	|								
;	SP	+	22	->	|_________mask2[6]________|	|								
;	SP	+	20	->	|_________mask2[7]________|	|								
;	SP	+	22	->	|_________key_addr________|	|								
;	SP	+	22	->	|________cipher_addr______|	|								
;-------------------------------------------------------------------------------
; 1) X[7] ^= X[5] & X[6]
			andequal 7,5,6,R4,R5,R6,8

; 2) X[4] ^= X[5] & X[7]
			andequal 4,5,7,R4,R5,R6,8

; 3) X[5] ^= X[4] | X[3]
			orequal 5,4,3,R4,R5,R6,8

; 4) X[6] ^= X[4]
			xorequal	6,4,8

; 5) X[3] ^= X[7]
			xorequal	3,7,8

; 6) X[7] ^= X[3] & X[6]
			andequal 7,3,6,R4,R5,R6,8
			.endm
;===============================================================================

;===============================================================================
;-------------------------------------------------------------------------------
; S3
mask_S3		.macro
			pop		R6							;
			pop		R5							;
			pop		R4							;
			push	R7							;
			push	R8							;
			push	R9							;
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[5]__________|	|	R4 	:	X[0]					
;	SP	+	2 	->	|___________X[4]__________|	|	R5 	:	X[1]							
;	SP	+	4 	->	|___________X[3]__________|	|	R6 	:	X[2]							
;	SP	+	6 	->	|_________loop_idx________|	|	R7 	:	gen for dst							
;	SP	+	8 	->	|_________mask1[0]________|	|	R8 	:	gen for dstm1						
;	SP	+	a 	->	|_________mask1[1]________|	|	R9 	:	gen for dstm2						
;	SP	+	c 	->	|_________mask1[2]________|	|	R10	:	X[6]							
;	SP	+	e 	->	|_________mask1[3]________|	|	R11	:	X[7]							
;	SP	+	10	->	|_________mask1[4]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[5]________|	|	R13	:	gen							
;	SP	+	14	->	|_________mask1[6]________|	|	R14	:	gen							
;	SP	+	16	->	|_________mask1[7]________|	|	R15	:	gen							
;	SP	+	18	->	|_________mask2[0]________|	|								
;	SP	+	1a	->	|_________mask2[1]________|	|								
;	SP	+	1c	->	|_________mask2[2]________|	|								
;	SP	+	1e	->	|_________mask2[3]________|	|								
;	SP	+	20	->	|_________mask2[4]________|	|								
;	SP	+	22	->	|_________mask2[5]________|	|								
;	SP	+	22	->	|_________mask2[6]________|	|								
;	SP	+	20	->	|_________mask2[7]________|	|								
;	SP	+	22	->	|_________key_addr________|	|								
;	SP	+	22	->	|________cipher_addr______|	|								
;-------------------------------------------------------------------------------
; 1) X[0] ^= X[2] & X[1]
			andequal 0,2,1,R7,R8,R9,8

; 2) X[1] ^= X[2] | X[0]
			orequal 1,2,0,R7,R8,R9,8

; 3) X[1] = ~X[1]
			inv.w	R5								;

; 4) X[2] ^= X[0] | X[1]
			orequal 2,0,1,R7,R8,R9,8
			.endm
;===============================================================================

;===============================================================================
;-------------------------------------------------------------------------------
; Extend xor
mask_extend	.macro
			pop		R9							;
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[4]__________|	|	R4 	:	X[0]					
;	SP	+	2 	->	|___________X[3]__________|	|	R5 	:	X[1]							
;	SP	+	4 	->	|_________loop_idx________|	|	R6 	:	X[2]							
;	SP	+	6 	->	|_________mask1[0]________|	|	R7 	:	gen							
;	SP	+	8 	->	|_________mask1[1]________|	|	R8 	:	gen							
;	SP	+	a 	->	|_________mask1[2]________|	|	R9 	:	X[5]							
;	SP	+	c 	->	|_________mask1[3]________|	|	R10	:	X[6]							
;	SP	+	e 	->	|_________mask1[4]________|	|	R11	:	X[7]							
;	SP	+	10	->	|_________mask1[5]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[6]________|	|	R13	:	gen							
;	SP	+	14	->	|_________mask1[7]________|	|	R14	:	gen							
;	SP	+	16	->	|_________mask2[0]________|	|	R15	:	gen							
;	SP	+	18	->	|_________mask2[1]________|	|								
;	SP	+	1a	->	|_________mask2[2]________|	|								
;	SP	+	1c	->	|_________mask2[3]________|	|								
;	SP	+	1e	->	|_________mask2[4]________|	|								
;	SP	+	20	->	|_________mask2[5]________|	|								
;	SP	+	22	->	|_________mask2[6]________|	|								
;	SP	+	22	->	|_________mask2[7]________|	|								
;	SP	+	20	->	|_________key_addr________|	|								
;	SP	+	22	->	|________cipher_addr______|	|								
;-------------------------------------------------------------------------------
; 1) X[7] ^= X[2]
			xorequal	7,2,6
; 2) X[6] ^= X[1]
			xorequal	6,1,6
; 3) X[5] ^= X[0]
			xorequal	5,0,6
			.endm
;===============================================================================

;-------------------------------------------------------------------------------
;macro for S5_2

andequal1	.macro	Ra, Rma, Rmma, Rb, Rmb, Rmmb, Rc, Rmc, Rmmc
;	X[a] ^= X[b]&X[c]
			push	Rmma										;	Store Rmma
			push	Rma											;	Store Rma
			push	Ra											;	Store Ra
			mask_refresh Rc, Rmc, Rmmc							;	Refresh second operand
			ISW_and	Rb, Rmb, Rmmb, Rc, Rmc, Rmmc, Ra, Rma, Rmma
			xor.w	@SP+,		Ra								;
			xor.w	@SP+,		Rma								;
			xor.w	@SP+,		Rmma							;
			.endm

orequal1	.macro	Ra, Rma, Rmma, Rb, Rmb, Rmmb, Rc, Rmc, Rmmc
			push	Rmma										;	Store Rmma
			push	Rma											;	Store Rma
			push	Ra											;	Store Ra
			mask_refresh Rc, Rmc, Rmmc							;	Refresh second operand
			ISW_or	Rb, Rmb, Rmmb, Rc, Rmc, Rmmc, Ra, Rma, Rmma
			xor.w	@SP+,		Ra								;
			xor.w	@SP+,		Rma								;
			xor.w	@SP+,		Rmma							;
			.endm
;===============================================================================
;-------------------------------------------------------------------------------
; S5_2	X[7] = T[0], X[6] = T[1], X[5] = T[2]
mask_S5_2	.macro
			pop		R8							;
			pop		R7							;
			push	R11							;
			push	R10							;
			push	R9							;
			push	R6							;
			push	R5							;
			push	R4							;
			getmask	5,	R4,	R5,	0xe 
			getmask	6,	R6,	R13,0xe 
			getmask	7,	R14,R15,0xe 
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[0]__________|	|	R4 	:	Tm1[2]					
;	SP	+	2 	->	|___________X[1]__________|	|	R5 	:	Tm2[2]							
;	SP	+	4 	->	|___________X[2]__________|	|	R6 	:	Tm1[1]							
;	SP	+	6 	->	|___________X[5]__________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|___________X[6]__________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|___________X[7]__________|	|	R9 	:	T[2] = X[5]							
;	SP	+	c 	->	|_________loop_idx________|	|	R10	:	T[1] = X[6]							
;	SP	+	e 	->	|_________mask1[0]________|	|	R11	:	T[0] = X[7]							
;	SP	+	10	->	|_________mask1[1]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[2]________|	|	R13	:	Tm2[1]							
;	SP	+	14	->	|_________mask1[3]________|	|	R14	:	Tm1[0]							
;	SP	+	16	->	|_________mask1[4]________|	|	R15	:	Tm2[0]							
;	SP	+	18	->	|_________mask1[5]________|	|								
;	SP	+	1a	->	|_________mask1[6]________|	|	T[0]_fam 	:	R11, R14, R15					
;	SP	+	1c	->	|_________mask1[7]________|	|	T[1]_fam	:	R10, R6,  R13					
;	SP	+	1e	->	|_________mask2[0]________|	|	T[2]_fam	:	R9,  R4,  R5					
;	SP	+	20	->	|_________mask2[1]________|	|								
;	SP	+	22	->	|_________mask2[2]________|	|								
;	SP	+	24	->	|_________mask2[3]________|	|								
;	SP	+	26	->	|_________mask2[4]________|	|								
;	SP	+	28	->	|_________mask2[5]________|	|								
;	SP	+	2a	->	|_________mask2[6]________|	|								
;	SP	+	2c	->	|_________mask2[7]________|	|								
;-------------------------------------------------------------------------------
; Default depth : 0xe
; 1) X[4] ^= X[3] & T[0]
			push	R4											;
			push	R5											;
			push	R6											;
			push	R13											;

			getmask	4,R4,R5,0x16								; getmask X4
			getmask	3,R6,R13,0x16								; getmask X3
			andequal1	R8, R4, R5, R7, R6, R13, R11, R14, R15
			setmask	4,R4,R5,0x16								; setmask X4

			pop		R13											;
			pop		R6											;
			pop		R5											;
			pop		R4											;

; 2) X[4] ^= T[1]
			push	R4											;	loss exist. R4 R5 are already mask of X4, And for next step, push R14, R15 is more efficient.
			push	R5											;
			getmask	4,R4,R5,0x12								; getmask X4
			xor.w	R10,	R8									;
			xor.w	R6 ,	R4									;
			xor.w	R13,	R5									;
			setmask 4,R4,R5,0x12
			pop		R5
			pop		R4

; 3) T[2] ^= X[4] | T[1]
			push	R14											;
			push	R15											;

			getmask	4,R14,R15,0x12								; getmask X4
			orequal1	R9, R4, R5, R8, R14, R15, R10, R6, R13

			pop		R15											;
			pop		R14											;

; 4) T[0] ^= T[2]
			xor.w	R9 ,	R11									;
			xor.w	R4 ,	R14									;
			xor.w	R5 ,	R15									;

; 5) T[1] ^= X[3]
			push	R4											;
			push	R5											;
			getmask	3, R4, R5, 0x12
			xor.w	R7 ,	R10									;
			xor.w	R4 ,	R6									;
			xor.w	R5 ,	R13									;
			pop		R5
			pop		R4

; 6) T[2] |= T[1]
			push	R15											;
			push	R14											;
			push	R7											;
			mask_refresh R10, R6, R13							;	Refresh second operand
			ISW_or	R9, R4, R5, R10, R6, R13, R7, R14, R15
			mov.w	R7 ,		R9									;
			mov.w	R14,		R4									;
			mov.w	R15,		R5									;
			pop		R7											;
			pop		R14											;
			pop		R15											;

; 7) X[3] ^= X[4] | T[0]
			push	R4											;
			push	R5											;
			push	R6											;
			push	R13											;

			getmask	3,R4,R5,0x16								; getmask X3
			getmask	4,R6,R13,0x16								; getmask X4
			orequal1	R7, R4, R5, R8, R6, R13, R11, R14, R15
			setmask	3,R4,R5,0x16								; setmask X4

			pop		R13											;
			pop		R6											;
			pop		R5											;
			pop		R4											;
			

; 8) T[2] ^= T[0]
			xor.w	R11,	R9									;
			xor.w	R14,	R4									;
			xor.w	R15,	R5									;
			.endm
;===============================================================================

;===============================================================================
; Truncated XOR 								;
mask_trun	.macro
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[0]__________|	|	R4 	:	Tm1[2]					
;	SP	+	2 	->	|___________X[1]__________|	|	R5 	:	Tm2[2]							
;	SP	+	4 	->	|___________X[2]__________|	|	R6 	:	Tm1[1]							
;	SP	+	6 	->	|___________X[5]__________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|___________X[6]__________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|___________X[7]__________|	|	R9 	:	T[2]							
;	SP	+	c 	->	|_________loop_idx________|	|	R10	:	T[1]							
;	SP	+	e 	->	|_________mask1[0]________|	|	R11	:	T[0]							
;	SP	+	10	->	|_________mask1[1]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[2]________|	|	R13	:	Tm2[1]							
;	SP	+	14	->	|_________mask1[3]________|	|	R14	:	Tm1[0]							
;	SP	+	16	->	|_________mask1[4]________|	|	R15	:	Tm2[0]							
;	SP	+	18	->	|_________mask1[5]________|	|								
;	SP	+	1a	->	|_________mask1[6]________|	|						
;	SP	+	1c	->	|_________mask1[7]________|	|						
;	SP	+	1e	->	|_________mask2[0]________|	|						
;	SP	+	20	->	|_________mask2[1]________|	|								
;	SP	+	22	->	|_________mask2[2]________|	|								
;	SP	+	24	->	|_________mask2[3]________|	|								
;	SP	+	26	->	|_________mask2[4]________|	|								
;	SP	+	28	->	|_________mask2[5]________|	|								
;	SP	+	2a	->	|_________mask2[6]________|	|								
;	SP	+	2c	->	|_________mask2[7]________|	|		
; X[2] ^= T[0]
			xor.w	R11,		0x4(SP)			;
			xor.w	0x12(SP),	R14				;	R14 -> mask1[2]
			xor.w	0x22(SP),	R15				;	R15 -> mask2[2]

; X[1] ^= T[2]
			xor.w	R9,			0x2(SP)			;
			xor.w	0x10(SP),	R4				;	R4 -> mask1[1]
			xor.w	0x20(SP),	R5				;	R5 -> mask2[1]

; X[0] ^= T[1]
			xor.w	R10,		0x0(SP)			;
			xor.w	0xe(SP),	R6				; loss exist. Since X[0] doesn't rotate, xor into stack is more efficient.
			xor.w	0x1e(SP),	R13				; loss exist. Since X[0] doesn't rotate, xor into stack is more efficient.
			.endm 								; end macro
;===============================================================================

;===============================================================================
mask_slayer	.macro
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|_________loop_idx________|	|	R4 	:	X[0]							
;	SP	+	2 	->	|_________mask1[0]________|	|	R5 	:	X[1]							
;	SP	+	4 	->	|_________mask1[1]________|	|	R6 	:	X[2]							
;	SP	+	6 	->	|_________mask1[2]________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|_________mask1[3]________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|_________mask1[4]________|	|	R9 	:	X[5]							
;	SP	+	c 	->	|_________mask1[5]________|	|	R10	:	X[6]							
;	SP	+	e 	->	|_________mask1[6]________|	|	R11	:	X[7]							
;	SP	+	10	->	|_________mask1[7]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask2[0]________|	|	R13	:	gen							
;	SP	+	14	->	|_________mask2[1]________|	|	R14	:	gen							
;	SP	+	16	->	|_________mask2[2]________|	|	R15	:	gen							
;	SP	+	18	->	|_________mask2[3]________|	|								
;	SP	+	1a	->	|_________mask2[4]________|	|								
;	SP	+	1c	->	|_________mask2[5]________|	|								
;	SP	+	1e	->	|_________mask2[6]________|	|								
;	SP	+	20	->	|_________mask2[7]________|	|								
;	SP	+	22	->	|_________key_addr________|	|								
;	SP	+	22	->	|________cipher_addr______|	|								
			mask_S5_1
			mask_S3
			mask_extend
			mask_S5_2
			mask_trun
			.endm
;===============================================================================


;===============================================================================
mask_player	.macro
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[0]__________|	|	R4 	:	mask1[1]					
;	SP	+	2 	->	|___________X[1]__________|	|	R5 	:	mask2[1]							
;	SP	+	4 	->	|___________X[2]__________|	|	R6 	:	mask1[0]							
;	SP	+	6 	->	|___________X[5]__________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|___________X[6]__________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|___________X[7]__________|	|	R9 	:	gen							
;	SP	+	c 	->	|_________loop_idx________|	|	R10	:	gen							
;	SP	+	e 	->	|_________mask1[0]________|	|	R11	:	gen							
;	SP	+	10	->	|_________mask1[1]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[2]________|	|	R13	:	mask2[0]							
;	SP	+	14	->	|_________mask1[3]________|	|	R14	:	mask1[2]							
;	SP	+	16	->	|_________mask1[4]________|	|	R15	:	mask2[2]							
;	SP	+	18	->	|_________mask1[5]________|	|								
;	SP	+	1a	->	|_________mask1[6]________|	|						
;	SP	+	1c	->	|_________mask1[7]________|	|					
;	SP	+	1e	->	|_________mask2[0]________|	|				
;	SP	+	20	->	|_________mask2[1]________|	|								
;	SP	+	22	->	|_________mask2[2]________|	|								
;	SP	+	24	->	|_________mask2[3]________|	|								
;	SP	+	26	->	|_________mask2[4]________|	|								
;	SP	+	28	->	|_________mask2[5]________|	|								
;	SP	+	2a	->	|_________mask2[6]________|	|								
;	SP	+	2c	->	|_________mask2[7]________|	|								
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
; p-layer of mask12[0,1,2,3]
			getmask	3, R9, R10, 0xe
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[0]__________|	|	R4 	:	mask1[1]					
;	SP	+	2 	->	|___________X[1]__________|	|	R5 	:	mask2[1]							
;	SP	+	4 	->	|___________X[2]__________|	|	R6 	:	mask1[0]							
;	SP	+	6 	->	|___________X[5]__________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|___________X[6]__________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|___________X[7]__________|	|	R9 	:	mask1[3]							
;	SP	+	c 	->	|_________loop_idx________|	|	R10	:	mask2[3]							
;	SP	+	e 	->	|_________mask1[0]________|	|	R11	:	gen							
;	SP	+	10	->	|_________mask1[1]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[2]________|	|	R13	:	mask2[0]							
;	SP	+	14	->	|_________mask1[3]________|	|	R14	:	mask1[2]							
;	SP	+	16	->	|_________mask1[4]________|	|	R15	:	mask2[2]							
;	SP	+	18	->	|_________mask1[5]________|	|								
;	SP	+	1a	->	|_________mask1[6]________|	|						
;	SP	+	1c	->	|_________mask1[7]________|	|					
;	SP	+	1e	->	|_________mask2[0]________|	|				
;	SP	+	20	->	|_________mask2[1]________|	|								
;	SP	+	22	->	|_________mask2[2]________|	|								
;	SP	+	24	->	|_________mask2[3]________|	|								
;	SP	+	26	->	|_________mask2[4]________|	|								
;	SP	+	28	->	|_________mask2[5]________|	|								
;	SP	+	2a	->	|_________mask2[6]________|	|								
;	SP	+	2c	->	|_________mask2[7]________|	|								

; 1) X[1] << 15
			bit.w #1, R4					; 0x1 and the value of R9 are logically ANDed. The results affects only the status bits.
											; So, if LSB is 1, carry bit becomes 1. Else, 0.
			rrc		R4						; Rotate Right through carry.

			bit.w #1, R5
			rrc		R5			
; 2) X[2] << 8
			swpb	R14						; Swap Byte

			swpb	R15						; Swap Byte
; 3) X[3] << 2
			rla.w	R9						; Rotate Left Arithmetically
			adc.w	R9						; Add carry to destination
			rla.w	R9
			adc.w	R9

			rla.w	R10						; Rotate Left Arithmetically
			adc.w	R10						; Add carry to destination
			rla.w	R10
			adc.w	R10
; store mask into stack
			setmask	0, R6, R13, 0xe			;
			setmask	1, R4, R5, 0xe			;
			setmask	2, R14, R15, 0xe			;
			setmask	3, R9, R10, 0xe			;
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
; p-layer of mask12[4,5,6,7]
			getmask	4, R6, R13, 0xe
			getmask	5, R4, R5, 0xe
			getmask	6, R14, R15, 0xe
			getmask	7, R9, R10, 0xe
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|___________X[0]__________|	|	R4 	:	mask1[1 + 4]					
;	SP	+	2 	->	|___________X[1]__________|	|	R5 	:	mask2[1 + 4]							
;	SP	+	4 	->	|___________X[2]__________|	|	R6 	:	mask1[0 + 4]							
;	SP	+	6 	->	|___________X[5]__________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|___________X[6]__________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|___________X[7]__________|	|	R9 	:	mask1[3 + 4]							
;	SP	+	c 	->	|_________loop_idx________|	|	R10	:	mask2[3 + 4]							
;	SP	+	e 	->	|_________mask1[0]________|	|	R11	:	gen							
;	SP	+	10	->	|_________mask1[1]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask1[2]________|	|	R13	:	mask2[0 + 4]							
;	SP	+	14	->	|_________mask1[3]________|	|	R14	:	mask1[2 + 4]							
;	SP	+	16	->	|_________mask1[4]________|	|	R15	:	mask2[2 + 4]							
;	SP	+	18	->	|_________mask1[5]________|	|								
;	SP	+	1a	->	|_________mask1[6]________|	|						
;	SP	+	1c	->	|_________mask1[7]________|	|					
;	SP	+	1e	->	|_________mask2[0]________|	|				
;	SP	+	20	->	|_________mask2[1]________|	|								
;	SP	+	22	->	|_________mask2[2]________|	|								
;	SP	+	24	->	|_________mask2[3]________|	|								
;	SP	+	26	->	|_________mask2[4]________|	|								
;	SP	+	28	->	|_________mask2[5]________|	|								
;	SP	+	2a	->	|_________mask2[6]________|	|								
;	SP	+	2c	->	|_________mask2[7]________|	|								
;-------------------------------------------------------------------------------
; 4) X[4] << 10
			swpb	R6
			rla.w	R6
			adc.w	R6
			rla.w	R6
			adc.w	R6

			swpb	R13
			rla.w	R13
			adc.w	R13
			rla.w	R13
			adc.w	R13

; 5) X[5] << 7
			swpb	R4
			bit.w #1, R4
			rrc		R4

			swpb	R5
			bit.w #1, R5
			rrc		R5

; 6) X[6] << 9
			swpb	R14
			rla.w	R14
			adc.w	R14

			swpb	R15
			rla.w	R15
			adc.w	R15

; 7) X[7] << 1
			rla.w	R9
			adc.w	R9

			rla.w	R10
			adc.w	R10

; store mask into stack
			setmask	4, R6, R13, 0xe			;
			setmask	5, R4, R5, 0xe			;
			setmask	6, R14, R15, 0xe			;
			setmask	7, R9, R10, 0xe			;
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
; p-layer of data
			pop		R4											;
			pop		R5											;
			pop		R6											;
			pop		R9											;
			pop		R10											;
			pop		R11											;
;	inner state of stack						|	inner state of register
;	SP	+	0 	->	|_________loop_idx________|	|	R4 	:	X[0]					
;	SP	+	2 	->	|_________mask1[0]________|	|	R5 	:	X[1]							
;	SP	+	4 	->	|_________mask1[1]________|	|	R6 	:	X[2]							
;	SP	+	6 	->	|_________mask1[2]________|	|	R7 	:	X[3]							
;	SP	+	8 	->	|_________mask1[3]________|	|	R8 	:	X[4]							
;	SP	+	a 	->	|_________mask1[4]________|	|	R9 	:	X[5]							
;	SP	+	c 	->	|_________mask1[5]________|	|	R10	:	X[6]							
;	SP	+	e 	->	|_________mask1[6]________|	|	R11	:	X[7]							
;	SP	+	10	->	|_________mask1[7]________|	|	R12	:	gen							
;	SP	+	12	->	|_________mask2[0]________|	|	R13	:	gen							
;	SP	+	14	->	|_________mask2[1]________|	|	R14	:	gen							
;	SP	+	16	->	|_________mask2[2]________|	|	R15	:	gen							
;	SP	+	18	->	|_________mask2[3]________|	|								
;	SP	+	1a	->	|_________mask2[4]________|	|						
;	SP	+	1c	->	|_________mask2[5]________|	|					
;	SP	+	1e	->	|_________mask2[6]________|	|				
;	SP	+	20	->	|_________mask2[7]________|	|								
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
;===============================================================================

;===============================================================================
Key_xor		.macro	loop_idx_reg
			mov.w	0x20(SP),	R13				; Pop key address,	clock : 3
			xor.w	@R13+,		R4				;	SP	+	0 	->	|_________mask1[0]________|
			xor.w	@R13+,		R5				;	SP	+	2 	->	|_________mask1[1]________|
			xor.w	@R13+,		R6				;	SP	+	4 	->	|_________mask1[2]________|
			xor.w	@R13+,		R7				;	SP	+	6 	->	|_________mask1[3]________|
			xor.w	@R13+,		R8				;	SP	+	8 	->	|_________mask1[4]________|
			xor.w	@R13+,		R9				;	SP	+	a 	->	|_________mask1[5]________|
			xor.w	@R13+,		R10				;	SP	+	c 	->	|_________mask1[6]________|
			xor.w	@R13,		R11				;	SP	+	e 	->	|_________mask1[7]________|
			xor.w 	loop_idx_reg, R4			;	SP	+	10	->	|_________mask2[0]________|
			.endm								;	SP	+	12	->	|_________mask2[1]________|
												;	SP	+	14	->	|_________mask2[2]________|
												;	SP	+	16	->	|_________mask2[3]________|
												;	SP	+	18	->	|_________mask2[4]________|
												;	SP	+	1a	->	|_________mask2[5]________|
												;	SP	+	1c	->	|_________mask2[6]________|
												;	SP	+	1e	->	|_________mask2[7]________|
												;	SP	+	20	->	|_________key_addr________|
;===============================================================================

;===============================================================================
masked_round_enc	.macro
			mask_slayer
			mask_player
			pop		R15							; Pop loop idx
			Key_xor	R15
			.endm
;===============================================================================

; --------- Function Start -----------------------------------------------------
Enc_l_m_share3:    .asmfunc
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
			masked_round_enc					; s -> p -> pop loop_idx -> key xor
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
