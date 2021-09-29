; *****************************************************************************
; File:     Enc_l_nm.asm
; Date:     14. Aug 2020
;
;	Encryption Function of PIPO 128-128 Cipher with loop, no masking code
;	update : 1) mov.w 0x2(R12), R4 : clock cycle = 3 --> mov.w @R12+, R4 : clock  cycle : 2
;
; *****************************************************************************

      .cdecls C,NOLIST,"msp430.h"       ; Processor specific definitions

       
;============================================================================
;	Encryption Function
;	Input : uint16_t P[], uint16_t K[], uint16_t C[]
;	Output: Store Cipher text to the address C[].
;============================================================================
      .global    Enc_l_nm               ; Declare symbol to be exported
      .sect ".text"                     ; Code is relocatable
Enc_l_nm:    .asmfunc
;------------------------------------------------------------------------------
; Initializing Register
			mov.w	 @R12+,		R4				; R(i+4) = P[i] = X[i]
			mov.w	 @R12+,		R5				;
			mov.w	 @R12+,		R6				;
			mov.w	 @R12+,		R7				;
			mov.w	 @R12+,		R8				;
			mov.w	 @R12+,		R9				;
			mov.w	 @R12+,		R10				;
			mov.w	 @R12,		R11				;
			sub.w	 #14,		R12				;

; Whitening Key XOR
			xor.w	 @R13+,		R4				;
			xor.w	 @R13+,		R5				;
			xor.w	 @R13+,		R6				;
			xor.w	 @R13+,		R7				;
			xor.w	 @R13+,		R8				;
			xor.w	 @R13+,		R9				;
			xor.w	 @R13+,		R10				;
			xor.w	 @R13,		R11				;
			sub.w	 #14,		R13				;


; Push Ciphertext address
			push	 R14						; Push Ciphertext address
;------------------------------------------------------------------------------
; Loop Starting
			clr	 	 R15						; R15 (loop index) become 0

Roundloop	inc.w 	 R15
			push	 R13						; Push Keytext address
			push 	 R15						; Push loop index

;------------------------------------------------------------------------------
; S_layer
;------------------------------------------------------------------------------
; S5_1
; 1) X[7] ^= X[5] & X[6]
			mov.w	R9,  R12					; R12 = X[5]
			and.w	R10, R12					; R12 = X[5] & X[6]
			xor.w	R12, R11					; R11 = X[7] --> X[7] ^= X[5] & X[6]
; 2) X[4] ^= X[5] & X[7]
			mov.w	R9,  R12					; R12 = X[5]
			and.w	R11, R12					; R12 = X[5] & X[7]
			xor.w	R12, R8						; R8  = X[4] --> X[4] ^= X[5] & X[7]
; 3) X[5] ^= X[4] | X[3]
			mov.w	R8,  R12					; R8  = X[4]
			bis.w	R7,  R12					; R12 = X[4] | X[3]
			xor.w	R12, R9 					; R9  = X[5] --> X[5] ^= X[4] | X[3]
; 4) X[6] ^= X[4]
			xor.w	R8,  R10					; R10 = X[6] --> X[6] ^= X[4]
; 5) X[3] ^= X[7]
			xor.w	R11, R7 					; R11 = X[3] --> X[3] ^= X[7]
; 6) X[7] ^= X[3] & X[6]
			mov.w	R7,  R12					; R12 = X[3]
			and.w	R10, R12					; R12 = X[3] & X[6]
			xor.w	R12, R11 					; R11 = X[7] --> X[7] ^= X[3] & X[6]
;------------------------------------------------------------------------------
; S3
; 1) X[0] ^= X[2] & X[1]
			mov.w	R6,  R12					; R12 = X[2]
			and.w	R5,  R12					; R12 = X[2] & X[1]
			xor.w	R12, R4						; R4  = X[0] --> X[0] ^= X[2] & X[1]
; 2) X[1] ^= X[2] | X[0]
			mov.w	R6,  R12					; R12 = X[2]
			bis.w	R4,  R12					; R12 = X[2] | X[0]
			xor.w	R12, R5						; R5  = X[1] --> X[1] ^= X[2] | X[0]
; 3) X[1] = ~X[1]
			inv.w	R5							; R9  = X[1] --> X[1] = ~X[1]
; 4) X[2] ^= X[0] | X[1]
			mov.w	R4,  R12					; R12 = X[0]
			bis.w	R5,  R12					; R12 = X[0] | X[1]
			xor.w	R12, R6 					; R6  = X[2] --> X[2] ^= X[0] | X[1]
;------------------------------------------------------------------------------
; Extend XOR
; 1) X[7] ^= X[2]
			xor.w	R6,  R11					; R11 = X[7] --> X[7] ^= X[2]
; 2) X[6] ^= X[1]
			xor.w	R5,  R10					; R10 = X[6] --> X[6] ^= X[1]
; 3) X[5] ^= X[0]
			xor.w	R4,  R9 					; R9  = X[5] --> X[5] ^= X[0]

;------------------------------------------------------------------------------
; Just use register 13,14,15 as T[0],T[1],T[2].
;------------------------------------------------------------------------------
; S5_2
; Define T[0] = R15 = X[7], T[1] = R14 = X[6], T[2] = R13 = X[5]
			mov.w	R11, R15
			mov.w	R10, R14
			mov.w	R9,  R13
; 1) X[4] ^= X[3] & T[0]
			mov.w	R7,  R12					; R12 = X[3]
			and.w	R15, R12					; R12 = X[3] & T[0]
			xor.w	R12, R8 					; R8  = X[4] --> X[4] ^= X[3] & T[0]
; 2) X[4] ^= T[1]
			xor.w	R14, R8						; R12 = X[4] --> X[4] ^= T[1]
; 3) T[2] ^= X[4] | T[1]
			mov.w	R8,  R12					; R12 = X[4]
			bis.w	R14, R12					; R12 = X[4] | T[1]
			xor.w	R12, R13					; R13 = T[2] --> T[2] ^= X[4] | T[1]
; 4) T[0] ^= T[2]
			xor.w	R13, R15					; R13 = T[2] --> T[0] ^= T[2]
; 5) T[1] ^= X[3]
			xor.w	R7,  R14					; R14 = T[1] --> T[1] ^= X[3]
; 6) T[2] |= T[1]
			bis.w	R14, R13					; R13 = T[2] --> T[2] |= T[1]
; 7) X[3] ^= X[4] | T[0]
			mov.w	R8,  R12					; R12 = X[4]
			bis.w	R15, R12					; R12 = X[4] | T[0]
			xor.w	R12, R7 					; R7  = X[3] --> X[3] ^= X[4] | T[0]
; 8) T[2] ^= T[0]
			xor.w	R15, R13					; R13 = T[2] --> T[2] ^= T[0]
;------------------------------------------------------------------------------
; Truncated XOR
; X[2] ^= T[0]
			xor.w	R15, R6						; R6  = X[2] --> X[2] ^= T[0]
; X[1] ^= T[2]
			xor.w	R13, R5						; R5  = X[1] --> X[2] ^= T[0]
; X[0] ^= T[1]
			xor.w	R14, R4						; R4  = X[0] --> X[0] ^= T[1]
;------------------------------------------------------------------------------
; P_layer
;------------------------------------------------------------------------------
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
;------------------------------------------------------------------------------
; Key XOR
			pop		R15							; round index
			pop		R13							; key address

			xor.w	 R15, 		R4				;
			xor.w	 @R13+,		R4				;
			xor.w	 @R13+,		R5				;
			xor.w	 @R13+,		R6				;
			xor.w	 @R13+,		R7				;
			xor.w	 @R13+,		R8				;
			xor.w	 @R13+,		R9				;
			xor.w	 @R13+,		R10				;
			xor.w	 @R13,		R11				;
			sub.w	 #14,		R13				;

;------------------------------------------------------------------------------
; If loop End?
			cmp.b 	#19,R15						; If R15(loop index) == 19, Zero bit set. Else, Zero bit = 0
			jnz		Roundloop


;------------------------------------------------------------------------------
; Store X[0], ... , X[4], X[5], X[6], X[7]
;------------------------------------------------------------------------------
			pop		R12							; pop Ciphertext address
			mov.w	R4,   0x0(R12)
			mov.w	R5,   0x2(R12)
			mov.w	R6,   0x4(R12)
			mov.w	R7,   0x6(R12)
			mov.w	R8,   0x8(R12)
			mov.w	R9,   0xa(R12)
			mov.w	R10,  0xc(R12)
			mov.w	R11,  0xe(R12)
;------------------------------------------------------------------------------

   .if ($defined(__MSP430_HAS_MSP430XV2_CPU__) | $defined(__MSP430_HAS_MSP430X_CPU__))
        reta
   .else
        ret
   .endif
         .endasmfunc

        .end
