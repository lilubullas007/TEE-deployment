/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the low-level binary field bit shifting functions.
 *
 * @ingroup bn
 */

#include "low/relic_fp_low.h"

//.arch atmega128

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

.text

.global fp_sqrn_low

.macro PROLOGUE
	.irp i, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31
		push 	\i
	.endr
.endm

.macro EPILOGUE
	.irp i, 31, 30, 29, 28, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 0
		pop 	\i
	.endr
	ret
.endm

fp_sqrn_low:
	PROLOGUE

	movw r28,r22
	movw r26,r24

	clr r24
	clr r25
	clr r22
	movw r8,r24
	movw r10,r24
	movw r12,r24
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	ldd r2,Y+0
	ldd r3,Y+0+1
	ldd r4,Y+0+2
	ldd r5,Y+0+3
	mul r2,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r2,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r2,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r2,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r3,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r5,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;0
	st X+,r9 ;1
	st X+,r10 ;2
	st X+,r11 ;3

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+0
	ldd r3,Y+0+1
	ldd r4,Y+0+2
	ldd r5,Y+0+3
	ldd r6,Y+4
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+4+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+4+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+4+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;4
	st X+,r9 ;5
	st X+,r10 ;6
	st X+,r11 ;7

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+0
	ldd r3,Y+0+1
	ldd r4,Y+0+2
	ldd r5,Y+0+3
	ldd r6,Y+8
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+8+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+8+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+8+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	ldd r2,Y+4
	ldd r3,Y+4+1
	ldd r4,Y+4+2
	ldd r5,Y+4+3
	mul r2,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r2,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r2,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r2,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r3,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r5,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;8
	st X+,r9 ;9
	st X+,r10 ;10
	st X+,r11 ;11

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+0
	ldd r3,Y+0+1
	ldd r4,Y+0+2
	ldd r5,Y+0+3
	ldd r6,Y+12
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+12+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+12+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+12+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	ldd r2,Y+4
	ldd r3,Y+4+1
	ldd r4,Y+4+2
	ldd r5,Y+4+3
	ldd r6,Y+8
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+8+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+8+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+8+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;12
	st X+,r9 ;13
	st X+,r10 ;14
	st X+,r11 ;15

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+0
	ldd r3,Y+0+1
	ldd r4,Y+0+2
	ldd r5,Y+0+3
	ldd r6,Y+16
	mul r6,r2
	add r8,r0
    adc r9,r1
    adc r16,r25
    add r8,r0
    adc r9,r1
    adc r16,r25
    mul r6,r3
    add r9,r0
    adc r10,r1
    adc r17,r25
    add r9,r0
    adc r10,r1
    adc r17,r25
    mul r6,r4
    add r10,r0
    adc r11,r1
    adc r18,r25
    add r10,r0
    adc r11,r1
    adc r18,r25
    mul r6,r5
    add r11,r0
    adc r12,r1
    adc r19,r25
    add r11,r0
    adc r12,r1
    adc r19,r25
    ldd r6,Y+16+1
    mul r6,r2
    add r9,r0
    adc r10,r1
    adc r17,r25
    add r9,r0
    adc r10,r1
    adc r17,r25
    mul r6,r3
    add r10,r0
    adc r11,r1
    adc r18,r25
    add r10,r0
    adc r11,r1
    adc r18,r25
    mul r6,r4
    add r11,r0
    adc r12,r1
    adc r19,r25
    add r11,r0
    adc r12,r1
    adc r19,r25
    mul r6,r5
    add r12,r0
    adc r13,r1
    adc r20,r25
    add r12,r0
    adc r13,r1
    adc r20,r25
    ldd r6,Y+16+2
    mul r6,r2
    add r10,r0
    adc r11,r1
    adc r18,r25
    add r10,r0
    adc r11,r1
    adc r18,r25
    mul r6,r3
    add r11,r0
    adc r12,r1
    adc r19,r25
    add r11,r0
    adc r12,r1
    adc r19,r25
    mul r6,r4
    add r12,r0
    adc r13,r1
    adc r20,r25
    add r12,r0
    adc r13,r1
    adc r20,r25
    mul r6,r5
    add r13,r0
    adc r14,r1
    adc r21,r25
    add r13,r0
    adc r14,r1
    adc r21,r25
    ldd r6,Y+16+3
    mul r6,r2
    add r11,r0
    adc r12,r1
    adc r19,r25
    add r11,r0
    adc r12,r1
    adc r19,r25
    mul r6,r3
    add r12,r0
    adc r13,r1
    adc r20,r25
    add r12,r0
    adc r13,r1
    adc r20,r25
    mul r6,r4
    add r13,r0
    adc r14,r1
    adc r21,r25
    add r13,r0
    adc r14,r1
    adc r21,r25
    mul r6,r5
    add r14,r0
    adc r15,r1
    adc r22,r25
    add r14,r0
    adc r15,r1
    adc r22,r25
	ldd r2,Y+4
	ldd r3,Y+4+1
	ldd r4,Y+4+2
	ldd r5,Y+4+3
	ldd r6,Y+12
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+12+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+12+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+12+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	ldd r2,Y+8
	ldd r3,Y+8+1
	ldd r4,Y+8+2
	ldd r5,Y+8+3
	mul r2,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r2,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r2,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r2,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r3,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r5,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;16
	st X+,r9 ;17
	st X+,r10 ;18
	st X+,r11 ;19

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+4
	ldd r3,Y+4+1
	ldd r4,Y+4+2
	ldd r5,Y+4+3
	ldd r6,Y+16
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+16+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+16+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+16+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	ldd r2,Y+8
	ldd r3,Y+8+1
	ldd r4,Y+8+2
	ldd r5,Y+8+3
	ldd r6,Y+12
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+12+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+12+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+12+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;20
	st X+,r9 ;21
	st X+,r10 ;22
	st X+,r11 ;23

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+8
	ldd r3,Y+8+1
	ldd r4,Y+8+2
	ldd r5,Y+8+3
	ldd r6,Y+16
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+16+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+16+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+16+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	ldd r2,Y+12
	ldd r3,Y+12+1
	ldd r4,Y+12+2
	ldd r5,Y+12+3
	mul r2,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r2,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r2,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r2,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r3,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r5,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;24
	st X+,r9 ;25
	st X+,r10 ;26
	st X+,r11 ;27

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+12
	ldd r3,Y+12+1
	ldd r4,Y+12+2
	ldd r5,Y+12+3
	ldd r6,Y+16
	mul r6,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r6,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	ldd r6,Y+16+1
	mul r6,r2
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r6,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	ldd r6,Y+16+2
	mul r6,r2
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r6,r3
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	ldd r6,Y+16+3
	mul r6,r2
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r6,r3
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r6,r4
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r6,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;28
	st X+,r9 ;29
	st X+,r10 ;30
	st X+,r11 ;31

	movw r8,r12
	movw r10,r14
	mov r12,r22
	clr r13
	movw r14,r24
	movw r16,r24
	movw r18,r24
	movw r20,r24
	clr r22
	ldd r2,Y+16
	ldd r3,Y+16+1
	ldd r4,Y+16+2
	ldd r5,Y+16+3
	mul r2,r2
	add r8,r0
	adc r9,r1
	adc r16,r25
	mul r2,r3
	add r9,r0
	adc r10,r1
	adc r17,r25
	add r9,r0
	adc r10,r1
	adc r17,r25
	mul r2,r4
	add r10,r0
	adc r11,r1
	adc r18,r25
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r2,r5
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r3
	add r10,r0
	adc r11,r1
	adc r18,r25
	mul r3,r4
	add r11,r0
	adc r12,r1
	adc r19,r25
	add r11,r0
	adc r12,r1
	adc r19,r25
	mul r3,r5
	add r12,r0
	adc r13,r1
	adc r20,r25
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r4
	add r12,r0
	adc r13,r1
	adc r20,r25
	mul r4,r5
	add r13,r0
	adc r14,r1
	adc r21,r25
	add r13,r0
	adc r14,r1
	adc r21,r25
	mul r5,r5
	add r14,r0
	adc r15,r1
	adc r22,r25
	add r10,r16
	adc r11,r17
	adc r12,r18
	adc r13,r19
	adc r14,r20
	adc r15,r21
	adc r22,r25
	st X+,r8 ;32
	st X+,r9 ;33
	st X+,r10 ;34
	st X+,r11 ;35
	st X+,r12  ;36
	st X+,r13  ;37
	st X+,r14  ;38
	st X+,r15  ;39

	clr r1
	EPILOGUE
	ret
