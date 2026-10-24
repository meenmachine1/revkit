@ CodeWarrior's byte loops and comparisons (ARMv5TE), as hand-matching met
@ them: the loop counts down with subs and tests the result with bgt.
	.syntax unified
	.arm
	.text

	.global memset_cw
	.type memset_cw,%function
@ void memset_cw(char *p, int c, int n) { while (n > 0) { *p++ = c; n--; } }
memset_cw:
	cmp r2, #0
	bxle lr
1:	strb r1, [r0], #1
	subs r2, r2, #1
	bgt 1b
	bx lr
	.size memset_cw, .-memset_cw

	.global half_cw
	.type half_cw,%function
@ void half_cw(u16 *p) { p[0] = p[0] + 1; p[1] = (s16)p[1] >> 1; }
half_cw:
	ldrh r1, [r0]
	add r1, r1, #1
	strh r1, [r0]
	ldrsh r1, [r0, #2]
	mov r1, r1, asr #1
	strh r1, [r0, #2]
	bx lr
	.size half_cw, .-half_cw

	.global start_cw
	.type start_cw,%function
start_cw:
	push {lr}
	bl memset_cw
	bl half_cw
	pop {pc}
	.size start_cw, .-start_cw
