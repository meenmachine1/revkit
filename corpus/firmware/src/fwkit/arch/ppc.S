/* fwkit startup for 32-bit PowerPC: the reset vector at 0x100 and the
 * external interrupt at 0x500 (exception prefix at the ROM), then C. */
	.section .vectors, "ax"
vectors:
	.org	0x100
	.globl _start
_start:
	li	%r0, 0
	mtmsr	%r0
	isync
	lis	%r1, __stack_top@ha
	addi	%r1, %r1, __stack_top@l
	stwu	%r0, -16(%r1)
	bl	fw_reset
1:	b	1b

	.org	0x500
external_interrupt:
	stwu	%r1, -80(%r1)
	stw	%r0, 8(%r1)
	mflr	%r0
	stw	%r0, 12(%r1)
	mfcr	%r0
	stw	%r0, 16(%r1)
	mfctr	%r0
	stw	%r0, 20(%r1)
	mfxer	%r0
	stw	%r0, 24(%r1)
	stmw	%r3, 28(%r1)
	bl	board_irq_dispatch
	lmw	%r3, 28(%r1)
	lwz	%r0, 24(%r1)
	mtxer	%r0
	lwz	%r0, 20(%r1)
	mtctr	%r0
	lwz	%r0, 16(%r1)
	mtcr	%r0
	lwz	%r0, 12(%r1)
	mtlr	%r0
	lwz	%r0, 8(%r1)
	addi	%r1, %r1, 80
	rfi

	.org	0x900
decrementer:
	b	external_interrupt
