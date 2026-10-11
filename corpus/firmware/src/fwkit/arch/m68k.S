/* fwkit startup for the 68020: the vector table at 0 (initial stack,
 * reset, exceptions, autovectored interrupts), then C. */
	.section .vectors, "ax"
	.long	__stack_top
	.long	_start
	.rept	22
	.long	exception
	.endr
	.long	spurious		/* 24: spurious interrupt */
	.rept	7
	.long	interrupt		/* 25-31: autovectors */
	.endr
	.rept	224
	.long	exception
	.endr

	.text
	.globl _start
_start:
	move.w	#0x2700, %sr
	lea	__stack_top, %sp
	jsr	fw_reset
1:	bra.s	1b

interrupt:
	movem.l	%d0-%d1/%a0-%a1, -(%sp)
	jsr	board_irq_dispatch
	movem.l	(%sp)+, %d0-%d1/%a0-%a1
spurious:
	rte

exception:
	move.w	#0x2700, %sr
	jsr	board_reset
	bra.s	exception
