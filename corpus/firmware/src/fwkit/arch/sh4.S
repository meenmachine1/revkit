/* fwkit startup for SH-4: reset at the start of the ROM (P2), the
 * interrupt vector at VBR + 0x600, then C. */
	.section .vectors, "ax"
	.globl _start
_start:
	mov.l	sr_init, r0
	ldc	r0, sr
	mov.l	vbr_init, r0
	ldc	r0, vbr
	mov.l	stack_init, r15
	mov.l	reset_c, r0
	jsr	@r0
	nop
1:	bra	1b
	nop
	.align	2
sr_init:	.long	0x700000f0
vbr_init:	.long	_start
stack_init:	.long	__stack_top
reset_c:	.long	fw_reset

	.org	0x600
interrupt:
	sts.l	pr, @-r15
	sts.l	mach, @-r15
	sts.l	macl, @-r15
	stc.l	gbr, @-r15
	mov.l	dispatch, r0
	jsr	@r0
	nop
	ldc.l	@r15+, gbr
	lds.l	@r15+, macl
	lds.l	@r15+, mach
	lds.l	@r15+, pr
	rte
	nop
	.align	2
dispatch:	.long	board_irq_dispatch
