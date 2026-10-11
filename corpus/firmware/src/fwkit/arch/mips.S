/* fwkit startup for MIPS32: the boot ROM's reset and exception vectors
 * (BEV=1), a stack, then C. */
	.set noreorder
	.set noat
	.section .vectors, "ax"
	.globl _start
_start:
	b	reset
	nop

	.org	0x380			/* general exception, BEV=1 */
general_exception:
	la	$k0, exception_entry
	jr	$k0
	nop

reset:
	mtc0	$zero, $12		/* Status: interrupts off */
	mtc0	$zero, $13		/* Cause */
	la	$sp, __stack_top
	addiu	$sp, $sp, -32
	la	$t9, fw_reset
	jalr	$t9
	nop
1:	b	1b
	nop

	.text
	.globl exception_entry
exception_entry:
	addiu	$sp, $sp, -96
	sw	$at, 4($sp)
	sw	$v0, 8($sp)
	sw	$v1, 12($sp)
	sw	$a0, 16($sp)
	sw	$a1, 20($sp)
	sw	$a2, 24($sp)
	sw	$a3, 28($sp)
	sw	$t0, 32($sp)
	sw	$t1, 36($sp)
	sw	$t2, 40($sp)
	sw	$t3, 44($sp)
	sw	$t4, 48($sp)
	sw	$t5, 52($sp)
	sw	$t6, 56($sp)
	sw	$t7, 60($sp)
	sw	$t8, 64($sp)
	sw	$t9, 68($sp)
	sw	$ra, 72($sp)
	mfhi	$t0
	sw	$t0, 76($sp)
	mflo	$t0
	sw	$t0, 80($sp)
	jal	board_irq_dispatch
	nop
	lw	$t0, 80($sp)
	mtlo	$t0
	lw	$t0, 76($sp)
	mthi	$t0
	lw	$ra, 72($sp)
	lw	$t9, 68($sp)
	lw	$t8, 64($sp)
	lw	$t7, 60($sp)
	lw	$t6, 56($sp)
	lw	$t5, 52($sp)
	lw	$t4, 48($sp)
	lw	$t3, 44($sp)
	lw	$t2, 40($sp)
	lw	$t1, 36($sp)
	lw	$t0, 32($sp)
	lw	$a3, 28($sp)
	lw	$a2, 24($sp)
	lw	$a1, 20($sp)
	lw	$a0, 16($sp)
	lw	$v1, 12($sp)
	lw	$v0, 8($sp)
	lw	$at, 4($sp)
	addiu	$sp, $sp, 96
	eret
	nop
