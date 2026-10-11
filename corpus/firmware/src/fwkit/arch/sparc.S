/* fwkit startup for SPARC V8: the trap table at the start of the ROM
 * (reset, register-window overflow and underflow, interrupt levels 1-15),
 * then C. Eight register windows. */
#define TRAP(handler) ba handler; nop; nop; nop
#define BAD TRAP(bad_trap)
#define IRQ ba interrupt; rd %psr, %l0; nop; nop

	.section .vectors, "ax"
	.globl _start
_start:
	TRAP(reset)		/* 0x00 reset */
	BAD; BAD; BAD; BAD	/* 0x01-0x04 */
	TRAP(window_overflow)	/* 0x05 */
	TRAP(window_underflow)	/* 0x06 */
	.rept	10		/* 0x07-0x10 */
	BAD
	.endr
	.rept	15		/* 0x11-0x1f: interrupt levels 1-15 */
	IRQ
	.endr
	.rept	224		/* 0x20-0xff */
	BAD
	.endr

	.text
reset:
	set	0x0fe0, %g1	/* supervisor, previous supervisor, PIL 15, traps off */
	wr	%g1, %psr
	wr	%g0, 2, %wim
	set	_start, %g1
	wr	%g1, %tbr
	nop
	nop
	nop
	set	__stack_top - 96, %sp
	mov	%g0, %fp
	call	fw_reset
	nop
1:	ba	1b
	nop

window_overflow:
	mov	%wim, %l3
	mov	%g1, %l7
	srl	%l3, 1, %g1
	sll	%l3, 7, %l4
	or	%l4, %g1, %g1
	save
	mov	%g1, %wim
	nop
	nop
	nop
	std	%l0, [%sp + 0]
	std	%l2, [%sp + 8]
	std	%l4, [%sp + 16]
	std	%l6, [%sp + 24]
	std	%i0, [%sp + 32]
	std	%i2, [%sp + 40]
	std	%i4, [%sp + 48]
	std	%i6, [%sp + 56]
	restore
	mov	%l7, %g1
	jmp	%l1
	rett	%l2

window_underflow:
	mov	%wim, %l3
	sll	%l3, 1, %l4
	srl	%l3, 7, %l5
	or	%l5, %l4, %l5
	mov	%l5, %wim
	nop
	nop
	nop
	restore
	restore
	ldd	[%sp + 0], %l0
	ldd	[%sp + 8], %l2
	ldd	[%sp + 16], %l4
	ldd	[%sp + 24], %l6
	ldd	[%sp + 32], %i0
	ldd	[%sp + 40], %i2
	ldd	[%sp + 48], %i4
	ldd	[%sp + 56], %i6
	save
	save
	jmp	%l1
	rett	%l2

interrupt:
	save	%sp, -96, %sp
	call	board_irq_dispatch
	nop
	restore
	wr	%l0, %psr
	nop
	nop
	nop
	jmp	%l1
	rett	%l2

bad_trap:
	call	board_reset
	nop
