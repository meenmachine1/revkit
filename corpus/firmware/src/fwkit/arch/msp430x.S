/* fwkit startup for MSP430X (large model, 20-bit addresses): reset at the
 * start of the ROM holds the watchdog, sets the stack and enters C; the
 * interrupt entry saves the registers C may clobber. */
	.section .vectors, "ax"
	.globl _start
_start:
	mov.w	#0x5a80, &0x015c	/* WDTCTL: hold */
	mova	#__stack_top, r1
	calla	#fw_reset
1:	jmp	1b

	.text
	.globl isr_entry
isr_entry:
	pushm.a	#5, r15
	calla	#board_irq_dispatch
	popm.a	#5, r15
	reti
