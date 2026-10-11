/* fwkit startup for the ESP32's Xtensa LX6 (windowed ABI): the window
 * overflow and underflow vectors and the user exception vector at VECBASE,
 * then a window and a stack, then C. */
	.section .vectors, "ax"
	.align	4
	.globl	_vectors
_vectors:
	.org	0x00
_WindowOverflow4:
	s32e	a0, a5, -16
	s32e	a1, a5, -12
	s32e	a2, a5, -8
	s32e	a3, a5, -4
	rfwo
	.org	0x40
_WindowUnderflow4:
	l32e	a0, a5, -16
	l32e	a1, a5, -12
	l32e	a2, a5, -8
	l32e	a3, a5, -4
	rfwu
	.org	0x80
_WindowOverflow8:
	s32e	a0, a9, -16
	l32e	a0, a1, -12
	s32e	a1, a9, -12
	s32e	a2, a9, -8
	s32e	a3, a9, -4
	s32e	a4, a0, -32
	s32e	a5, a0, -28
	s32e	a6, a0, -24
	s32e	a7, a0, -20
	rfwo
	.org	0xc0
_WindowUnderflow8:
	l32e	a1, a9, -12
	l32e	a0, a9, -16
	l32e	a7, a1, -12
	l32e	a2, a9, -8
	l32e	a4, a7, -32
	l32e	a3, a9, -4
	l32e	a5, a7, -28
	l32e	a6, a7, -24
	l32e	a7, a7, -20
	rfwu
	.org	0x100
_WindowOverflow12:
	s32e	a0, a13, -16
	l32e	a0, a1, -12
	s32e	a1, a13, -12
	s32e	a2, a13, -8
	s32e	a3, a13, -4
	s32e	a4, a0, -48
	s32e	a5, a0, -44
	s32e	a6, a0, -40
	s32e	a7, a0, -36
	s32e	a8, a0, -32
	s32e	a9, a0, -28
	s32e	a10, a0, -24
	s32e	a11, a0, -20
	rfwo
	.org	0x140
_WindowUnderflow12:
	l32e	a1, a13, -12
	l32e	a0, a13, -16
	l32e	a11, a1, -12
	l32e	a2, a13, -8
	l32e	a4, a11, -48
	l32e	a8, a11, -32
	l32e	a3, a13, -4
	l32e	a5, a11, -44
	l32e	a6, a11, -40
	l32e	a7, a11, -36
	l32e	a9, a11, -28
	l32e	a10, a11, -24
	l32e	a11, a11, -20
	rfwu
	.org	0x340
_UserExceptionVector:
	wsr.excsave1	a0
	j	user_exception

	.text
	.literal_position
	.align	4
user_exception:
	addi	a1, a1, -32
	s32i	a2, a1, 0
	s32i	a3, a1, 4
	s32i	a4, a1, 8
	movi	a4, board_irq_dispatch
	callx4	a4
	l32i	a4, a1, 8
	l32i	a3, a1, 4
	l32i	a2, a1, 0
	addi	a1, a1, 32
	rsr.excsave1	a0
	rfe

	.align	4
	.globl	_start
_start:
	movi	a0, 0
	wsr.windowbase	a0
	rsync
	movi	a0, 1
	wsr.windowstart	a0
	rsync
	movi	a0, _vectors
	wsr.vecbase	a0
	movi	a0, 0x00040020		/* PS: WOE, UM */
	wsr.ps	a0
	rsync
	movi	a1, __stack_top
	movi	a0, 0
	movi	a4, fw_reset
	callx4	a4
1:	j	1b
