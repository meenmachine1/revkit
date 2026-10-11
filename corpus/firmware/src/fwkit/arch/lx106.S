/* fwkit startup for the ESP8266's Xtensa L106 (CALL0 ABI): the user
 * exception vector at VECBASE + 0x50, then a stack, then C. */
	.section .vectors, "ax"
	.align	4
	.globl	_vectors
_vectors:
	.org	0x10
_DebugExceptionVector:
	j	_DebugExceptionVector
	.org	0x20
_NMIExceptionVector:
	j	_NMIExceptionVector
	.org	0x30
_KernelExceptionVector:
	j	_KernelExceptionVector
	.org	0x50
_UserExceptionVector:
	wsr.excsave1	a0
	j	user_exception

	.text
	.literal_position
	.align	4
user_exception:
	addi	a1, a1, -64
	s32i	a2, a1, 8
	s32i	a3, a1, 12
	s32i	a4, a1, 16
	s32i	a5, a1, 20
	s32i	a6, a1, 24
	s32i	a7, a1, 28
	s32i	a8, a1, 32
	s32i	a9, a1, 36
	s32i	a10, a1, 40
	s32i	a11, a1, 44
	s32i	a12, a1, 48
	s32i	a13, a1, 52
	s32i	a14, a1, 56
	s32i	a15, a1, 60
	rsr.sar	a2
	s32i	a2, a1, 4
	movi	a0, board_irq_dispatch
	callx0	a0
	l32i	a2, a1, 4
	wsr.sar	a2
	l32i	a15, a1, 60
	l32i	a14, a1, 56
	l32i	a13, a1, 52
	l32i	a12, a1, 48
	l32i	a11, a1, 44
	l32i	a10, a1, 40
	l32i	a9, a1, 36
	l32i	a8, a1, 32
	l32i	a7, a1, 28
	l32i	a6, a1, 24
	l32i	a5, a1, 20
	l32i	a4, a1, 16
	l32i	a3, a1, 12
	l32i	a2, a1, 8
	addi	a1, a1, 64
	rsr.excsave1	a0
	rfe

	.align	4
	.globl	_start
_start:
	movi	a1, __stack_top
	movi	a0, _vectors
	wsr.vecbase	a0
	movi	a0, fw_reset
	callx0	a0
1:	j	1b
