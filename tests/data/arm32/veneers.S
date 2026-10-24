@ Hand-written code of the fixture (kit.h): the SDK's interrupt pair, a
@ long-branch veneer and a Thumb-to-ARM stub, and the start-up code.

    .syntax unified
    .section .text.start, "ax"
    .arm
    .global _start
_start:
    ldr sp, =0x023f0000
    bl main
1:  b 1b

    .section .text.os, "ax"
    .arm
    .global OS_DisableInterrupts
    .type OS_DisableInterrupts, %function
OS_DisableInterrupts:
    mrs r0, cpsr
    orr r1, r0, #0xc0
    msr cpsr_c, r1
    and r0, r0, #0xc0
    bx lr
    .size OS_DisableInterrupts, . - OS_DisableInterrupts

    .global OS_RestoreInterrupts
    .type OS_RestoreInterrupts, %function
OS_RestoreInterrupts:
    mrs r1, cpsr
    bic r2, r1, #0xc0
    orr r2, r2, r0
    msr cpsr_c, r2
    bx lr
    .size OS_RestoreInterrupts, . - OS_RestoreInterrupts

@ A long-branch veneer, as a linker places one: the target's address in a
@ literal word.
    .global dev_dispatch_veneer
    .type dev_dispatch_veneer, %function
dev_dispatch_veneer:
    ldr pc, [pc, #-4]
    .word dev_dispatch
    .size dev_dispatch_veneer, . - dev_dispatch_veneer

@ Thumb code calling ARM code without BLX, as ARMv4T stubs do.
    .thumb
    .global bd_read_from_thumb
    .type bd_read_from_thumb, %function
    .thumb_func
bd_read_from_thumb:
    bx pc
    nop
    .arm
    b bd_read
    .size bd_read_from_thumb, . - bd_read_from_thumb
