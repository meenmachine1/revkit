@ Synthetic ARM firmware: the exception vector table at 0, as a boot ROM
@ has it (ldr pc through a table of handler addresses), and the reset
@ handler, which sets up a stack and jumps to main through a literal.
        .arm
        .section .vectors, "ax"
        .global _vectors
_vectors:
        ldr     pc, reset_addr
        ldr     pc, undef_addr
        ldr     pc, swi_addr
        ldr     pc, pabort_addr
        ldr     pc, dabort_addr
        b       .
        ldr     pc, irq_addr
        ldr     pc, fiq_addr
reset_addr:  .word reset
undef_addr:  .word hang
swi_addr:    .word hang
pabort_addr: .word hang
dabort_addr: .word hang
irq_addr:    .word irq_handler
fiq_addr:    .word hang

        .text
        .global reset
        .type   reset, %function
reset:
        ldr     sp, =0x20008000
        ldr     r0, =main
        mov     lr, pc
        bx      r0
        .type   hang, %function
hang:
        b       hang
        .ltorg
