@ ARMv4T start-up for the firmware-emulation fixtures (Versatile/PB):
@ the vector table at 0, a stack per mode, and main in user mode with
@ IRQ and FIQ enabled, entered by an exception return (MOVS pc, lr).
@ IRQ handlers are C (irq_handler); the FIQ handler counts in fiq_count
@ with FIQ's own r8-r12 (nothing saved); SWIs go to swi_handler(number,
@ saved r0-r3); undefined instructions to trap_handler.
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
undef_addr:  .word undef_entry
swi_addr:    .word swi_entry
pabort_addr: .word abort_entry
dabort_addr: .word abort_entry
irq_addr:    .word irq_entry
fiq_addr:    .word fiq_entry

        .text
        .global reset
        .type   reset, %function
reset:
        msr     cpsr_c, #0xd2           @ IRQ mode, IRQ and FIQ masked
        ldr     sp, =__irq_stack
        msr     cpsr_c, #0xd1           @ FIQ
        ldr     sp, =__fiq_stack
        msr     cpsr_c, #0xd7           @ abort
        ldr     sp, =__abt_stack
        msr     cpsr_c, #0xdb           @ undefined
        ldr     sp, =__und_stack
        msr     cpsr_c, #0xdf           @ system: the user registers
        ldr     sp, =__usr_stack
        msr     cpsr_c, #0xd3           @ supervisor
        ldr     sp, =__svc_stack
        ldr     r0, =__bss_start
        ldr     r1, =__bss_end
        mov     r2, #0
1:      cmp     r0, r1
        strlo   r2, [r0], #4
        blo     1b
        mov     r0, #0x10               @ user mode, IRQ and FIQ on
        msr     spsr_cxsf, r0
        ldr     lr, =user_main
        movs    pc, lr

        .type   user_main, %function
user_main:
        bl      main
        mov     r1, r0
        swi     0x10                    @ exit(main's result)
        b       .

        .type   irq_entry, %function
irq_entry:
        sub     lr, lr, #4
        stmfd   sp!, {r0-r3, r12, lr}
        bl      irq_handler
        ldmfd   sp!, {r0-r3, r12, pc}^

        .type   fiq_entry, %function
fiq_entry:
        ldr     r8, =fiq_count
        ldr     r9, [r8]
        add     r9, r9, #1
        str     r9, [r8]
        ldr     r10, =0x101e300c        @ timer 2 IntClr
        str     r9, [r10]
        mov     r11, #0
        mov     r12, #0
        subs    pc, lr, #4

        .type   swi_entry, %function
swi_entry:
        stmfd   sp!, {r0-r3, r12, lr}
        ldr     r0, [lr, #-4]
        bic     r0, r0, #0xff000000
        mov     r1, sp
        bl      swi_handler
        ldmfd   sp!, {r0-r3, r12, pc}^

        .type   undef_entry, %function
undef_entry:
        stmfd   sp!, {r0-r3, r12, lr}
        mov     r0, #1
        sub     r1, lr, #4
        bl      trap_handler
        ldmfd   sp!, {r0-r3, r12, pc}^

        .type   abort_entry, %function
abort_entry:
        sub     lr, lr, #4
        stmfd   sp!, {r0-r3, r12, lr}
        mov     r0, #2
        mov     r1, lr
        bl      trap_handler
        ldmfd   sp!, {r0-r3, r12, lr}
        add     lr, lr, #4              @ skip the faulting instruction
        movs    pc, lr

        .ltorg

        .weak   irq_handler
        .weak   fiq_count
irq_handler:
        bx      lr
