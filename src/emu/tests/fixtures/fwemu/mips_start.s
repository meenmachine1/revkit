# MIPS32 (big endian) start-up for the firmware-emulation fixture: entry at
# the image's start (kseg0, 0x80000000), a stack, BEV cleared so exceptions
# go to EBase + 0x180, and a general exception handler that saves the
# registers C clobbers, calls exception(cause, epc, frame) for the EPC to
# return to, and returns with ERET.
        .set    noreorder
        .set    noat
        .section .text.start, "ax"
        .globl  _start
_start:
        la      $sp, __stack_top
        mtc0    $zero, $12              # Status: BEV, ERL, EXL and IE clear
        ehb
        j       main_start
        nop

        .org    0x180
        .globl  exception_vector
exception_vector:
        addiu   $sp, $sp, -96
        sw      $at, 0($sp)
        sw      $v0, 4($sp)
        sw      $v1, 8($sp)
        sw      $a0, 12($sp)
        sw      $a1, 16($sp)
        sw      $a2, 20($sp)
        sw      $a3, 24($sp)
        sw      $t0, 28($sp)
        sw      $t1, 32($sp)
        sw      $t2, 36($sp)
        sw      $t3, 40($sp)
        sw      $t4, 44($sp)
        sw      $t5, 48($sp)
        sw      $t6, 52($sp)
        sw      $t7, 56($sp)
        sw      $t8, 60($sp)
        sw      $t9, 64($sp)
        sw      $ra, 68($sp)
        mfc0    $a0, $13                # Cause
        mfc0    $a1, $14                # EPC
        move    $a2, $sp
        jal     exception
        addiu   $sp, $sp, -16
        addiu   $sp, $sp, 16
        mtc0    $v0, $14
        lw      $at, 0($sp)
        lw      $v0, 4($sp)
        lw      $v1, 8($sp)
        lw      $a0, 12($sp)
        lw      $a1, 16($sp)
        lw      $a2, 20($sp)
        lw      $a3, 24($sp)
        lw      $t0, 28($sp)
        lw      $t1, 32($sp)
        lw      $t2, 36($sp)
        lw      $t3, 40($sp)
        lw      $t4, 44($sp)
        lw      $t5, 48($sp)
        lw      $t6, 52($sp)
        lw      $t7, 56($sp)
        lw      $t8, 60($sp)
        lw      $t9, 64($sp)
        lw      $ra, 68($sp)
        addiu   $sp, $sp, 96
        eret
        nop

main_start:
        jal     main
        nop
        mtc0    $zero, $12              # interrupts off
1:      b       1b
        nop
