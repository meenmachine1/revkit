/* Versatile/PB fixtures: everything in RAM at 0 (qemu loads the ELF there),
 * a stack per mode above the image. */
ENTRY(_vectors)
SECTIONS {
  . = 0;
  .text : { *(.vectors) *(.text*) *(.rodata*) }
  .data : { *(.data*) }
  .bss : { . = ALIGN(4); __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(4); __bss_end = .; }
  . = ALIGN(16);
  . = . + 0x2000; __usr_stack = .;
  . = . + 0x800; __svc_stack = .;
  . = . + 0x800; __irq_stack = .;
  . = . + 0x400; __fiq_stack = .;
  . = . + 0x400; __abt_stack = .;
  . = . + 0x400; __und_stack = .;
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
