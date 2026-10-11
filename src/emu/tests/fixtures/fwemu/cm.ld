/* Stellaris LM3S6965: flash at 0, 64 KiB of SRAM at 0x20000000. */
ENTRY(reset_handler)
MEMORY {
  FLASH (rx) : ORIGIN = 0, LENGTH = 256K
  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > FLASH
  .bss (NOLOAD) : { . = ALIGN(4); __bss_start = .; *(.bss*) *(COMMON) . = ALIGN(4); __bss_end = .; } > SRAM
  __stack_top = ORIGIN(SRAM) + LENGTH(SRAM);
  __psp_top = __stack_top - 0x1000;
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) *(.data*) }
}
