/* mcukit's linker script for the 16-bit MSP430 (16 KB of flash at 0xc000,
 * the interrupt vectors at 0xffe0, 512 bytes of RAM at 0x200). */
ENTRY(reset_handler)
MEMORY {
  rom (rx)     : ORIGIN = 0xc000, LENGTH = 0x3fe0
  vectors (r)  : ORIGIN = 0xffe0, LENGTH = 0x20
  ram (rwx)    : ORIGIN = 0x0200, LENGTH = 0x200
}
SECTIONS {
  .text : {
    *(.text .text.*)
    . = ALIGN(2);
  } > rom
  .rodata : {
    *(.rodata .rodata.*)
    . = ALIGN(2);
  } > rom
  .data : {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(2);
    __data_end = .;
  } > ram AT > rom
  __data_load = LOADADDR(.data);
  .bss (NOLOAD) : {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(2);
    __bss_end = .;
  } > ram
  .vectors : { KEEP(*(.vectors)) } > vectors
  __stack_top = ORIGIN(ram) + LENGTH(ram);
  /DISCARD/ : { *(.comment) *(.MSP430.attributes) *(.note .note.*) }
}
