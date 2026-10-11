ENTRY(_start)
SECTIONS {
  . = 0x80000000;
  .text : { *(.text.start) *(.text*) *(.rodata*) }
  .data : { *(.data*) *(.sdata*) }
  .bss : { *(.sbss*) *(.bss*) *(COMMON) }
  . = ALIGN(16);
  . = . + 0x2000;
  __stack_top = .;
  /DISCARD/ : { *(.MIPS.*) *(.reginfo) *(.comment) *(.pdr) *(.gnu.attributes) }
}
