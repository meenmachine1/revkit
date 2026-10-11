/* Laid out as a boot image: vectors at 0, code, read-only data, then data
 * (a raw binary has no sections: everything is one block at 0). */
ENTRY(_vectors)
SECTIONS {
  . = 0;
  .text : { *(.vectors) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
