/* The fixture's layout (make_fixture.py): code and read-only data from
   0x02000000, as a Nintendo DS's main module; data after them; bss in RAM
   elsewhere (a region the manifest names). */
ENTRY(_start)
SECTIONS
{
  . = 0x02000000;
  .text : { *(.text.start) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  . = 0x02200000;
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}
