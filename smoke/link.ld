OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
  . = 0x80000000;

  .text : ALIGN(4) {
    *(.text.start)
    *(.text*)
    *(.rodata*)
  }

  .data : ALIGN(8) {
    *(.data*)
  }

  .bss : ALIGN(8) {
    *(.bss*)
    *(COMMON)
  }
}
